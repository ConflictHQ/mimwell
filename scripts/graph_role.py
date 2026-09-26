"""The contract role `graph` (#225): traversal over the edges table, and AGE as a derived projection.

The `edges` table is the single relation authority in every cell. Traversal walks it:
a Python frontier walk on `files` and `sqlite`, a recursive CTE on `postgres` and
`mysql`. With `graph=age` (Postgres only) a `deliver()` consumer, `AgeGraph.write`,
materializes the policy-filtered graph of one audience into an Apache AGE graph, and a
walk uses Cypher only while that projection is current: the authority acknowledged its
delivery at the outbox head, and its node and edge sets match the actor's readable nodes
and edges in the authority. A graph written any other way is not walked. A Cypher read
runs in a READ ONLY transaction that is always rolled back, so nothing it does persists;
its write-keyword check only fails such a query early. The contract refuses a graph
store that holds any other role or owns a field.

A walk returns the nodes reachable from `start` over outgoing relations within `depth`
hops, each at its shortest distance, ordered by (depth, id) in every mode.
"""

from __future__ import annotations

from collections import deque
from contextlib import contextmanager
import hashlib
import json
import re

from sql_dialect import PostgresDialect, StoreError

MAX_DEPTH = 8
# Cypher clauses that write, looked for outside string literals.
WRITE_CLAUSE = re.compile(r"\b(?:CREATE|MERGE|SET|DELETE|REMOVE)\b", re.IGNORECASE)
LITERAL = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")
DIRECT_WRITE = ("the edges table is the single relation authority; AGE is written only by its "
                "projection consumer, AgeGraph.write through Authority.deliver (#225)")


def check_depth(depth):
    if type(depth) is not int or not 1 <= depth <= MAX_DEPTH:
        raise StoreError(f"walk depth must be an integer from 1 to {MAX_DEPTH}")


def ordered(hops):
    """The one ordering every mode returns: shortest distance, then identity."""
    return [{"id": identity, "depth": hops[identity]} for identity in sorted(hops, key=lambda i: (hops[i], i))]


def frontier_walk(edges, start, depth):
    """Python frontier walk over (source, target) pairs already filtered to readable nodes."""
    adjacent = {}
    for source, target in edges:
        adjacent.setdefault(source, set()).add(target)
    hops, frontier = {start: 0}, deque([start])
    while frontier:
        current = frontier.popleft()
        if hops[current] == depth:
            continue
        for target in adjacent.get(current, ()):
            if target not in hops:
                hops[target] = hops[current] + 1
                frontier.append(target)
    return ordered(hops)


def edges_table_walk(dialect, readable, start, depth):
    """Recursive CTE over `edges`, joined to the readable live records at both ends."""
    placeholders = dialect.placeholders(len(readable))
    rows = dialect.execute(
        "WITH RECURSIVE visible (id) AS "
        f"(SELECT id FROM records WHERE deleted=0 AND collection IN ({placeholders})), "
        "walk (id, hops) AS (SELECT id, 0 FROM visible WHERE id=? "
        "UNION SELECT e.target, w.hops + 1 FROM walk w JOIN edges e ON e.source = w.id "
        "JOIN visible v ON v.id = e.target WHERE w.hops < ?) "
        "SELECT id, MIN(hops) FROM walk GROUP BY id",
        (*readable, start, depth),
    ).fetchall()
    return ordered({row[0]: int(row[1]) for row in rows})


def node_digest(ids):
    """Binds a projection to the exact readable node set it was delivered for."""
    return hashlib.sha256(json.dumps(sorted(ids), ensure_ascii=False).encode()).hexdigest()


def edge_digest(edges):
    """Binds a projection to the exact readable (source, target, rel) edge set it was delivered for."""
    return hashlib.sha256(json.dumps(sorted(map(list, edges)), ensure_ascii=False).encode()).hexdigest()


class AgeGraph:
    """One Apache AGE graph per (contract, audience), in the authority's Postgres database.

    `write` is the only writer: pass it to `Authority.deliver` as the write callback of
    consumer `AgeGraph.consumer(...)`, so `Authority.observe()` reports its lag behind the
    outbox head. It replaces the graph with the delivered payload in one transaction and
    never moves back to an older outbox sequence. It checks only the payload's shape, so
    `Authority.walk` uses a projection only when the authority acknowledged this consumer's
    delivery at the head and the projection's node and edge digests match the authority's.
    `walk` and `read` run in a READ ONLY transaction that is always rolled back.
    """

    def __init__(self, dsn):
        psycopg = PostgresDialect.module()
        self.connection = psycopg.connect(dsn, autocommit=True)
        try:
            self.connection.execute("LOAD 'age'")
            self.connection.execute('SET search_path = ag_catalog, "$user", public')
        except BaseException:
            self.connection.close()
            raise

    def close(self):
        self.connection.close()

    @staticmethod
    def name(contract, audience):
        return "graph_" + hashlib.sha256(f"{contract}\0{audience}".encode()).hexdigest()[:24]

    @classmethod
    def consumer(cls, contract, audience):
        """The deliveries consumer for one audience's graph; Authority.observe() reports its lag."""
        return "graph:age:" + cls.name(contract, audience)

    def _cypher(self, graph, query, parameters, columns="x agtype"):
        return self.connection.execute(
            f"SELECT * FROM cypher('{graph}', $$ {query} $$, %s::agtype) AS ({columns})",
            (json.dumps(parameters, ensure_ascii=False),),
        ).fetchall()

    def _exists(self, graph):
        return self.connection.execute("SELECT 1 FROM ag_graph WHERE name=%s", (graph,)).fetchone() is not None

    def _meta(self, graph):
        if not self._exists(graph):
            return None
        rows = self._cypher(graph, "MATCH (m:Projection) RETURN properties(m)", {})
        return json.loads(rows[0][0]) if rows else None

    def write(self, payload):
        """The projection consumer: materialize one delivered, policy-filtered graph."""
        if not isinstance(payload, dict) or payload.get("protocolVersion") != "1.0" or not {
                "contract", "audience", "sequence", "graph"}.issubset(payload):
            raise StoreError("AGE accepts only a delivery payload; " + DIRECT_WRITE)
        graph = self.name(payload["contract"], payload["audience"])
        nodes = [{"id": node["id"], "kind": node["kind"]} for node in payload["graph"]["nodes"]]
        ids = {node["id"] for node in nodes}
        # Only edges between delivered nodes are created, so only those are digested.
        edges = [{"source": e["source"], "target": e["target"], "rel": e["rel"]} for e in payload["graph"]["edges"]
                 if e["source"] in ids and e["target"] in ids]
        meta = {"contract": payload["contract"], "audience": payload["audience"], "sequence": payload["sequence"],
                "nodes": node_digest(ids), "edges": edge_digest((e["source"], e["target"], e["rel"]) for e in edges)}
        self.connection.execute("BEGIN")
        try:
            self.connection.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (graph,))
            previous = self._meta(graph)
            if previous is not None and previous["sequence"] > payload["sequence"]:
                self.connection.execute("ROLLBACK")
                return
            if self._exists(graph):
                self.connection.execute("SELECT drop_graph(%s, true)", (graph,))
            self.connection.execute("SELECT create_graph(%s)", (graph,))
            self._cypher(graph, "CREATE (:Projection {contract: $contract, audience: $audience, sequence: $sequence, "
                                "nodes: $nodes, edges: $edges})", meta)
            self._cypher(graph, "UNWIND $nodes AS n CREATE (:Node {id: n.id, kind: n.kind})", {"nodes": nodes})
            self._cypher(graph, "UNWIND $edges AS e MATCH (a:Node {id: e.source}), (b:Node {id: e.target}) "
                                "CREATE (a)-[:REL {rel: e.rel}]->(b)", {"edges": edges})
            self.connection.execute("COMMIT")
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise

    @contextmanager
    def _read_only(self):
        """One REPEATABLE READ, READ ONLY transaction, always rolled back: nothing in it persists.

        READ ONLY alone is not enough: some AGE releases (1.6.0) run a Cypher DELETE inside one.
        """
        self.connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        try:
            yield
        except Exception as exc:
            if "read-only transaction" in str(exc):
                raise StoreError(DIRECT_WRITE) from None
            raise
        finally:
            self.connection.execute("ROLLBACK")

    def read(self, contract, audience, query, parameters=None, columns="x agtype"):
        """Cypher against one audience's projection; None when it has none.

        The always-rolled-back transaction is what keeps writes out; the keyword check only
        fails a query that names a write clause early.
        """
        if WRITE_CLAUSE.search(LITERAL.sub("''", query)):
            raise StoreError(DIRECT_WRITE)
        graph = self.name(contract, audience)
        with self._read_only():
            if not self._exists(graph):
                return None
            return [tuple(json.loads(value) for value in row)
                    for row in self._cypher(graph, query, parameters or {}, columns)]

    def walk(self, contract, audience, start, depth, *, sequence, ids, edges):
        """Cypher walk, or None unless the projection holds this outbox head and readable node and edge sets.

        The currency check and the walk read one snapshot of the projection.
        """
        check_depth(depth)
        graph = self.name(contract, audience)
        with self._read_only():
            meta = self._meta(graph)
            if (meta is None or meta["sequence"] != sequence or meta["nodes"] != node_digest(ids)
                    or meta.get("edges") != edge_digest(edges)):
                return None
            rows = self._cypher(
                graph, f"MATCH p = (s:Node {{id: $start}})-[:REL*1..{depth}]->(t:Node) WHERE t.id <> $start "
                       "RETURN t.id, min(length(p))", {"start": start}, "id agtype, hops agtype")
            hops = {json.loads(identity): json.loads(value) for identity, value in rows}
        hops[start] = 0
        return ordered(hops)
