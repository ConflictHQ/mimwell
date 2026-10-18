#!/usr/bin/env python3
"""Knowledge-base generators for the client portal — one entry point, several
subcommands. Every generator is client-agnostic: all client-specific inputs come
from client.config.json or sibling data files under knowledge/. Optional catalogs
can be empty; graph merging requires actual recording inputs so missing sources
cannot erase previously generated knowledge.

Subcommands
-----------
  merge              Merge per-recording graphs -> knowledge-base/knowledge_graph.json
  gen-issues         Export GitHub issues (config: issues.repos) -> issues.json
  gen-sessions       Build the meetings catalog        -> app/sessions.json
  import-drive-docs  Import curated Drive docs (data file) -> knowledge/docs/prior/

The PlanOpticon working area stays at knowledge-base/ (gitignored). Stdlib only.

Run from anywhere:
    python3 scripts/merge-kg.py <subcommand> [options]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys

from kg_identity import identity

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "client.config.json")


def load_config() -> dict:
    """Load client.config.json; missing/invalid -> empty config."""
    try:
        with open(CONFIG, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def load_data(rel_path: str) -> dict:
    """Load an optional sibling data file under ROOT; absent -> {}."""
    path = os.path.join(ROOT, rel_path)
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ── merge ────────────────────────────────────────────────────────────────────

def sealed_fragment(graph) -> bool:
    """Recognize Studio's opaque record envelope without decrypting it.

    A protection marker is never interpreted as a plaintext graph. Unknown or
    damaged envelopes must be repaired by their owner, not silently published.
    """
    if not isinstance(graph, dict) or not ({"protected", "sealed"} & graph.keys()):
        return False
    protected = graph.get("protected")
    if (isinstance(protected, dict) and protected.get("format") == "brain-record-seal/v1"
            and isinstance(graph.get("sealed"), str) and graph["sealed"].startswith("enc:v1:")):
        return True
    raise ValueError("unknown or malformed protected recording graph")


def cmd_merge(_args) -> None:
    """Merge every per-recording knowledge graph into one raw graph that the
    enrichment step consumes. Each node occurrence is tagged with its recording
    so enrichment can count source recordings.
    """
    rec = os.path.join(ROOT, "knowledge-base", "recordings")
    out = os.path.join(ROOT, "knowledge-base", "knowledge_graph.json")

    all_nodes, all_edges = [], []
    recordings = 0
    sealed = 0
    for gpath in sorted(glob.glob(os.path.join(rec, "*", "results", "knowledge_graph.json"))):
        folder = os.path.basename(os.path.dirname(os.path.dirname(gpath)))
        if folder.startswith("video"):  # raw unanalyzed captures
            continue
        with open(gpath, encoding="utf-8") as f:
            g = json.load(f)
        if sealed_fragment(g):
            sealed += 1
            continue
        if not isinstance(g, dict) or "nodes" not in g:
            raise ValueError(f"recording graph must contain a nodes array: {gpath}")
        nodes = g["nodes"]
        edges = g.get("relationships", g.get("edges", []))
        if (not isinstance(nodes, list) or not all(isinstance(n, dict) for n in nodes)
                or not isinstance(edges, list) or not all(isinstance(e, dict) for e in edges)):
            raise ValueError(f"recording nodes and relationships must be arrays of objects: {gpath}")
        recordings += 1
        for n in nodes:
            container = (n.get("props", {})
                         if not identity(n, "node") and "occurrences" in n.get("props", {}) else n)
            occ = container.get("occurrences") or [{}]
            for o in occ:
                o.setdefault("recording", folder)
            container["occurrences"] = occ
            all_nodes.append(n)
        all_edges.extend(edges)

    if not recordings and not sealed and not getattr(_args, "allow_empty", False):
        raise ValueError("no eligible recording graphs found; existing outputs were preserved. "
                         "Use --allow-empty only for an intentionally empty source set")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"nodes": all_nodes, "relationships": all_edges}, f)
    print(f"Merged {recordings} recordings -> {out}: "
          f"{len(all_nodes)} nodes (pre-dedup), {len(all_edges)} relationships")


# ── gen-issues ─────────────────────────────────────────────────────────────--

ISSUE_FIELDS = "number,title,state,labels,assignees,milestone,updatedAt,url"


def _fetch_issues(repo: str, state: str, limit: int) -> list[dict]:
    raw = subprocess.check_output(
        ["gh", "issue", "list", "--repo", repo, "--state", state,
         "--limit", str(limit), "--json", ISSUE_FIELDS],
        text=True,
    )
    issues = json.loads(raw)
    for i in issues:
        i["labels"] = [l["name"] for l in i.get("labels", [])]
        i["assignees"] = [a["login"] for a in i.get("assignees", [])]
        m = i.get("milestone")
        i["milestone"] = m["title"] if m else None
    return issues


def cmd_gen_issues(_args) -> None:
    """Export GitHub issues into issues.json — a live tracker the portal chat
    agent reads directly. Repos come from client.config.json ("issues":
    {"repos": [...]}); an empty/absent list writes an empty tracker without
    crashing. Requires an authenticated `gh` CLI for the listed repos.
    """
    out = os.path.join(ROOT, "issues.json")
    repos = (load_config().get("issues") or {}).get("repos") or []

    result = {"description": "Live GitHub issue tracker.", "repos": []}
    for repo in repos:
        try:
            open_issues = _fetch_issues(repo, "open", 200)
            closed = _fetch_issues(repo, "closed", 30)
        except subprocess.CalledProcessError as e:
            print(f"WARN: {repo}: {e}")
            continue
        result["repos"].append({
            "repo": repo,
            "open_count": len(open_issues),
            "open": open_issues,
            "recently_closed": closed,
        })

    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
    total = sum(r["open_count"] for r in result["repos"])
    print(f"Wrote {out}: {total} open issues across {len(result['repos'])} repos")


# ── gen-sessions ───────────────────────────────────────────────────────────--

DATE_RE = re.compile(r"(20\d{2})[-.](\d{2})[-.](\d{2})")


def _session_date(folder: str, manifest: dict) -> str:
    m = DATE_RE.search(folder)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    p = (manifest.get("video", {}) or {}).get("processed_at", "")
    return p[:10] if p else ""


def _item_text(x) -> str:
    if isinstance(x, str):
        return x
    if isinstance(x, dict):
        for key in ("point", "action", "task", "item", "description"):
            if x.get(key):
                return x[key]
    return ""


def cmd_gen_sessions(_args) -> None:
    """Build app/sessions.json — the meetings catalog for the Intelligence
    gallery — from the PlanOpticon working area (knowledge-base/recordings/,
    gitignored).

    For each analyzed recording: title, date, duration, key points, action-item
    count, and links to the committed redacted analysis/transcript. Copies one
    representative frame per session to app/thumbs/<id>.jpg for the gallery.

    Optional sibling data files (absent -> safe defaults):
      knowledge/session-tags.json        {"tags": {"<folder>": ["Label", ...]}}
      knowledge/session-recordings.json  {"recordings": {"<folder>": "<driveId>"}}
    """
    rec = os.path.join(ROOT, "knowledge-base", "recordings")
    thumbs = os.path.join(ROOT, "app", "thumbs")
    out = os.path.join(ROOT, "app", "sessions.json")

    explicit_tags = load_data(os.path.join("knowledge", "session-tags.json")).get("tags", {})
    drive_map = load_data(os.path.join("knowledge", "session-recordings.json")).get("recordings", {})

    # Index agenda/notes files by date so a recording can show the matching
    # agenda for the same day (one meeting = agenda + recording when both exist).
    agenda_dir = os.path.join(ROOT, "knowledge", "docs", "agendas")
    agenda_by_date = {}
    for ap in glob.glob(os.path.join(agenda_dir, "*.md")):
        d = os.path.basename(ap)[:-3]
        if DATE_RE.match(d):
            agenda_by_date[d] = f"knowledge/docs/agendas/{d}.md"

    sessions = []
    os.makedirs(thumbs, exist_ok=True)

    for mpath in sorted(glob.glob(os.path.join(rec, "*", "manifest.json"))):
        folder = os.path.basename(os.path.dirname(mpath))
        if folder.startswith("video"):  # raw unanalyzed captures
            continue
        with open(mpath, encoding="utf-8") as f:
            manifest = json.load(f)
        video = manifest.get("video", {}) or {}
        title = video.get("title") or folder.replace("-", " ").title()
        dur = video.get("duration_seconds") or 0

        # Key points + action-item count come from the structured results files.
        kp_path = os.path.join(rec, folder, "results", "key_points.json")
        key_points = []
        if os.path.isfile(kp_path):
            with open(kp_path, encoding="utf-8") as f:
                for k in json.load(f):
                    pt = k.get("point") if isinstance(k, dict) else (k if isinstance(k, str) else None)
                    if pt:
                        key_points.append(pt)
        ai_path = os.path.join(rec, folder, "results", "action_items.json")
        raw_ai = []
        if os.path.isfile(ai_path):
            with open(ai_path, encoding="utf-8") as f:
                raw_ai = json.load(f)
        action_items = [t for t in (_item_text(a) for a in raw_ai) if t]

        # Link to the committed redacted analysis + transcript if ingested.
        doc_rel = f"knowledge/docs/sessions/{folder}.md"
        has_doc = os.path.isfile(os.path.join(ROOT, doc_rel))
        tr_rel = f"knowledge/docs/sessions/transcripts/{folder}.md"
        has_tr = os.path.isfile(os.path.join(ROOT, tr_rel))
        sdate = _session_date(folder, manifest)
        drive_id = drive_map.get(folder, "")

        # Copy one representative frame (~40% through) as the thumbnail.
        frames = sorted(glob.glob(os.path.join(rec, folder, "frames", "frame_*.jpg")))
        thumb = ""
        if frames:
            pick = frames[int(len(frames) * 0.4)]
            dst = os.path.join(thumbs, f"{folder}.jpg")
            shutil.copyfile(pick, dst)
            # Resize to a gallery thumbnail to keep the repo lean (best effort).
            subprocess.run(["sips", "--resampleWidth", "480", dst],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            thumb = f"app/thumbs/{folder}.jpg"

        labels = explicit_tags.get(folder) or []
        sessions.append({
            "id": folder,
            "title": title,
            "labels": labels,
            "date": sdate,
            "duration_min": round(dur / 60) if dur else None,
            "key_points": key_points[:10],
            "action_items": action_items,
            "action_item_count": len(action_items),
            "frames": (manifest.get("stats", {}) or {}).get("frames_extracted", 0),
            "doc": doc_rel if has_doc else "",
            "transcript": tr_rel if has_tr else "",
            "agenda": agenda_by_date.get(sdate, ""),
            "drive_url": f"https://drive.google.com/file/d/{drive_id}/view" if drive_id else "",
            "thumb": thumb,
        })

    sessions.sort(key=lambda s: s["date"], reverse=True)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"count": len(sessions), "sessions": sessions}, f, indent=1)
    print(f"Wrote {out}: {len(sessions)} sessions, "
          f"{sum(1 for s in sessions if s['thumb'])} thumbnails")


# ── import-drive-docs ──────────────────────────────────────────────────────--

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CRED_RE = re.compile(r"(password|passwd|secret|api[_ ]?key|token)\s*[:=]\s*\S+", re.I)
# Google Docs markdown export embeds screenshots as base64 data URIs — strip them
# (no search value, huge bloat). Handles both ![alt](data:...) and bare data URIs.
IMG_MD_RE = re.compile(r"!\[[^\]]*\]\(data:image/[^)]*\)")
DATA_URI_RE = re.compile(r"data:image/[A-Za-z.+-]+;base64,[A-Za-z0-9+/=\s]+")


def _redact(text: str, keep_domains: tuple) -> str:
    text = IMG_MD_RE.sub("`[image omitted]`", text)
    text = DATA_URI_RE.sub("[image omitted]", text)
    text = EMAIL_RE.sub(
        lambda m: m.group(0) if keep_domains and m.group(0).lower().endswith(keep_domains)
        else "[email redacted]",
        text,
    )
    return CRED_RE.sub(lambda m: m.group(1) + ": [redacted]", text)


def _export(file_id: str, mime: str, out_dir: str) -> str:
    tmp = os.path.join(out_dir, ".export.tmp")
    env = {k: v for k, v in os.environ.items()
           if k != "GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE"}
    r = subprocess.run(
        ["gws", "drive", "files", "export", "--params",
         json.dumps({"fileId": file_id, "mimeType": mime}), "-o", tmp],
        capture_output=True, text=True, env=env,
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip()[:200])
    with open(tmp, encoding="utf-8", errors="replace") as f:
        text = f.read()
    os.remove(tmp)
    return text


def cmd_import_drive_docs(_args) -> None:
    """Import curated prior documentation from the engagement Drive into the
    indexed knowledge tree (knowledge/docs/prior/) so the chat agent can search
    it. Each doc is exported (Docs -> markdown, Sheets -> CSV), PII-redacted, and
    written with frontmatter.

    The doc list lives in the data file knowledge/drive-docs.json (absent ->
    no-op):
      {"docs": [{"slug": "...", "fileId": "...", "title": "...", "kind": "doc|sheet"}]}

    Email domains to preserve through redaction come from client.config.json
    ("knowledge": {"keepEmailDomains": ["example.com"]}); default keeps none.
    Requires the gws CLI authenticated as the Drive owner.
    """
    out_dir = os.path.join(ROOT, "knowledge", "docs", "prior")
    docs = load_data(os.path.join("knowledge", "drive-docs.json")).get("docs", [])
    keep_domains = tuple(
        d.lower() for d in (load_config().get("knowledge") or {}).get("keepEmailDomains", [])
    )

    if not docs:
        print("No docs listed in knowledge/drive-docs.json — nothing to import.")
        return

    os.makedirs(out_dir, exist_ok=True)
    written = failed = 0
    for d in docs:
        slug = d.get("slug", "")
        fid = d.get("fileId", "")
        title = d.get("title", slug)
        kind = d.get("kind", "doc")
        if not slug or not fid:
            print(f"  skip (missing slug/fileId): {d}")
            continue
        try:
            if kind == "sheet":
                body = _export(fid, "text/csv", out_dir)
                body = "```csv\n" + body.strip() + "\n```\n"
                desc = f"{title} — prior documentation (spreadsheet export)."
            else:
                body = _export(fid, "text/markdown", out_dir)
                desc = f"{title} — prior documentation imported from the engagement Drive."
        except Exception as e:  # noqa: BLE001
            print(f"  FAIL {slug}: {e}")
            failed += 1
            continue
        fm = f'---\ntitle: "{title}"\ndescription: "{desc}"\n---\n\n'
        with open(os.path.join(out_dir, f"{slug}.md"), "w", encoding="utf-8") as f:
            f.write(fm + _redact(body, keep_domains))
        written += 1
        print(f"  ok   {slug}")

    print(f"Imported {written} prior docs to {out_dir} ({failed} failed)")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    merge_parser = sub.add_parser("merge", help="merge per-recording graphs into the raw graph")
    merge_parser.add_argument("--allow-empty", action="store_true",
                              help="publish an empty merged graph when the source set is intentionally empty")
    sub.add_parser("gen-issues", help="export GitHub issues to issues.json")
    sub.add_parser("gen-sessions", help="build app/sessions.json from recordings")
    sub.add_parser("import-drive-docs", help="import curated Drive docs to knowledge/docs/prior/")

    handlers = {
        "merge": cmd_merge,
        "gen-issues": cmd_gen_issues,
        "gen-sessions": cmd_gen_sessions,
        "import-drive-docs": cmd_import_drive_docs,
    }
    args = parser.parse_args()
    handlers[args.command](args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        print(f"merge-kg: {exc}", file=sys.stderr)
        sys.exit(1)
