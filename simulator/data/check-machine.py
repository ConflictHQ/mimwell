#!/usr/bin/env python3
"""Referential-integrity + honesty checks for the simulator's machine.json.

Mirrors the machine-schema.md validator intent (V1, V3, V5, V8) plus the
proof-03 connection-point discipline (spec delta 12), which is checked twice:

  1. every connection path must start and end exactly on the declared port
     (data against data), tolerance 2px; and
  2. every declared port must itself sit on the machinery it anchors to
     (data against the drawing), same tolerance — otherwise a port can float
     in mid-air, the path can end exactly on it, and check (1) reports success.

It also carries the content completeness the v2 rulings added: tech on every
component (27), how on every capability (31), narrative + sources on every
scenario (28), and — permanently, rather than as a one-off before a release —
the beat check: every beat target must resolve against the frame map, the
connection list or a placed component, because the player silently no-ops a
beat whose target it cannot find.
"""
import json
import math
import os
import re
import sys
from pathlib import Path

PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "machine.json"
# machine.json is engagement-owned: a brain that has not adopted the simulator has
# none. That is a clean skip, as machine-check skips an absent app/machine.json (#362);
# a path named on the command line must still exist.
if len(sys.argv) <= 1 and not PATH.is_file():
    print("simulator-check: simulator/data/machine.json absent — skipped (simulator not adopted)")
    sys.exit(0)

TOL = 2.0
PSEUDO_ENDPOINTS = {"products"}  # the product wall: docked works, not a component

# Frame silhouettes in TEMPLATE-LOCAL coordinates, transcribed from the frame art
# (the T[...] built-ins in app/index.html and the bespoke templates in
# app/frames.js). Only the load-bearing outline is transcribed — the body panel,
# its roof/nameplate, and any structure a spoke is meant to land on. World
# placement comes from the frame map in machine.json (x, y, scale), so moving a
# frame in the data carries its silhouette with it.
#   ("rect", x0, y0, x1, y1) | ("circle", cx, cy, r) | ("annulus", cx, cy, r_in, r_out)
TEMPLATE_BOUNDS = {
    # four dock subframes 260 apart, each a body rect under a roof flange
    "fr-docks": [s for i in range(6) for s in (("rect", 0, i * 260, 130, i * 260 + 100),
                                               ("rect", -8, i * 260 - 18, 138, i * 260))],
    # the built-in generic frame template in app/index.html
    "generic": [("rect", 0, 0, 190, 120)],
}

# Privacy (V8). The artifact must not name a person or point at a specific
# session. Writing the denied names into this file would itself be the leak, so
# the committed check is nameless: it scans for meeting / session / attribution
# shapes. An installation can supply a literal name list out of band through
# PRIVACY_DENYLIST_FILE (one entry per line, '#' comments and blanks ignored);
# its hits are reported by line number so the names stay out of CI logs too.
_MONTHS = ("january|february|march|april|june|july|august|september|october|"
           "november|december")  # 'may' omitted: it collides with the modal verb
PRIVACY_PATTERNS = [
    r"\bexec(utive)?\s+(meeting|session|review|call|readout)\b",
    r"\b(%s)\s+(session|list|review|meeting|call|workshop)\b" % _MONTHS,
    r"\battendees?\b",
    r"\b(live|design|proof|sprint|steering)\s+review\b",
    r"\breview\s+session\b",
    r"\bstand-?up\b",
    r"\bper\s+the\s+(call|meeting|session|review)\b",
    r"\b(he|she|they)\s+said\b",
    r"\bas\s+\w+\s+(said|noted|put it)\b",
    r"\bminutes\s+of\s+the\b",
    r"\bactions?\s+from\s+the\s+(call|meeting|session|review)\b",
]

errors, warnings, notes = [], [], []

doc = json.loads(PATH.read_text())

components = {c["id"]: c for c in doc["components"]}
capabilities = {k["id"]: k for k in doc["capabilities"]}
products = {p["id"]: p for p in doc["products"]}
frames = {f["id"]: f for f in doc["frames"]}

if len(components) != len(doc["components"]):
    errors.append("duplicate component ids")
if len(frames) != len(doc["frames"]):
    errors.append("duplicate frame ids")
conn_ids = [c["id"] for c in doc["connections"]]
if len(set(conn_ids)) != len(conn_ids):
    errors.append("duplicate connection ids: %s" %
                  {i for i in conn_ids if conn_ids.count(i) > 1})


# ---------- path geometry ----------
def path_endpoints(d):
    """Return ((x0,y0),(x1,y1)) for an SVG path using M/C/L/H/V absolute cmds."""
    toks = re.findall(r"[MCLHVmclhv]|-?\d+(?:\.\d+)?", d)
    i, cur, start = 0, None, None
    while i < len(toks):
        cmd = toks[i]
        if cmd not in "MCLHV":
            raise ValueError("unsupported path command %r in %r" % (cmd, d))
        i += 1
        nums = []
        while i < len(toks) and toks[i] not in "MCLHVmclhv":
            nums.append(float(toks[i]))
            i += 1
        if cmd == "M":
            cur = (nums[0], nums[1])
            start = cur
        elif cmd == "L":
            cur = (nums[-2], nums[-1])
        elif cmd == "C":
            cur = (nums[-2], nums[-1])
        elif cmd == "H":
            cur = (nums[-1], cur[1])
        elif cmd == "V":
            cur = (cur[0], nums[-1])
    return start, cur


def resolve_endpoint(ref, side, conn_id):
    """Return (component, port_coords_or_None). Records errors."""
    if ref in PSEUDO_ENDPOINTS:
        notes.append("%s.%s -> %r (pseudo-endpoint: the docked product wall)" % (conn_id, side, ref))
        return None, None
    comp_id, _, port = ref.partition(".")
    comp = components.get(comp_id)
    if comp is None:
        errors.append("connection %s: %s endpoint %r names no component" % (conn_id, side, ref))
        return None, None
    if not port:
        warnings.append("connection %s: %s endpoint %r has no port — spec delta 12 wants "
                        "every line to terminate on a declared port" % (conn_id, side, ref))
        return comp, None
    p = (comp.get("ports") or {}).get(port)
    if p is None:
        errors.append("connection %s: %s port %r not declared on %s" % (conn_id, side, port, comp_id))
        return comp, None
    return comp, (p["x"], p["y"])


for conn in doc["connections"]:
    cid = conn["id"]
    frm, frm_pt = resolve_endpoint(conn["from"], "from", cid)
    to, to_pt = resolve_endpoint(conn["to"], "to", cid)
    if "pii" not in conn:
        warnings.append("connection %s: no pii flag" % cid)
    if "path" in conn:
        try:
            p0, p1 = path_endpoints(conn["path"])
        except ValueError as exc:
            errors.append("connection %s: %s" % (cid, exc))
            continue
        for label, got, want in (("start", p0, frm_pt), ("end", p1, to_pt)):
            if want is None:
                continue
            dx, dy = abs(got[0] - want[0]), abs(got[1] - want[1])
            if dx > TOL or dy > TOL:
                errors.append("connection %s: path %s %s is %.0fpx,%.0fpx off port %s"
                              % (cid, label, got, dx, dy,
                                 conn["from"] if label == "start" else conn["to"]))
    # PII coherence: a raw-PII line should touch a declared PII zone at one end
    if conn.get("pii"):
        zones = [c for c in (frm, to) if c and c.get("piiZone")]
        if not zones:
            notes.append("connection %s carries pii but neither endpoint declares piiZone "
                         "(v1 convention: only resting zones declare it)" % cid)


# ---------- ports land on the drawing, not beside it (spec delta 12) ----------
def shape_gap(shape, x, y):
    """Signed distance from (x, y) to a silhouette primitive, template-local.
    Negative = inside the machinery, positive = that many px out in open space."""
    kind = shape[0]
    if kind == "rect":
        _, x0, y0, x1, y1 = shape
        dx = max(x0 - x, 0.0, x - x1)
        dy = max(y0 - y, 0.0, y - y1)
        if dx or dy:
            return math.hypot(dx, dy)
        return -min(x - x0, x1 - x, y - y0, y1 - y)
    if kind == "circle":
        _, cx, cy, r = shape
        return math.hypot(x - cx, y - cy) - r
    if kind == "annulus":
        _, cx, cy, r_in, r_out = shape
        m = math.hypot(x - cx, y - cy)
        return max(r_in - m, m - r_out)
    raise ValueError("unknown silhouette primitive %r" % (kind,))


def port_gap(frame, x, y):
    """Signed world-space distance from a port to its frame's drawn silhouette."""
    scale = frame.get("scale") or 1.0
    lx, ly = (x - frame["x"]) / scale, (y - frame["y"]) / scale
    bounds = TEMPLATE_BOUNDS[frame.get("template") or frame["id"]]
    return min(shape_gap(s, lx, ly) for s in bounds) * scale


frame_of = {m: f for f in doc["frames"] for m in f["components"]}
for f in doc["frames"]:
    if (f.get("template") or f["id"]) not in TEMPLATE_BOUNDS:
        errors.append("frame %s has no TEMPLATE_BOUNDS entry, so its ports cannot be checked "
                      "against the drawing — transcribe the template silhouette (spec delta 12)"
                      % f["id"])

ports_checked = ports_off = 0
for cid in sorted(components):
    fr = frame_of.get(cid)
    for pn, p in (components[cid].get("ports") or {}).items():
        if fr is None:
            notes.append("port %s.%s is declared on a component with no frame placement, so it "
                         "cannot be measured against a drawing" % (cid, pn))
            continue
        if (fr.get("template") or fr["id"]) not in TEMPLATE_BOUNDS:
            continue  # already an error above; don't double-report per port
        ports_checked += 1
        gap = port_gap(fr, p["x"], p["y"])
        if gap > TOL:
            ports_off += 1
            errors.append("port %s.%s at (%g,%g) floats %.1fpx off the %s drawing — spec delta 12 "
                          "wants spokes landing on machinery, not beside it"
                          % (cid, pn, p["x"], p["y"], gap, fr["id"]))

# ---------- frames ----------
seen_in_frame = {}
for f in doc["frames"]:
    if "epigram" not in f or not f["epigram"].strip():
        errors.append("frame %s: missing epigram (spec delta 16)" % f["id"])
    for m in f["components"]:
        if m not in components:
            errors.append("frame %s: member %r names no component" % (f["id"], m))
        elif m in seen_in_frame:
            errors.append("component %s placed in two frames (%s, %s)" % (m, seen_in_frame[m], f["id"]))
        else:
            seen_in_frame[m] = f["id"]

for cid, c in components.items():
    if cid not in seen_in_frame:
        if "factory" in c["views"]:
            errors.append("component %s is in the factory view but has no frame placement" % cid)
        else:
            notes.append("component %s has no frame placement (views: %s)" % (cid, ",".join(c["views"])))
    for internal in c.get("internals", []):
        if internal["id"] not in components:
            warnings.append("component %s: internal %r does not resolve to a component card"
                            % (cid, internal["id"]))

# ---------- capabilities / products ----------
for kid, k in capabilities.items():
    for u in k["unlockedBy"]:
        if u not in components:
            errors.append("capability %s: unlockedBy %r names no component" % (kid, u))
    for p in k["products"]:
        if p not in products:
            errors.append("capability %s: products %r names no product" % (kid, p))
        elif kid not in products[p]["consumes"]:
            errors.append("capability %s lists product %s, but %s.consumes omits it" % (kid, p, p))
    status = k.get("status")
    built = [u for u in k["unlockedBy"] if components.get(u, {}).get("delivery", {}).get("status") == "built"]
    if status == "solves" and len(built) != len(k["unlockedBy"]):
        warnings.append("capability %s: assessed-once-unlocked status 'solves' (chip suppressed until %d/%d unlockedBy are built)"
                        % (kid, len(built), len(k["unlockedBy"])))
    if status in ("partially-solves", "blocked-on-data"):
        if not k.get("statusNote"):
            errors.append("capability %s: %s requires a statusNote" % (kid, status))
        if not built:
            warnings.append("capability %s: assessed-once-unlocked status %r (chip suppressed; zero built machinery yet)" % (kid, status))
    if status is None and not k.get("statusNote"):
        warnings.append("capability %s has no status and no statusNote" % kid)

for pid, p in products.items():
    for kid in p["consumes"]:
        if kid not in capabilities:
            errors.append("product %s: consumes %r names no capability" % (pid, kid))
        elif pid not in capabilities[kid]["products"]:
            errors.append("product %s consumes %s, but %s.products omits it" % (pid, kid, kid))

# ---------- content completeness (rulings 27, 31) ----------
for cid, c in components.items():
    if not (c.get("tech") or "").strip():
        errors.append("component %s: no tech — the components and infra views lead with the vendor "
                      "or service name at this depth (ruling 27)" % cid)

for kid, k in capabilities.items():
    if not (k.get("how") or "").strip():
        errors.append("capability %s: no how — a capability card has to name the mechanism chain "
                      "that produces it, not only what it does and why (ruling 31)" % kid)

# ---------- scenarios: narrative, sources, and beat targets (rulings 18, 28) ----------
# What each verb's target has to name, transcribed from the beat interpreter in
# app/index.html. 'overview' is a camera the app derives from the content bounds
# rather than a frame, so it is a legal camera target and nothing else.
BEAT_TARGET_KIND = {
    "camera": "frame",              # goCam(CAMS[target]) — frame ids + overview
    "travel": "connection",         # M.connections.find(id === target)
    "process": "placed-component",  # frameOfComp(target) -> pulse that frame
    "commission": "placed-component",   # frameOfComp(target) -> colorize it
    "card": "component",            # showCard(target)
    "flag": "frame-or-component",   # frameEls[target] || frameOfComp(target)
    "caption": None,                # no target: the caption itself is the beat
}
DERIVED_CAMS = {"overview"}
connection_ids = {c["id"] for c in doc["connections"]}


def beat_target_resolves(kind, target):
    if kind == "frame":
        return target in frames or target in DERIVED_CAMS
    if kind == "connection":
        return target in connection_ids
    if kind == "component":
        return target in components
    if kind == "placed-component":
        return target in components and target in frame_of
    if kind == "frame-or-component":
        return target in frames or (target in components and target in frame_of)
    raise ValueError("unknown beat target kind %r" % (kind,))


scenarios = doc.get("scenarios", [])
scenario_ids = [s["id"] for s in scenarios]
if len(set(scenario_ids)) != len(scenario_ids):
    errors.append("duplicate scenario ids: %s" %
                  {i for i in scenario_ids if scenario_ids.count(i) > 1})

beats_checked = 0
for s in scenarios:
    sid = s["id"]
    if not (s.get("mode") or "").strip():
        errors.append("scenario %s: no mode — the walkthrough has to declare which play mode it is "
                      "honest in (end-state colors everything)" % sid)
    if not (s.get("epigram") or "").strip():
        errors.append("scenario %s: missing epigram (spec delta 16)" % sid)

    narrative = (s.get("narrative") or "").strip()
    if not narrative:
        errors.append("scenario %s: no narrative — the read-along panel needs the whole use case as "
                      "prose, not the captions concatenated (ruling 28)" % sid)
    else:
        paras = [p for p in narrative.split("\n\n") if p.strip()]
        if not 2 <= len(paras) <= 4:
            errors.append("scenario %s: narrative is %d paragraph(s); ruling 28 wants 2–4, "
                          "separated by a blank line" % (sid, len(paras)))

    sources = s.get("sources") or []
    if not sources:
        errors.append("scenario %s: no sources — every walkthrough cites the brain documents it is "
                      "accurate to (ruling 28)" % sid)
    for i, source in enumerate(sources):
        if not (source.get("label") or "").strip():
            errors.append("scenario %s: source %d has no label" % (sid, i))
        href = source.get("href") or ""
        if not href.startswith("/"):
            errors.append("scenario %s: source href %r must be a site-relative path starting with "
                          "'/' — the panel opens it against the portal, not the simulator's own "
                          "directory" % (sid, href))

    for i, b in enumerate(s.get("beats") or []):
        verb = b.get("verb")
        if verb not in BEAT_TARGET_KIND:
            errors.append("scenario %s beat %d: verb %r is not in the player's verb set %s"
                          % (sid, i, verb, sorted(BEAT_TARGET_KIND)))
            continue
        kind = BEAT_TARGET_KIND[verb]
        target = b.get("target")
        if kind is None:
            if target is not None:
                errors.append("scenario %s beat %d: a caption beat carries target %r, which the "
                              "player ignores — say it with a verb that does something"
                              % (sid, i, target))
            if not (b.get("caption") or "").strip():
                errors.append("scenario %s beat %d: caption beat with no caption" % (sid, i))
            continue
        if not target:
            errors.append("scenario %s beat %d: %s beat has no target" % (sid, i, verb))
            continue
        beats_checked += 1
        if not beat_target_resolves(kind, target):
            errors.append("scenario %s beat %d: %s target %r resolves to no %s, so the player would "
                          "silently skip it" % (sid, i, verb, target, kind.replace("-", " ")))

# ---------- delivery honesty ----------
for cid, c in components.items():
    d = c["delivery"]
    if d["status"] == "built" and not d.get("evidence"):
        errors.append("component %s is 'built' with no evidence" % cid)
    if d["status"] == "built" and not (d.get("date") or c.get("existing")):
        warnings.append("component %s is 'built' with no date and is not marked existing" % cid)
    if d["phase"] == "post-1" and re.search(r"phase\s*[23]", json.dumps(c), re.I):
        errors.append("component %s is post-1 but names a numeral phase" % cid)
    for field in ("body", "valueLine"):
        if not c.get(field, "").strip():
            errors.append("component %s: empty %s" % (cid, field))

# ---------- privacy (V8) ----------
blob = json.dumps(doc, ensure_ascii=False)
for pattern in PRIVACY_PATTERNS:
    hits = len(re.findall(pattern, blob, re.I))
    if hits:
        errors.append("privacy: %d match(es) for the meeting/attribution pattern %s — the "
                      "artifact must not point at a specific session" % (hits, pattern))

denylist_file = os.environ.get("PRIVACY_DENYLIST_FILE")
if denylist_file:
    denylist_path = Path(denylist_file)
    if not denylist_path.is_file():
        errors.append("privacy: PRIVACY_DENYLIST_FILE is set to %r but there is no file there"
                      % denylist_file)
    else:
        for lineno, line in enumerate(denylist_path.read_text().splitlines(), 1):
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            if re.search(r"\b%s" % re.escape(entry), blob, re.I):
                errors.append("privacy: PRIVACY_DENYLIST_FILE entry on line %d appears in the "
                              "document (the entry itself is withheld from this report)" % lineno)

# ---------- report ----------
built = [c for c in components.values() if c["delivery"]["status"] == "built"]
print("components: %d   frames: %d   connections: %d   capabilities: %d   products: %d"
      % (len(components), len(frames), len(doc["connections"]), len(capabilities), len(products)))
print("ports on the drawing: %d/%d (spec delta 12, tolerance %gpx)"
      % (ports_checked - ports_off, ports_checked, TOL))
print("scenarios: %d   targeted beats resolved: %d   sources cited: %d"
      % (len(scenarios), beats_checked, sum(len(s.get("sources") or []) for s in scenarios)))
print("built: %s" % ", ".join(sorted(c["id"] for c in built)))
for n in notes:
    print("NOTE   %s" % n)
for w in warnings:
    print("WARN   %s" % w)
for e in errors:
    print("ERROR  %s" % e)
print("\n%d error(s), %d warning(s)" % (len(errors), len(warnings)))
sys.exit(1 if errors else 0)
