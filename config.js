// Central config barrel (JS runtime) — the single source of truth.
//
// Loads client.config.json ONCE, deep-freezes it so the config object is
// read-only (config is input, not mutable state), and exports the frozen
// `settings` singleton. Every JS consumer — the worker and any future module —
// imports from here so there is exactly one config shape:
//
//   import { settings } from "./config.js";
//
// Mirrors scripts/config.py on the JS side. The bundler inlines the JSON import
// at build time, so this is a zero-cost compile-time load. Stays client-
// agnostic: no client values live here, only the loading/freezing seam.

import config from "./client.config.json";

function deepFreeze(obj) {
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    if (value && typeof value === "object" && !Object.isFrozen(value)) {
      deepFreeze(value);
    }
  }
  return Object.freeze(obj);
}

// Purpose-neutral owner seam (#206, Phase 2: canonical). brain.name /
// brain.shortName / brain.purpose / brain.owner are the documented, canonical
// seam; client.* is a DEPRECATED read alias, accepted for one more release
// (2026-09-24 decision), so an unmigrated config still resolves. Mirrors
// scripts/config.py's _resolve_owner_seam — same fields, same fallback order —
// so both runtimes agree. Mutates IN PLACE, before freezing, filling only the
// keys the config itself left absent.
function resolveOwnerSeam(cfg) {
  const client = (cfg && cfg.client) || {};
  if (!cfg.brain || typeof cfg.brain !== "object") cfg.brain = {};
  const brain = cfg.brain;
  if (brain.name === undefined && client.name) brain.name = client.name;
  if (brain.shortName === undefined) {
    if (client.shortName) brain.shortName = client.shortName;
    else if (brain.name) brain.shortName = brain.name;
  }
  if (brain.purpose === undefined && client.engagement) brain.purpose = client.engagement;
  if (brain.owner === undefined && client.name) brain.owner = { kind: "organization", name: client.name };
}
resolveOwnerSeam(config);

export const settings = deepFreeze(config);

export default settings;
