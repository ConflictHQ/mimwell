"""Strict scheduled tracker reads; ordinary local exports keep their legacy mode."""
import json
import os


def strict():
    value = os.environ.get('BRAIN_REFRESH_STRICT', '0')
    if value not in ('0', '1'):
        raise ValueError('BRAIN_REFRESH_STRICT must be 0 or 1')
    return value == '1'


def read_config(path, field):
    required = strict()
    try:
        with open(path, encoding='utf-8') as stream:
            config = json.load(stream)
    except (FileNotFoundError, json.JSONDecodeError):
        if required:
            raise
        return {}
    block = config.get(field)
    if required:
        if field in config and not isinstance(block, dict):
            raise ValueError('Tracker configuration block must be an object')
        block = block or {}
        repos = block.get('repos', [])
        projects = block.get('projects', [])
        if not isinstance(repos, list) or any(not isinstance(r, str) or not r.strip() for r in repos):
            raise ValueError('Tracker repos must be an array of nonempty strings')
        if not isinstance(projects, list) or any(
                not isinstance(p, dict) or type(p.get('number')) is not int or p['number'] <= 0
                or not isinstance(p.get('name'), str) or not p['name'].strip() for p in projects):
            raise ValueError('Tracker projects must declare positive numbers and names')
        if projects and (not isinstance(block.get('org'), str) or not block['org'].strip()):
            raise ValueError('Configured tracker projects require an organization')
    return block if isinstance(block, dict) else {}


def collection(raw, *, project=False):
    value = json.loads(raw)
    if strict():
        if project and (not isinstance(value, dict) or 'items' not in value):
            raise ValueError('Project response requires an explicit items array')
        records = value['items'] if project else value
        if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
            raise ValueError('Tracker response requires an array of records')
    return value.get('items', []) if project else value
