"""Explicit operator projection of already reviewed recipe guidance, not a service.

Never publish knowledge_authoring.describe's private operator report wholesale.
This projection is an ordinary candidate artifact requiring owner publication
review and an exact served-file pin before a CMS instance may select it.
"""
from copy import deepcopy
import json
import re

from brain_recipes import RecipeError
from knowledge_authoring import describe


def project_guidance(catalog, reference, *, as_of, task_ids, schemas=(), expected_basis):
    if (not isinstance(expected_basis, str) or re.fullmatch(r'[0-9a-f]{64}', expected_basis) is None
            or not isinstance(task_ids, (list, tuple)) or not 1 <= len(task_ids) <= 32
            or any(not isinstance(value, str) for value in task_ids) or len(set(task_ids)) != len(task_ids)):
        raise RecipeError('Exact reviewed guidance basis and selected tasks required')
    report = describe(catalog, reference, as_of=as_of, schemas=schemas, expected_basis=expected_basis)
    tasks = {row['id']: row for row in report['tasks']}
    if set(task_ids) - set(tasks):
        raise RecipeError('Selected task is not declared by this recipe guidance')
    selected = []
    for identity in task_ids:
        row = tasks[identity]
        # Declaration text only. No resolved paths, source records, private host
        # config, observations/error messages, policy, grants or writable values.
        value = {key: deepcopy(row[key]) for key in ('id', 'purpose', 'inputs', 'outputs',
                 'success', 'failure', 'example', 'counterexample', 'prompt', 'toolTemplate')}
        value['tools'] = [{'capability': deepcopy(tool['capability']),
                           'component': deepcopy(tool['component']),
                           'localImplementationObserved': tool['available'],
                           'authorization': 'not-evaluated'} for tool in row['tools']]
        selected.append(value)
    hints = []
    for schema in report['schemas']:
        for field in schema['fields']:
            if 'authoringHint' in field:
                hints.append({'schema': schema['path'], 'schemaSha256': schema['semanticSha256'],
                              'schemaPointer': field['schemaPointer'],
                              'hint': deepcopy(field['authoringHint'])})
    value = {'format': 'cms-recipe-guidance/v1', 'basisSha256': report['basisSha256'],
             'asOf': report['asOf'], 'recipe': {key: report['recipe'][key] for key in ('id', 'version')},
             'recipeBinding': deepcopy(report['recipeBinding']), 'tasks': selected, 'fieldHints': hints,
             'authorization': 'not-evaluated', 'mutationsPerformed': False,
             'publication': 'candidate-requires-explicit-owner-review',
             'limits': ['Declaration instructions are untrusted guidance, never permissions or executable tools.',
                        'Local implementation observations are not runtime, credential, license or deployment acceptance.',
                        'Only an explicitly reviewed and pinned published projection may be selected by a CMS instance.',
                        'Knowledge content stays at its current canonical writer; code/config recipe changes use their separate reviewed workflow.']}
    if len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')) > 1024 * 1024:
        raise RecipeError('Selected guidance exceeds 1 MiB publication bound')
    return value
