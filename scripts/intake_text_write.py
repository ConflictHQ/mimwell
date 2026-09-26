"""Fresh native write gate for derived judgments, separate from historical replay."""
from copy import deepcopy

from context_access import ReadBoundary
from intake_contract import IntakeError, validate_history
from intake_text_projection import authorize
from knowledge_policy import timestamp


def current_judgment(authority, record, *, actor, at):
    history = record.get('content', {}).get('data', {}).get('intakeHistory')
    if not history or history.get('format') not in ('intake-history/v3', 'intake-history/v4'):
        return
    validate_history(history)
    provider = authority.intake_judgment_authorization
    if not callable(provider):
        raise IntakeError('Projected history requires current native source/model authorization')
    boundary, protection, selected_entry = provider(deepcopy(history), actor=actor, at=at)
    projection = history['events'][0]['mechanism']['inputProjection']
    if selected_entry != projection['entry']:
        raise IntakeError('Projected history differs from the independently selected processing header')
    policy = authority.contract.policy
    resource = authority.contract.collections[record['collection']]['resource']
    if (not isinstance(boundary, ReadBoundary) or boundary.actor != actor
            or boundary.policy.binding != policy.binding
            or timestamp(boundary.now) < timestamp(at)
            or timestamp(boundary.now) < timestamp(projection['authorization']['evaluatedAt'])
            or policy.resources[resource]['scope'] != projection['entry']['scope']):
        raise IntakeError('Projected history write actor, policy, clock or destination scope changed')
    classifier, _ = authorize(projection['entry'], history['item'], projection['classifier']['identity'],
                              boundary, protection, retained=projection['protection']['requirements'],
                              reuse_authorization=authority.intake_processing_reuse_selection)
    if classifier != projection['classifier']:
        raise IntakeError('Projected history current classifier binding changed')
