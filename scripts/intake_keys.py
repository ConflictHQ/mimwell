"""Exact delivered-reference identity, distinct from reusable content processing."""
from knowledge_policy import fingerprint


def completion_key(item, destination, processing, labels, basis):
    return fingerprint({'format': 'intake-completion-key/v2', 'item': item,
                        'destination': destination, 'processing': processing,
                        'labels': sorted(labels), 'basis': basis})
