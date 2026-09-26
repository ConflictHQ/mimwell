"""Explicit transcription versions and unaltered estimates with available windows."""


def is_transcription(receipt):
    return receipt.get('format') in ('intake-transcription/v1', 'intake-transcription/v2',
                                     'intake-recording-transcription/v1')


def timed_segment(start, end, text, frames, max_overrun_ms):
    """Intersect a model estimate with real frames; this is not speech alignment."""
    if (any(type(value) is not int for value in (start, end, frames, max_overrun_ms))
            or not 1 <= frames <= 9600000 or not 0 <= max_overrun_ms <= 30000
            or not 0 <= start < end <= 630000 or start * 16 >= frames
            or end * 16 > frames + max_overrun_ms * 16 or not isinstance(text, str)):
        raise ValueError('Invalid reported timing or source window')
    return {'reportedLocator': {'kind': 'audio-ms', 'start': start, 'end': end},
            'sourceWindow': {'kind': 'audio-frames', 'start': start * 16, 'end': min(end * 16, frames)},
            'timingStatus': 'extends-past-audio' if end * 16 > frames else 'within-audio-estimate',
            'text': text}
