"""Bounded local JSONL pipe observation; never stages files or chooses grants."""
import fcntl
import os
import selectors
import stat
import time

from connector_host import ConnectorHostError, MAX_EXPORT_BYTES


def read_pipe(stream, max_bytes, *, timeout=5):
    if (type(max_bytes) is not int or not 0 <= max_bytes <= MAX_EXPORT_BYTES
            or type(timeout) not in (int, float) or not 0 < timeout <= 30):
        raise ConnectorHostError('Invalid connector pipe admission bound')
    fd = stream.fileno()
    info = os.fstat(fd)
    regular = stat.S_ISREG(info.st_mode)
    if not regular and not (stat.S_ISFIFO(info.st_mode) or stat.S_ISSOCK(info.st_mode)):
        raise ConnectorHostError('Connector stdin must be a regular file, pipe or socket')
    deadline = time.monotonic() + timeout
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    selector = selectors.DefaultSelector()
    result = bytearray()
    try:
        if not regular:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            selector.register(fd, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ConnectorHostError('Connector stdin exceeded its admission deadline')
            if not regular and not selector.select(remaining):
                raise ConnectorHostError('Connector stdin exceeded its admission deadline')
            try:
                chunk = os.read(fd, min(65536, max_bytes + 1 - len(result)))
            except BlockingIOError:
                continue
            if not chunk:
                return bytes(result)
            result.extend(chunk)
            if len(result) > max_bytes:
                raise ConnectorHostError('Connector stdin exceeds the registered byte limit')
    finally:
        selector.close()
        if not regular:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags)
