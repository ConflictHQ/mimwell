"""Non-reaping observation and cleanup of a caller-owned POSIX process group.

These primitives do not grant filesystem, authority, network or model permission.
A child must be started in its own session, and no other reaper may own it.
"""
import errno
import os
import signal
import subprocess
import sys
import time


class OwnedProcessError(ValueError):
    pass


def require_waitid():
    """Require non-reaping leader observation before starting an owned group."""
    required = ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT")
    if (not sys.platform.startswith(("darwin", "linux"))
            or not callable(getattr(os, "waitid", None))
            or any(not hasattr(os, name) for name in required)):
        raise OwnedProcessError("Safe process-group cleanup is unavailable on this platform")


def observe_unreaped_leader(child):
    """Return non-reaping waitid state; never signal a PID whose ownership is lost."""
    while True:
        try:
            result = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            break
        except InterruptedError:
            continue
        except OSError as exc:
            # In particular, ECHILD means another reaper may have released the
            # PID. Never signal its former process group in that state.
            raise OwnedProcessError("Cannot safely confirm ownership of the process group") from exc
    if result is not None and result.si_pid not in (0, child.pid):
        raise OwnedProcessError("Process wait returned an unrelated child identity")
    return result


def wait_unreaped_leader(child, timeout, timeout_message):
    """Wait for leader exit without reaping its PID, so the group ID stays owned."""
    deadline = time.monotonic() + timeout
    while True:
        result = observe_unreaped_leader(child)
        if result is not None and result.si_pid == child.pid:
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OwnedProcessError(timeout_message)
        time.sleep(min(0.01, remaining))


def kill_process_group(child):
    """Kill the owned group before the unreaped leader PID can be recycled."""
    require_waitid()
    # Popen.wait()/poll() reaps its leader. Reconfirm that the direct child is
    # still waitable before using its PID as a process-group ID.
    observed = observe_unreaped_leader(child)
    leader_exited = (observed is not None and observed.si_pid == child.pid
                     and observed.si_code in {getattr(os, name, None) for name in
                                              ("CLD_EXITED", "CLD_KILLED", "CLD_DUMPED")})
    kill_error = None
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        kill_error = exc
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        raise OwnedProcessError("Process did not terminate within its cleanup bound")
    # Darwin's killpg excludes zombie members. If the owned leader is already
    # an unreaped zombie and no live group member could be signaled, XNU returns
    # EPERM; a live same-UID descendant is still signaled successfully. Keep
    # this exception narrow: a live leader or another platform's EPERM remains
    # a cleanup failure.
    expected_darwin_zombie_group = (sys.platform == "darwin" and leader_exited
                                    and isinstance(kill_error, PermissionError)
                                    and kill_error.errno == errno.EPERM)
    if kill_error is not None and not expected_darwin_zombie_group:
        raise OwnedProcessError("Process group cleanup failed") from kill_error
