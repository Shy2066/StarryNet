"""Small Python 3.6-compatible process-group shutdown helper for V2."""

import errno
import os
import signal
import subprocess
import time


def signal_group(process, signum):
    try:
        os.killpg(process.pid, signum)
        return True
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False
        raise


def process_group_exists(process_group_id):
    try:
        os.killpg(process_group_id, 0)
        return True
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False
        return True


def stop_process_group(process, interrupt_grace_seconds,
                       terminate_grace_seconds=5, kill_grace_seconds=5):
    """Stop a new-session subprocess and wait for the entire group to exit."""
    forced = False
    if process.poll() is not None and not process_group_exists(process.pid):
        stdout, stderr = process.communicate()
        return process.returncode, stdout, stderr, forced, True
    for signum, wait_seconds in (
            (signal.SIGINT, interrupt_grace_seconds),
            (signal.SIGTERM, terminate_grace_seconds),
            (signal.SIGKILL, kill_grace_seconds)):
        signal_group(process, signum)
        try:
            stdout, stderr = process.communicate(timeout=wait_seconds)
        except subprocess.TimeoutExpired:
            forced = True
            stdout, stderr = None, None
        if not process_group_exists(process.pid):
            return process.returncode, stdout, stderr, forced, True
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline and process_group_exists(process.pid):
        time.sleep(0.05)
    if process.poll() is None:
        try:
            stdout, stderr = process.communicate(timeout=0.1)
        except subprocess.TimeoutExpired:
            stdout, stderr = None, None
    return process.returncode, stdout, stderr, True, not process_group_exists(process.pid)
