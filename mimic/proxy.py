"""Secure runtime state shared by the proxy and mimic CLI processes."""
import json
import os
import stat
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


def state_path():
    """Location of the short-lived mitmweb connection state."""
    override = os.environ.get("MIMIC_STATE_FILE")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".mimic" / "proxy.json"


def load_state():
    """Read proxy state, returning None for missing or invalid state."""
    path = state_path()
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            return None
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            return None
        with path.open(encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(state, dict):
        return None
    if not isinstance(state.get("url"), str) or not isinstance(
        state.get("token"), str
    ):
        return None
    try:
        url = urlsplit(state["url"])
        hostname = url.hostname
        port = url.port
    except ValueError:
        return None
    if (
        url.scheme != "http"
        or hostname not in {"127.0.0.1", "::1", "localhost"}
        or port is None
        or url.username is not None
        or url.password is not None
        or url.path not in ("", "/")
        or url.query
        or url.fragment
        or not state["token"]
    ):
        return None
    return state


def save_state(state):
    """Atomically write proxy state readable only by the current user."""
    path = state_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass

    fd, temporary = tempfile.mkstemp(prefix=".proxy-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = -1
            json.dump(state, f)
            f.write("\n")
        os.replace(temporary, path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def clear_state(token=None):
    """Remove state, optionally only when it belongs to the given process token."""
    path = state_path()
    if token is not None:
        current = load_state()
        if not current or current.get("token") != token:
            return False
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


def pid_is_running(pid):
    """Return whether a recorded proxy process still exists."""
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
