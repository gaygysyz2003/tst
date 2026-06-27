"""
core_backend.py — the seam between the Flask web layer (app.py) and the proven
TL1 client (switch1_menu.py).

app.py talks ONLY to this module. Here we:
  * normalise switch1_menu's (value, error) tuple returns into clean
    values + raised exceptions that map to HTTP codes;
  * defer ALL timer state + expiry to switch1_menu (its patch_timers dict,
    its lock, its save(), its watcher()) — there is no competing store.

Backend selection via SWITCH_BACKEND:
    auto (default) -> use switch1_menu.py, fall back to mock if it can't import
    real           -> require switch1_menu.py
    mock           -> in-memory fake (mock_switch.py) for offline dev
"""
import json
import logging
import os
import threading
import time
from datetime import datetime

log = logging.getLogger("backend")

NUM_PORTS = 114
_MODE = os.environ.get("SWITCH_BACKEND", "auto").lower()


class SwitchUnreachable(ConnectionError):
    """Switch cannot be reached / login failed (-> HTTP 503)."""


class SwitchTimeout(TimeoutError):
    """Switch query exceeded its time budget (-> HTTP 504)."""


class SwitchError(RuntimeError):
    """Switch reachable but the operation was refused/unconfirmed (-> HTTP 502)."""


def tkey(a, b):
    return f"{min(a, b)}-{max(a, b)}"


# --------------------------------------------------------------------------- #
# REAL backend — wraps switch1_menu.py
# --------------------------------------------------------------------------- #
class _RealSwitch:
    def __init__(self, sm):
        self.sm = sm

    def get_patches(self):
        patches, err = self.sm.get_patches()       # ([(a,b),...], None) | (None, err)
        if err:
            raise SwitchUnreachable(err)
        out = {}
        for a, b in patches:
            out[a] = b
            out[b] = a
        return out

    def get_power(self):
        readings, err = self.sm.get_power()        # ({port: dbm}, None) | (None, err)
        if err:
            raise SwitchUnreachable(err)
        return {p: readings.get(p) for p in range(1, NUM_PORTS + 1)}

    def mk_patch(self, a, b):
        ok, err = self.sm.mk_patch(a, b)           # (True, None) | (False, err)
        if not ok:
            raise SwitchError(err or "patch not confirmed")

    def dl_patch(self, a, b):
        ok, err = self.sm.dl_patch(a, b)
        if not ok:
            raise SwitchError(err or "patch still present")


class _RealTimers:
    """Timer state lives in switch1_menu's patch_timers dict, guarded by its lock."""

    def __init__(self, sm):
        self.sm = sm

    def load(self):
        self.sm.load()

    def snapshot(self):
        with self.sm.lock:
            return {k: dict(v) for k, v in self.sm.patch_timers.items()}

    def get(self, key):
        with self.sm.lock:
            v = self.sm.patch_timers.get(key)
            return dict(v) if v else None

    def set(self, key, expires_iso, label):
        with self.sm.lock:
            self.sm.patch_timers[key] = {"expires": expires_iso, "label": label or ""}
            self.sm.save()

    def delete(self, key):
        with self.sm.lock:
            existed = self.sm.patch_timers.pop(key, None) is not None
            if existed:
                self.sm.save()
            return existed

    def start_watcher(self):
        # Your proven expiry loop — owns dl_patch + save for expired patches.
        threading.Thread(target=self.sm.watcher, daemon=True, name="patch-watcher").start()


# --------------------------------------------------------------------------- #
# MOCK backend — offline dev, no hardware
# --------------------------------------------------------------------------- #
class _MockSwitch:
    def __init__(self, mock):
        self.m = mock

    def get_patches(self):
        return self.m.get_patches()

    def get_power(self):
        return self.m.get_power()

    def mk_patch(self, a, b):
        try:
            self.m.mk_patch(a, b)
        except Exception as e:  # noqa: BLE001
            raise SwitchError(str(e))

    def dl_patch(self, a, b):
        self.m.dl_patch(a, b)


class _LocalTimers:
    """Self-contained timer store + watcher, used only in mock mode."""

    def __init__(self, path, switch):
        self.path = path
        self.switch = switch
        self.lock = threading.Lock()
        self.data = {}

    def load(self):
        if not os.path.exists(self.path):
            self.data = {}
            return
        try:
            with open(self.path) as f:
                self.data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            log.error("cannot load %s: %s", self.path, e)
            raise SystemExit(1)
        if not isinstance(self.data, dict):
            log.error("%s is not a JSON object", self.path)
            raise SystemExit(1)

    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=2)
        os.replace(tmp, self.path)

    def snapshot(self):
        with self.lock:
            return {k: dict(v) for k, v in self.data.items()}

    def get(self, key):
        with self.lock:
            v = self.data.get(key)
            return dict(v) if v else None

    def set(self, key, expires_iso, label):
        with self.lock:
            self.data[key] = {"expires": expires_iso, "label": label or ""}
            self._save()

    def delete(self, key):
        with self.lock:
            existed = self.data.pop(key, None) is not None
            if existed:
                self._save()
            return existed

    def _watch(self):
        while True:
            time.sleep(30)
            now = datetime.utcnow()
            with self.lock:
                expired = [k for k, v in self.data.items()
                           if datetime.fromisoformat(v["expires"]) <= now]
            for key in expired:
                a, b = (int(x) for x in key.split("-"))
                try:
                    self.switch.dl_patch(a, b)
                except Exception as e:  # noqa: BLE001
                    log.warning("watcher: dl_patch %s failed: %s", key, e)
                    continue
                with self.lock:
                    self.data.pop(key, None)
                    self._save()
                log.info("watcher: expired patch %s removed", key)

    def start_watcher(self):
        threading.Thread(target=self._watch, daemon=True, name="patch-watcher").start()


# --------------------------------------------------------------------------- #
# Selection + public passthrough
# --------------------------------------------------------------------------- #
_switch = None
_timers = None


def _use_real():
    global _switch, _timers
    import switch1_menu as sm
    _switch = _RealSwitch(sm)
    _timers = _RealTimers(sm)
    log.info("Using REAL backend (switch1_menu.py -> %s:%s)", sm.SWITCH_IP, sm.SWITCH_PORT)


def _use_mock():
    global _switch, _timers
    import mock_switch
    _switch = _MockSwitch(mock_switch)
    _timers = _LocalTimers(os.environ.get("TIMERS_FILE", "patch_timers.json"), _switch)
    log.info("Using MOCK backend (no hardware)")


def _init():
    if _switch is not None:
        return
    if _MODE == "mock":
        _use_mock()
    elif _MODE == "real":
        _use_real()
    else:  # auto
        try:
            _use_real()
        except Exception as e:  # noqa: BLE001
            log.warning("switch1_menu.py unavailable (%s) — falling back to MOCK", e)
            _use_mock()


# switch operations
def get_patches():
    _init(); return _switch.get_patches()


def get_power():
    _init(); return _switch.get_power()


def mk_patch(a, b):
    _init(); return _switch.mk_patch(a, b)


def dl_patch(a, b):
    _init(); return _switch.dl_patch(a, b)


# timer operations
def load_timers():
    _init(); _timers.load()


def timers_snapshot():
    _init(); return _timers.snapshot()


def get_timer(key):
    _init(); return _timers.get(key)


def set_timer(key, expires_iso, label):
    _init(); _timers.set(key, expires_iso, label)


def del_timer(key):
    _init(); return _timers.delete(key)


def start_watcher():
    _init(); _timers.start_watcher()
