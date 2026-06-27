"""
app.py — Flask web layer for nokia-lab-switch-manager.

Serves the single-file frontend and exposes the /api/* REST contract. All switch
I/O and all timer/expiry state live in switch1_menu.py (reached via core_backend);
this file only validates input, maps results to HTTP, and derives port status.

Run locally (mock switch, no hardware):
    pip install -r requirements.txt
    SWITCH_BACKEND=mock python app.py        # http://localhost:5000

On the lab VM (real switch, auto-detected next to switch1_menu.py):
    python app.py
"""
import logging
import os
import re
from datetime import datetime, timedelta

from flask import Flask, jsonify, request, send_from_directory

import core_backend as core

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
CONFIG_DEFAULTS = {
    "SWITCH_HOST": "10.252.254.8",
    "SWITCH_PORT": "3082",
    "SWITCH_USER": "root",
    "SWITCH_PASS": "root",
    "SERVER_PORT": "5000",
}

NUM_PORTS = 114
EXPIRING_THRESHOLD = 300          # seconds: <= this and > 0 => "expiring"
MAX_LABEL_LEN = 64
MAX_DURATION_MIN = 10080          # 7 days

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("app")


def load_config() -> dict:
    cfg = {}
    for key, default in CONFIG_DEFAULTS.items():
        if key in os.environ:
            cfg[key] = os.environ[key]
        else:
            cfg[key] = default
            log.warning("config %s not set — using default %r", key, default)
    return cfg


# --------------------------------------------------------------------------- #
# Domain helpers
# --------------------------------------------------------------------------- #
def remaining_seconds(entry):
    if not entry:
        return None
    try:
        expires = datetime.fromisoformat(entry["expires"])
    except (KeyError, ValueError):
        return None
    return int((expires - datetime.utcnow()).total_seconds())


def derive_port_status(port, patches, timers):
    if port not in patches:
        return "free"
    entry = timers.get(core.tkey(port, patches[port]))
    if not entry:
        return "patched"
    rem = remaining_seconds(entry)
    if rem is None:
        return "patched"
    if rem <= 0:
        return "expired"
    if rem <= EXPIRING_THRESHOLD:
        return "expiring"
    return "patched"


def build_patches(patches, timers):
    seen, out = set(), []
    for port, partner in patches.items():
        key = core.tkey(port, partner)
        if key in seen:
            continue
        seen.add(key)
        entry = timers.get(key)
        out.append({
            "patch_id": key,
            "port_a": min(port, partner),
            "port_b": max(port, partner),
            "label": (entry or {}).get("label", ""),
            "expires": (entry or {}).get("expires"),
            "remaining_seconds": remaining_seconds(entry),
        })
    out.sort(key=lambda p: p["port_a"])
    return out


def err(message, code):
    return jsonify({"status": "error", "message": message}), code


def switch_error_response(e):
    """Map a switch exception to the right HTTP code."""
    if isinstance(e, core.SwitchTimeout):
        return err(f"Switch query timed out: {e}", 504)
    if isinstance(e, core.SwitchUnreachable):
        return err(f"Switch unreachable: {e}", 503)
    if isinstance(e, core.SwitchError):
        return err(f"Switch refused operation: {e}", 502)
    raise e


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
app = Flask(__name__, static_folder="static", static_url_path="/static")


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/ports")
def api_ports():
    try:
        patches = core.get_patches()
    except (core.SwitchUnreachable, core.SwitchTimeout, core.SwitchError) as e:
        return switch_error_response(e)
    timers = core.timers_snapshot()
    ports = [{"port": p, "status": derive_port_status(p, patches, timers)}
             for p in range(1, NUM_PORTS + 1)]
    return jsonify({"ports": ports, "patches": build_patches(patches, timers)})


@app.post("/api/patches")
def api_create_patch():
    body = request.get_json(silent=True) or {}
    try:
        port_a = int(body["port_a"])
        port_b = int(body["port_b"])
        duration = int(body["duration_minutes"])
    except (KeyError, TypeError, ValueError):
        return err("port_a, port_b and duration_minutes are required integers", 400)

    label = (body.get("label") or "").strip()
    if not (1 <= port_a <= NUM_PORTS) or not (1 <= port_b <= NUM_PORTS):
        return err(f"port numbers must be between 1 and {NUM_PORTS}", 400)
    if port_a == port_b:
        return err("port_a and port_b must differ", 400)
    if not (0 < duration <= MAX_DURATION_MIN):
        return err(f"duration_minutes must be between 1 and {MAX_DURATION_MIN}", 400)
    if len(label) > MAX_LABEL_LEN:
        return err(f"label exceeds {MAX_LABEL_LEN} characters", 400)

    try:
        patches = core.get_patches()
        if port_a in patches or port_b in patches:
            busy = port_a if port_a in patches else port_b
            return err(f"port {busy} is already in an active patch", 409)
        core.mk_patch(port_a, port_b)
    except (core.SwitchUnreachable, core.SwitchTimeout, core.SwitchError) as e:
        return switch_error_response(e)

    key = core.tkey(port_a, port_b)
    expires = (datetime.utcnow() + timedelta(minutes=duration)).isoformat()
    core.set_timer(key, expires, label)

    return jsonify({
        "patch_id": key,
        "port_a": min(port_a, port_b),
        "port_b": max(port_a, port_b),
        "label": label,
        "duration_minutes": duration,
        "expires": expires,
    }), 201


@app.delete("/api/patches/<patch_id>")
def api_delete_patch(patch_id):
    m = re.fullmatch(r"(\d+)-(\d+)", patch_id)
    if not m:
        return err("patch_id must be of the form '<int>-<int>'", 400)
    a, b = int(m.group(1)), int(m.group(2))

    try:
        patches = core.get_patches()
        if patches.get(a) != b:
            return err(f"patch {patch_id} not found", 404)
        label = (core.get_timer(patch_id) or {}).get("label", "")
        core.dl_patch(a, b)
    except (core.SwitchUnreachable, core.SwitchTimeout, core.SwitchError) as e:
        return switch_error_response(e)

    core.del_timer(patch_id)
    return jsonify({"patch_id": patch_id, "port_a": a, "port_b": b, "label": label})


@app.get("/api/power")
def api_power():
    try:
        readings = core.get_power()
    except (core.SwitchUnreachable, core.SwitchTimeout, core.SwitchError) as e:
        return switch_error_response(e)
    out = [{"port": p, "dbm": readings.get(p)} for p in range(1, NUM_PORTS + 1)]
    return jsonify({"readings": out})


def main():
    cfg = load_config()
    core.load_timers()        # loads patch_timers.json via switch1_menu
    core.start_watcher()      # your proven expiry watcher
    port = int(cfg["SERVER_PORT"])
    log.info("starting on 0.0.0.0:%s", port)
    app.run(host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
