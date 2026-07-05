#!/usr/bin/env python3
"""
t5_wizard.py -- state-driven progressive-disclosure provisioning wizard for the
Cisco 400G-XP-LC (T5) over TL1.  SELF-CONTAINED: stdlib only, no other files
needed, runs on Python 3.6+.  Run it on a host that reaches the NEs.

Unlike a fixed build-up / teardown recipe, this walks a *decision tree whose
options are computed from the node's live state*: it shows the card, then each
port, and for the chosen port offers ONLY the actions that are legal right now.
Each action is applied and verified against the node before the next set of
options is shown -- because the commit changes what is possible next.

Design (confirmed on NE-77, 2026-07-03):
  * The NE enumerates NOTHING -- every RTRV returns current state only.  So the
    option CATALOG comes from the card model below (sourced from EPNM) and the
    node supplies only CURRENT STATE + physical-optic presence + verify.
  * State signals: provisioned+up = "...:IS-NR"; disabled = "...:OOS-MA,DSBLD";
    absent = DENY SDBE ("Facility Is Not Provisioned"); no optic = DENY IDNV
    ("PPM Does Not Exist") on ENT.  A 100G client facility can only be created
    where a 100G optic is physically present (APPM line carries a 100G CARDNAME).

Run:  python3 t5_wizard.py
Env:  TL1_UID (default CISCO15), TL1_PID (default otbu+1)
"""

import itertools
import os
import re
import socket
import time


# ===========================================================================
# CONFIG -- nodes
# ===========================================================================

class Node(object):
    def __init__(self, ip, tl1_port=3082, name=""):
        self.ip = ip
        self.tl1_port = tl1_port
        self.name = name


NODES = [
    Node(ip="10.252.254.77", name="NE-77"),
    Node(ip="10.252.254.74", name="NE-74"),
]


# ===========================================================================
# TL1 session (raw socket) -- inlined from the engine
# ===========================================================================

class Tl1Error(Exception):
    pass


class Tl1Response(object):
    def __init__(self, ctag, completion, error_code="", raw=""):
        self.ctag = ctag
        self.completion = completion      # COMPLD | DENY | PRTL | RTRV | ""
        self.error_code = error_code
        self.raw = raw

    @property
    def ok(self):
        return self.completion in ("COMPLD", "PRTL")


_COMPLETION_RE = re.compile(r"^M\s+(\S+)\s+(COMPLD|DENY|PRTL|RTRV)\b", re.MULTILINE)
_ERRCODE_RE = re.compile(r"^\s+([A-Z]{4})\b", re.MULTILINE)


class TL1Session(object):
    def __init__(self, sock, read_timeout=30.0, idle_gap=0.4, logger=None):
        self._s = sock
        self.read_timeout = read_timeout
        self.idle_gap = idle_gap
        self._log = logger or (lambda *_: None)
        self._buf = ""
        self._s.settimeout(0.5)

    def send(self, command):
        if not command.rstrip().endswith(";"):
            command = command.rstrip() + ";"
        self._log(">>> " + command)
        self._s.sendall((command + "\r\n").encode("ascii", "replace"))

    def _recv(self):
        try:
            chunk = self._s.recv(8192)
        except socket.timeout:
            return ""
        except OSError:
            return ""
        return chunk.decode("ascii", "replace") if chunk else ""

    def read_response(self, ctag):
        """Read until the response block for THIS ctag terminates with ';'.

        Matches the exact ctag so the async alarm/event storm (A / ** / *C
        messages, e.g. SIGLOSS/SQUELCHED after bringing a port IS) is skipped
        rather than mistaken for our completion.
        """
        comp_re = re.compile(
            r"^M\s+{}\s+(COMPLD|DENY|PRTL|RTRV)\b".format(re.escape(str(ctag))),
            re.MULTILINE)
        deadline = time.monotonic() + self.read_timeout
        block, self._buf = self._buf, ""

        while time.monotonic() < deadline:
            data = self._recv()
            if data:
                block += data
                if ";" in block and comp_re.search(block):
                    time.sleep(self.idle_gap)
                    block += self._recv()
                    return self._parse(block, ctag, comp_re)
            else:
                if block and ";" in block and comp_re.search(block):
                    return self._parse(block, ctag, comp_re)
                time.sleep(0.05)

        raise Tl1Error("timeout waiting for ctag={}\n{}".format(ctag, block))

    def _parse(self, block, ctag, comp_re):
        self._log(block.strip())
        m = comp_re.search(block) or _COMPLETION_RE.search(block)
        if not m:
            return Tl1Response(ctag=ctag, completion="", raw=block)
        completion = m.group(m.lastindex)
        err = ""
        if completion == "DENY":
            em = _ERRCODE_RE.search(block[m.end():])
            err = em.group(1) if em else ""
        return Tl1Response(ctag=ctag, completion=completion,
                           error_code=err, raw=block)


_ctag = itertools.count(1)


def next_ctag():
    return str(next(_ctag))


CARD_TYPE = "400G-XP-LC"

# --- card model (from EPNM; the NE does not enumerate these) -------------------
# For MXP with trunks 11 & 12 at M-200G, the four OPM-100G slices S1..S4 map to
# client ports 7,8,9,10 in order.  This mapping is a card convention (EPNM
# "Card Operating Modes": 1:OPM-100G(7) 2:OPM-100G(8) 3:OPM-100G(9) 4:OPM-100G(10)).
SLICE_TO_CLIENT = {1: 7, 2: 8, 3: 9, 4: 10}

_STATE_RE = re.compile(r"((?:IS|OOS)-[A-Z]+(?:,[A-Z]+)?)")


# ===========================================================================
# TL1 helpers
# ===========================================================================

def _run(sess, template):
    """Send a command template ('{c}' marks the ctag slot) and return response."""
    ctag = next_ctag()
    sess.send(template.replace("{c}", ctag))
    return sess.read_response(ctag)


def _open(node, uid, pid):
    sock = socket.create_connection((node.ip, node.tl1_port), timeout=20)
    sess = TL1Session(sock)
    if not _run(sess, "ACT-USER::{}:{{c}}::{}".format(uid, pid)).ok:
        sock.close()
        raise Tl1Error("login rejected")
    return sock, sess


def _state_of(resp):
    """Service state (IS-NR / OOS-MA,DSBLD / ...) from an RTRV, or None if absent."""
    if not resp.ok:
        return None
    m = _STATE_RE.findall(resp.raw)
    return m[-1] if m else "present"


# ===========================================================================
# Live state model
# ===========================================================================

class Port(object):
    def __init__(self, port, kind, optic=None, facility=None,
                 provisioned=False, state=None, freq=None):
        self.port = port
        self.kind = kind              # 'client' | 'trunk'
        self.optic = optic            # optic CARDNAME (physical pluggable), None if absent
        self.facility = facility      # facility AID if the port exists in the model
        self.provisioned = provisioned    # facility actually provisioned on the NE
        self.state = state            # service state string, or None if not provisioned
        self.freq = freq              # trunk only


class Card(object):
    def __init__(self, shelf, slot, opmode="", trunkopmode="", clientsets="", ports=None):
        self.shelf = shelf
        self.slot = slot
        self.opmode = opmode          # e.g. "MXP"
        self.trunkopmode = trunkopmode    # e.g. "11/M-200G&12/M-200G"
        self.clientsets = clientsets
        self.ports = ports if ports is not None else []
        self.client_trunk = {}        # client port -> trunk port it rides on


def _optic_of(eqpt_raw, aid):
    """CARDNAME (physical optic) on the APPM/PPM line for `aid`, else None."""
    for line in eqpt_raw.splitlines():
        if aid + ":" in line:
            m = re.search(r"(?<![A-Z])CARDNAME=([^,]+)", line)  # not ACTUALCARDNAME
            return m.group(1) if m else None
    return None


def discover(node, uid, pid):
    """Log in and build a live model of every 400G-XP-LC card on the node."""
    sock, sess = _open(node, uid, pid)
    try:
        eqpt = _run(sess, "RTRV-EQPT::ALL:{c}")
        clients_all = _run(sess, "RTRV-100GIGE::ALL:{c}")
        slots = sorted(
            set(re.findall(r"SLOT-(\d+)-(\d+):" + re.escape(CARD_TYPE), eqpt.raw)),
            key=lambda t: (int(t[0]), int(t[1])))

        cards = []
        for sh, sl in slots:
            sh, sl = int(sh), int(sl)
            opm = _run(sess, "RTRV-OPMODE::SLOT-{}-{}:{{c}}".format(sh, sl))
            mode = re.search(r"OPMODE=([^,]+)", opm.raw)
            top = re.search(r"TRUNKOPMODE=([^,]+)", opm.raw)
            cset = re.search(r"CLIENTSETS=([^,]+)", opm.raw)
            card = Card(shelf=sh, slot=sl,
                        opmode=mode.group(1) if mode else "",
                        trunkopmode=top.group(1) if top else "",
                        clientsets=cset.group(1) if cset else "")

            # map each client slice to the trunk it rides on, from CLIENTSETS
            # (e.g. 11/S1/OPM-100G&...&12/S3/OPM-100G -> {7:11, 8:11, 9:12, 10:12})
            for tk, sn in re.findall(r"(\d+)/S(\d+)/", card.clientsets):
                cp = SLICE_TO_CLIENT.get(int(sn))
                if cp:
                    card.client_trunk[cp] = int(tk)

            # trunk ports come straight from TRUNKOPMODE (e.g. 11/M-200G&12/M-200G)
            trunk_ports = [int(p) for p in re.findall(r"(\d+)/", card.trunkopmode)]
            for p in sorted(set(trunk_ports)):
                aid = "VFAC-{}-{}-{}-1".format(sh, sl, p)
                fac = _run(sess, "RTRV-OTU4C2::{}:{{c}}".format(aid))
                freq = re.search(r"FREQ=([^,]+)", fac.raw)
                card.ports.append(Port(
                    port=p, kind="trunk",
                    optic=_optic_of(eqpt.raw, "PPM-{}-{}-{}".format(sh, sl, p)),
                    facility=aid, provisioned=fac.ok, state=_state_of(fac),
                    freq=freq.group(1) if freq else None))

            # client ports = the OPM-100G slices, mapped to physical ports
            n_slices = len(re.findall(r"/S\d+/", card.clientsets)) or len(SLICE_TO_CLIENT)
            client_ports = [SLICE_TO_CLIENT[i] for i in range(1, n_slices + 1)
                            if i in SLICE_TO_CLIENT]
            for p in client_ports:
                aid = "AGGR-{}-{}-{}-1".format(sh, sl, p)
                provisioned = clients_all.ok and (aid + ":") in clients_all.raw
                state = None
                if provisioned:
                    for line in clients_all.raw.splitlines():
                        if aid + ":" in line:
                            mm = _STATE_RE.findall(line)
                            state = mm[-1] if mm else "present"
                            break
                card.ports.append(Port(
                    port=p, kind="client",
                    optic=_optic_of(eqpt.raw, "APPM-{}-{}-{}".format(sh, sl, p)),
                    facility=aid, provisioned=provisioned, state=state))
            cards.append(card)

        _run(sess, "CANC-USER::{}:{{c}}".format(uid))
        return cards
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ===========================================================================
# Decision core: which actions are legal for a port RIGHT NOW
# ===========================================================================

def _is_up(state):
    return bool(state) and state.startswith("IS")


def available_actions(port):
    """Return [(key, label, destructive)] legal for this port given live state.

    This is the heart of the progressive wizard: options are COMPUTED from the
    port's current state, not hardcoded.  After any action we re-discover, so the
    next call reflects the commit.
    """
    if not port.optic and port.kind == "client":
        return []  # no physical optic -> ENT would DENY IDNV; nothing to offer
    acts = []
    if port.kind == "client":
        if not port.provisioned:
            acts.append(("build", "Build up (create 100GIGE + power up)", False))
        elif _is_up(port.state):
            acts.append(("down", "Power down (OOS)", True))
            acts.append(("teardown", "Tear down (OOS + delete facility)", True))
        else:  # provisioned but OOS
            acts.append(("up", "Power up (bring IS)", False))
            acts.append(("teardown", "Tear down (delete facility)", True))
    else:  # trunk
        if _is_up(port.state):
            acts.append(("down", "Power down (OOS)", True))
        else:
            acts.append(("setfreq", "Set wavelength / frequency", False))
            acts.append(("up", "Power up (bring IS)", False))
    return acts


# ===========================================================================
# Apply handlers -- only TL1 syntax proven live on NE-77
# ===========================================================================

def _apply_client(sess, port, key, freq=None):
    aid = port.facility
    if key == "build":
        if not _run(sess, "ENT-100GIGE::{}:{{c}}:::NUMOFLANES=4".format(aid)).ok:
            return False
        _run(sess, "ED-100GIGE::{}:{{c}}::::IS".format(aid))     # tolerate SAIN
        return _verify(sess, "RTRV-100GIGE::{}:{{c}}".format(aid), "IS")
    if key == "up":
        _run(sess, "ED-100GIGE::{}:{{c}}::::IS".format(aid))
        return _verify(sess, "RTRV-100GIGE::{}:{{c}}".format(aid), "IS")
    if key == "down":
        _run(sess, "ED-100GIGE::{}:{{c}}:::CMDMDE=FRCD:OOS,DSBLD".format(aid))
        return _verify(sess, "RTRV-100GIGE::{}:{{c}}".format(aid), "OOS")
    if key == "teardown":
        _run(sess, "ED-100GIGE::{}:{{c}}:::CMDMDE=FRCD:OOS,DSBLD".format(aid))
        _run(sess, "DLT-100GIGE::{}:{{c}}".format(aid))
        return not _run(sess, "RTRV-100GIGE::{}:{{c}}".format(aid)).ok  # expect SDBE
    return False


def _apply_trunk(sess, port, key, freq=None):
    aid = port.facility
    if key == "setfreq":
        _run(sess, "ED-OTU4C2::{}:{{c}}:::FREQ={}".format(aid, freq))  # tolerate SROF
        return True
    if key == "up":
        _run(sess, "ED-OTU4C2::{}:{{c}}::::IS".format(aid))
        return _verify(sess, "RTRV-OTU4C2::{}:{{c}}".format(aid), "IS")
    if key == "down":
        _run(sess, "ED-OTU4C2::{}:{{c}}:::CMDMDE=FRCD:OOS,DSBLD".format(aid))
        return _verify(sess, "RTRV-OTU4C2::{}:{{c}}".format(aid), "OOS")
    return False


def _verify(sess, rtrv_template, want):
    resp = _run(sess, rtrv_template)
    return resp.ok and want in resp.raw


# ===========================================================================
# Guided flow: walk the engineer through building one client service, applying
# and verifying each step, skipping whatever live state shows is already done.
# ===========================================================================

def _guided_run(sess, template, verify_template=None, want=None, tolerate=()):
    """Apply one command, tolerate expected DENYs, then optionally verify."""
    resp = _run(sess, template)
    if not resp.ok and resp.error_code not in tolerate:
        return False, "DENIED " + (resp.error_code or "?")
    if verify_template:
        v = _run(sess, verify_template)
        if not (v.ok and (want in v.raw if want else True)):
            return False, "verify failed"
    return True, "ok"


def guided_build(node, uid, pid, card):
    clients = [p for p in card.ports if p.kind == "client" and p.optic]
    if not clients:
        print("  no client ports have an optic to build on.")
        return

    print("\n  Guided: provision a client service")
    for i, p in enumerate(clients, 1):
        tk = card.client_trunk.get(p.port, "?")
        print("    {}) client port {} (rides trunk {})  --  {}".format(
            i, p.port, tk, p.state or "not provisioned"))
    sel = input("  Which client port? (or 'q'): ").strip().lower()
    if sel in ("q", "quit", ""):
        return
    try:
        client = clients[int(sel) - 1]
    except (ValueError, IndexError):
        print("  invalid selection")
        return

    tport = card.client_trunk.get(client.port)
    trunk = next((p for p in card.ports
                  if p.kind == "trunk" and p.port == tport), None)

    # --- build the plan from live state: skip anything already done ---
    plan = []          # list of (step_key, human description)
    freq = None
    if trunk and not _is_up(trunk.state):
        cur = trunk.freq or "(unset)"
        f = input("  Trunk {} is {}. Frequency in nm [{}], Enter=keep: ".format(
            trunk.port, trunk.state or "?", cur)).strip()
        freq = f or trunk.freq
        if freq:
            plan.append(("trunk_freq",
                         "set trunk {} FREQ={}".format(trunk.port, freq)))
        plan.append(("trunk_up", "bring trunk {} in service".format(trunk.port)))
    elif trunk:
        print("  Step: trunk {} already in service (FREQ={}) -- skipping.".format(
            trunk.port, trunk.freq))
    if not client.provisioned:
        plan.append(("client_create",
                     "create 100GIGE facility on client {}".format(client.port)))
    if not _is_up(client.state):
        plan.append(("client_up",
                     "bring client {} in service".format(client.port)))

    if not plan:
        print("  client {} is already fully in service -- nothing to do.".format(
            client.port))
        return

    print("\n  Plan (each step is applied AND verified before the next):")
    for i, (k, desc) in enumerate(plan, 1):
        print("    {}. {}".format(i, desc))
    if input("  proceed? [y/N]: ").strip().lower() not in ("y", "yes"):
        print("  cancelled")
        return

    caid = client.facility
    taid = trunk.facility if trunk else None
    sock, sess = _open(node, uid, pid)
    try:
        done = True
        for k, desc in plan:
            print("  -> {}".format(desc))
            if k == "trunk_freq":
                ok, msg = _guided_run(
                    sess, "ED-OTU4C2::{}:{{c}}:::FREQ={}".format(taid, freq),
                    tolerate=("SROF",))
            elif k == "trunk_up":
                ok, msg = _guided_run(
                    sess, "ED-OTU4C2::{}:{{c}}::::IS".format(taid),
                    "RTRV-OTU4C2::{}:{{c}}".format(taid), "IS", tolerate=("SAIN",))
            elif k == "client_create":
                ok, msg = _guided_run(
                    sess, "ENT-100GIGE::{}:{{c}}:::NUMOFLANES=4".format(caid),
                    "RTRV-100GIGE::{}:{{c}}".format(caid))
            elif k == "client_up":
                ok, msg = _guided_run(
                    sess, "ED-100GIGE::{}:{{c}}::::IS".format(caid),
                    "RTRV-100GIGE::{}:{{c}}".format(caid), "IS", tolerate=("SAIN",))
            else:
                ok, msg = False, "unknown step"
            print("     {}".format("OK (verified)" if ok else "FAILED: " + msg))
            if not ok:
                print("  !! stopping guided build here; earlier steps stand.")
                done = False
                break
        if done:
            print("\n  >>> client {} service provisioned & verified.".format(
                client.port))
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ===========================================================================
# Display + interactive loop
# ===========================================================================

def _show_card(card):
    print("\n  ============================================================")
    print("  SLOT-{}-{}  {}   opmode: {} (trunks {})".format(
        card.shelf, card.slot, CARD_TYPE, card.opmode, card.trunkopmode))
    print("  ------------------------------------------------------------")
    for i, p in enumerate(card.ports, 1):
        if p.kind == "trunk":
            extra = "  FREQ={}".format(p.freq) if p.freq else ""
            optic = p.optic or "(no optic)"
            print("   {:>2}) TRUNK  port {:<2}  {:<8}  {:<14}  {}{}".format(
                i, p.port, optic, p.facility, p.state or "not provisioned", extra))
        else:
            optic = p.optic or "(no optic)"
            if not p.optic:
                tag = "-- insert 100G optic --"
            elif not p.provisioned:
                tag = "available (build up)"
            else:
                tag = p.state
            tk = card.client_trunk.get(p.port)
            trunk_note = "  (trunk {})".format(tk) if tk else ""
            print("   {:>2}) CLIENT port {:<2}  {:<26}  {:<12}  [{}]{}".format(
                i, p.port, optic, p.facility, tag, trunk_note))
    print("  ============================================================")


def _act_on_port(node, uid, pid, card, port):
    acts = available_actions(port)
    if not acts:
        print("  >> no actions available for this port (no optic present).")
        return
    print("\n  Port {} {} -- state: {}".format(
        port.kind, port.port, port.state or "not provisioned"))
    for i, (key, label, destr) in enumerate(acts, 1):
        print("    {}) {}{}".format(i, label, "   [destructive]" if destr else ""))
    sel = input("  Select action (or 'q'): ").strip().lower()
    if sel in ("q", "quit", ""):
        return
    try:
        key, label, destr = acts[int(sel) - 1]
    except (ValueError, IndexError):
        print("  invalid selection")
        return

    freq = None
    if key == "setfreq":
        freq = input("  frequency (nm, e.g. 1530.33): ").strip()
        if not freq:
            print("  cancelled")
            return

    if destr:
        if input("  '{}' -- type 'yes' to confirm: ".format(label)).strip().lower() != "yes":
            print("  cancelled")
            return
    else:
        if input("  {} [y/N]: ".format(label)).strip().lower() not in ("y", "yes"):
            print("  cancelled")
            return

    sock, sess = _open(node, uid, pid)
    try:
        handler = _apply_client if port.kind == "client" else _apply_trunk
        ok = handler(sess, port, key, freq)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    print("  >>> {}: {}".format(label, "OK (verified)" if ok else "FAILED / not verified"))


def run(uid, pid):
    print("\n=========================================")
    print(" T5 / 400G-XP-LC  state-driven wizard")
    print("=========================================")
    while True:
        print("\nNodes:")
        for i, n in enumerate(NODES, 1):
            print("  {}) {:8} {}".format(i, n.name or n.ip, n.ip))
        sel = input("Select node (number, IP, or 'q'): ").strip()
        if sel.lower() in ("q", "quit", ""):
            print("bye.")
            return 0
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", sel):
            node = Node(ip=sel, name=sel)
        else:
            try:
                node = NODES[int(sel) - 1]
            except (ValueError, IndexError):
                print("  invalid selection")
                continue

        print("\nConnecting to {} -- discovering ...".format(node.name or node.ip))
        try:
            cards = discover(node, uid, pid)
        except Exception as e:                        # noqa: BLE001
            print("  !! could not reach {}: {}".format(node.ip, e))
            continue
        if not cards:
            print("  no {} cards found.".format(CARD_TYPE))
            continue

        card = cards[0]
        if len(cards) > 1:
            for i, c in enumerate(cards, 1):
                print("  {}) SLOT-{}-{}".format(i, c.shelf, c.slot))
            cs = input("Select card [1]: ").strip() or "1"
            try:
                card = cards[int(cs) - 1]
            except (ValueError, IndexError):
                card = cards[0]

        while True:
            _show_card(card)
            sel = input("\n  Pick a port number, 'g' guided build, 'r' refresh, 'b' back: ").strip().lower()
            if sel in ("b", "back"):
                break
            if sel in ("r", "refresh", ""):
                pass
            elif sel in ("g", "guided"):
                guided_build(node, uid, pid, card)
            else:
                try:
                    pi = int(sel)
                    if 1 <= pi <= len(card.ports):
                        _act_on_port(node, uid, pid, card, card.ports[pi - 1])
                    else:
                        print("  invalid selection")
                        continue
                except ValueError:
                    print("  invalid selection")
                    continue
            # re-discover so the next menu reflects what just changed
            try:
                cards = discover(node, uid, pid)
                card = next((c for c in cards
                             if c.shelf == card.shelf and c.slot == card.slot), card)
            except Exception:                         # noqa: BLE001
                pass


if __name__ == "__main__":
    uid = os.environ.get("TL1_UID", "CISCO15")
    pid = os.environ.get("TL1_PID", "otbu+1")
    try:
        raise SystemExit(run(uid, pid))
    except (KeyboardInterrupt, EOFError):
        print("\nbye.")
        raise SystemExit(0)
