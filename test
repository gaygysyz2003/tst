#!/usr/bin/env python3
"""
t5_menu.py -- interactive engineer menu for the 400G-XP-LC TL1 tool.

Run:  python3 t5_menu.py
Needs the engine (t5_configuration.py) in the same directory.

Auto-discovers every 400G-XP-LC card on the chosen node and prints a FULL
INVENTORY (trunk + client ports, pluggable type, service state, what is
provisioned vs available). The engineer then picks a 100G client port and a
build-up / teardown / power-up action -- each verified against the node by the
engine.
"""

import os
import re
import socket

try:
    import t5_configuration as t5      # the engine file on the sandbox
except ImportError:
    import t5_provision as t5          # dev/repo name


# ---- response parsing helpers --------------------------------------------

def _state_of(resp):
    if not resp.ok:
        return "NOT PROVISIONED"
    m = re.findall(r"((?:IS|OOS)-[A-Z]+(?:,[A-Z]+)?)", resp.raw)
    return m[-1] if m else "present"


def _state_in_line(raw, aid):
    """Service state from the line in `raw` that names `aid`."""
    for line in raw.splitlines():
        if aid + ":" in line:
            m = re.findall(r"((?:IS|OOS)-[A-Z]+(?:,[A-Z]+)?)", line)
            return m[-1] if m else "?"
    return "?"


# ---- TL1 plumbing ---------------------------------------------------------

def _open_session(node, uid, pid):
    sock = socket.create_connection((node.ip, node.tl1_port), timeout=20)
    sess = t5.TL1Session(sock)
    ctag = t5.next_ctag()
    sess.send("ACT-USER::{}:{}::{}".format(uid, ctag, pid))
    if not sess.read_response(ctag).ok:
        sock.close()
        raise t5.Tl1Error("login rejected")
    return sock, sess


def _q(sess, cmd):
    ctag = t5.next_ctag()
    sess.send("{}:{}".format(cmd, ctag))
    return sess.read_response(ctag)


# ---- discovery: full inventory of each 400G-XP-LC card --------------------

def discover(node, uid, pid):
    sock, sess = _open_session(node, uid, pid)
    try:
        eqpt = _q(sess, "RTRV-EQPT::ALL")
        clients_all = _q(sess, "RTRV-100GIGE::ALL")
        slots = sorted(set(re.findall(r"SLOT-(\d+)-(\d+):400G-XP-LC", eqpt.raw)),
                       key=lambda t: (int(t[0]), int(t[1])))
        cards = []
        for sh, sl in slots:
            sh, sl = int(sh), int(sl)
            opm = _q(sess, "RTRV-OPMODE::SLOT-{}-{}".format(sh, sl))
            mm = re.search(r"OPMODE=([^,]+),TRUNKOPMODE=([^,]+)", opm.raw) if opm.ok else None
            opmode = "{} (trunks {})".format(mm.group(1), mm.group(2)) if mm else "none"

            clients, trunks = [], []
            for line in eqpt.raw.splitlines():
                m = re.match(r'\s*"(APPM|PPM)-{}-{}-(\d+):'.format(sh, sl), line)
                if not m:
                    continue
                prefix, port = m.group(1), int(m.group(2))
                cn = re.search(r"(?<![A-Z])CARDNAME=([^,]+)", line)  # not ACTUALCARDNAME
                ppm = cn.group(1) if cn else "(empty)"
                sm = re.findall(r"((?:IS|OOS)-[A-Z]+(?:,[A-Z]+)?)", line)
                ppm_state = sm[-1] if sm else "?"
                if prefix == "APPM":                       # client pluggable
                    is100 = ("100G" in ppm) and ("4X10G" not in ppm)
                    fac = "AGGR-{}-{}-{}-1".format(sh, sl, port)
                    if clients_all.ok and (fac + ":") in clients_all.raw:
                        fac_state = _state_in_line(clients_all.raw, fac)
                    else:
                        fac, fac_state = None, None
                    clients.append(dict(port=port, ppm=ppm, ppm_state=ppm_state,
                                        is100g=is100, facility=fac, fac_state=fac_state))
                else:                                      # PPM = trunk pluggable
                    tf = _q(sess, "RTRV-OTU4C2::VFAC-{}-{}-{}-1".format(sh, sl, port))
                    opr = re.search(r"OPR=([^,]+)", tf.raw)
                    trunks.append(dict(port=port, ppm=ppm,
                                       facility="VFAC-{}-{}-{}-1".format(sh, sl, port),
                                       state=_state_of(tf),
                                       opr=opr.group(1) if opr else None))
            clients.sort(key=lambda c: c["port"])
            trunks.sort(key=lambda t: t["port"])
            cards.append(dict(shelf=sh, slot=sl,
                              card_state=_state_in_line(eqpt.raw, "SLOT-{}-{}".format(sh, sl)),
                              opmode=opmode, clients=clients, trunks=trunks))
        _q(sess, "CANC-USER::{}".format(uid))
        return cards
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ---- display + selection --------------------------------------------------

def _show_inventory(node, card):
    print("\n  ============================================================")
    print("  {}  SLOT-{}-{}  400G-XP-LC  [{}]".format(
        node.name, card["shelf"], card["slot"], card["card_state"]))
    print("  opmode: {}".format(card["opmode"]))
    print("  ------------------------------------------------------------")
    print("  TRUNK ports:")
    for t in card["trunks"]:
        opr = "  OPR={}".format(t["opr"]) if t.get("opr") else ""
        print("    {:>2}  {:<6}  {:<14}  {}{}".format(
            t["port"], t["ppm"], t["facility"], t["state"], opr))
    print("  CLIENT ports:")
    for c in card["clients"]:
        if c["facility"]:
            fac, tag = "{} {}".format(c["facility"], c["fac_state"]), "PROVISIONED"
        elif c["is100g"]:
            fac, tag = "-", "available (100G)"
        elif c["ppm"] == "(empty)":
            fac, tag = "-", "empty (no optic)"
        else:
            fac, tag = "-", "other rate"
        ppm = c["ppm"] if len(c["ppm"]) <= 24 else c["ppm"][:24]
        print("    {:>2}  {:<24}  {:<12}  {:<22}  [{}]".format(
            c["port"], ppm, c["ppm_state"], fac, tag))
    print("  ============================================================")


def _pick_client(card):
    """Choose a 100G-capable client port to act on (auto if only one)."""
    opts = [c for c in card["clients"] if c["is100g"]]
    if not opts:
        print("  >> no 100G-capable client ports are populated on this card.")
        return None
    if len(opts) == 1:
        return opts[0]["port"]
    print("\n  100G client ports:")
    for i, c in enumerate(opts, 1):
        print("    {}) port {}  ({})".format(
            i, c["port"], "provisioned" if c["facility"] else "available"))
    sel = input("  pick client port [1]: ").strip() or "1"
    try:
        return opts[int(sel) - 1]["port"]
    except (ValueError, IndexError):
        return opts[0]["port"]


def _confirm_and_run(node, uid, pid, teardown, power_up_only, prompt, destructive=False):
    if destructive:
        if input("  {}  type 'yes' to confirm: ".format(prompt)).strip().lower() != "yes":
            print("  cancelled"); return
    else:
        if input("  {} [y/N]: ".format(prompt)).strip().lower() not in ("y", "yes"):
            print("  cancelled"); return
    ok = t5.provision_node(node, uid, pid, dry_run=False,
                           power_up_only=power_up_only, teardown=teardown)
    print("\n  >>> {}: {}".format(node.name, "SUCCESS (verified)" if ok else "FAILED"))


# ---- main menu loop -------------------------------------------------------

def run_menu(uid, pid):
    print("\n=========================================")
    print(" T5 / 400G-XP-LC Provisioning Menu")
    print("=========================================")
    while True:
        print("\nNodes:")
        for i, n in enumerate(t5.NODES, 1):
            print("  {}) {:8} {}".format(i, n.name or n.ip, n.ip))
        print("  or type any IP (e.g. 10.252.254.80) to target an unlisted node")
        sel = input("Select node number / IP (or 'q' to quit): ").strip()
        if sel.lower() in ("q", "quit", ""):
            print("bye."); return 0
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$", sel):
            ip, _, port = sel.partition(":")
            node = t5.Node(ip=ip, tl1_port=int(port) if port else 3082, name=ip)
            print("  (ad-hoc node {} -- shelf/slot auto-discovered)".format(ip))
        else:
            try:
                node = t5.NODES[int(sel) - 1]
            except (ValueError, IndexError):
                print("  invalid selection"); continue

        print("\nConnecting to {} ({}) -- discovering inventory ...".format(
            node.name or node.ip, node.ip))
        try:
            cards = discover(node, uid, pid)
        except Exception as e:                    # noqa: BLE001
            print("  !! could not reach {} over TL1: {}".format(node.ip, e))
            continue
        if not cards:
            print("  no 400G-XP-LC cards found on this node.")
            continue

        card = cards[0]
        if len(cards) > 1:
            print("\n400G-XP-LC cards found:")
            for i, c in enumerate(cards, 1):
                print("  {}) SLOT-{}-{}".format(i, c["shelf"], c["slot"]))
            cs = input("Select card [1]: ").strip() or "1"
            try:
                card = cards[int(cs) - 1]
            except (ValueError, IndexError):
                card = cards[0]
        node.shelf, node.slot = card["shelf"], card["slot"]

        while True:
            _show_inventory(node, card)
            print("\n  Actions (target: client port {} / trunk port {}):".format(
                node.client_port, node.trunk_port))
            print("    1) Build up      (provision + power up, verified)")
            print("    2) Tear down     (OOS + delete client, verified)")
            print("    3) Power-up only (set freq + bring IS)")
            print("    4) Refresh inventory")
            print("    5) Back to node list")
            print("    6) Quit")
            a = input("  Select action: ").strip().lower()

            if a in ("1", "2", "3"):
                cp = _pick_client(card)
                if cp is None:
                    continue
                node.client_port = cp
                if a == "1":
                    _confirm_and_run(node, uid, pid, False, False,
                                     "Build up {} client {}?".format(node.name, cp))
                elif a == "2":
                    _confirm_and_run(node, uid, pid, True, False,
                                     "TEAR DOWN {} client {} (drops traffic)".format(node.name, cp),
                                     destructive=True)
                else:
                    _confirm_and_run(node, uid, pid, False, True,
                                     "Power-up {} client {}?".format(node.name, cp))
            elif a == "4":
                pass
            elif a == "5":
                break
            elif a in ("6", "q", "quit"):
                return 0
            else:
                print("  invalid choice"); continue

            # re-discover so the inventory reflects what just happened
            try:
                cards = discover(node, uid, pid)
                card = next((c for c in cards
                             if c["shelf"] == node.shelf and c["slot"] == node.slot),
                            cards[0] if cards else card)
            except Exception:                     # noqa: BLE001
                pass


if __name__ == "__main__":
    uid = os.environ.get("TL1_UID", "CISCO15")
    pid = os.environ.get("TL1_PID", "otbu+1")
    try:
        raise SystemExit(run_menu(uid, pid))
    except (KeyboardInterrupt, EOFError):
        print("\nbye.")
        raise SystemExit(0)
