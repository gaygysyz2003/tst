#!/usr/bin/env python3
"""
t5_provision.py  --  Provision Cisco 400G-XP-LC (T5) over TL1.

SANDBOX EDITION: run this DIRECTLY ON the lab box (10.252.254.207), which
already reaches the NEs. It connects straight to <NE>:3082 over a raw socket --
no SSH, no paramiko, stdlib only (Python 3.6+).

Modes:
  (default)       full provision (build up) + verify in-service via RTRV
  --power-up-only just set freq + bring ports IS
  --teardown      break down (force ports OOS + delete client) + verify via RTRV
Each run ends by reading state back from the node (VERIFY PASS/FAIL); a node
reports COMPLETE & VERIFIED only if the node's own RTRV confirms the result.

Credentials come from env vars (fallback to the lab defaults below):
  TL1_UID  (default CISCO15)
  TL1_PID  (default otbu+1)

Usage:
  python3 t5_provision.py --dry-run --only NE-77            # preview, no connect
  python3 t5_provision.py --only NE-77 --power-up-only      # safe: only freq+IS
  python3 t5_provision.py --only NE-77                      # build up + verify
  python3 t5_provision.py --only NE-77 --teardown           # break down + verify
  python3 t5_provision.py                                   # all nodes
"""

from __future__ import annotations

import argparse
import itertools
import os
import re
import socket
import sys
import time
from dataclasses import dataclass


# ===========================================================================
# CONFIG
# ===========================================================================

@dataclass
class Node:
    ip: str
    tl1_port: int = 3082
    # AID grammar confirmed on NE-77: <shelf>-<slot>-<port>[-<sub>]
    shelf: int = 2          # 400G-XP-LC is in SHELF 2
    slot: int = 6           # ... SLOT 6  (SLOT-2-6)
    trunk_port: int = 11    # trunk port 11 -> power up
    client_port: int = 7    # client port 7 -> power up
    freq_nm: str = "1530.33"
    # PPMs to provision on a blank card. Scoped to the ports in use; on NE-77
    # these already exist so they get skipped. For a blank card, list every
    # client/trunk port the opmode references AND ensure the pluggable is
    # physically present, else ENT-EQPT will DENY.  # CONFIRM
    client_ppms: tuple = (7,)
    trunk_ppms: tuple = (11,)
    # Proven-valid operating-mode string read back from NE-77 (RTRV-OPMODE).
    opmode: str = ("OPMODE=MXP,TRUNKOPMODE=11/M-200G&12/M-200G,"
                   "CLIENTSETS=11/S1/OPM-100G&11/S2/OPM-100G&"
                   "12/S3/OPM-100G&12/S4/OPM-100G")
    name: str = ""


NODES = [
    # NE-77 confirmed: 400G-XP-LC at SLOT-2-6, trunk VFAC-2-6-11-1 (IS-NR,
    # FREQ=1530.33), client AGGR-2-6-7-1.
    Node(ip="10.252.254.77", shelf=2, slot=6, name="NE-77"),
    # NE-74: card location NOT yet confirmed -- run RTRV-EQPT::ALL there and
    # update shelf/slot before a live run.  # CONFIRM
    Node(ip="10.252.254.74", shelf=2, slot=6, name="NE-74"),
]


# ===========================================================================
# TL1 session (raw socket)
# ===========================================================================

class Tl1Error(Exception):
    pass


@dataclass
class Tl1Response:
    ctag: str
    completion: str          # COMPLD | DENY | PRTL | RTRV | ""
    error_code: str = ""
    raw: str = ""

    @property
    def ok(self) -> bool:
        return self.completion in ("COMPLD", "PRTL")


_COMPLETION_RE = re.compile(r"^M\s+(\S+)\s+(COMPLD|DENY|PRTL|RTRV)\b", re.MULTILINE)
_ERRCODE_RE = re.compile(r"^\s+([A-Z]{4})\b", re.MULTILINE)


class TL1Session:
    def __init__(self, sock, read_timeout=30.0, idle_gap=0.4, logger=None):
        self._s = sock
        self.read_timeout = read_timeout
        self.idle_gap = idle_gap
        self._log = logger or (lambda *_: None)
        self._buf = ""
        self._s.settimeout(0.5)

    def send(self, command: str) -> None:
        if not command.rstrip().endswith(";"):
            command = command.rstrip() + ";"
        self._log(">>> " + command)
        self._s.sendall((command + "\r\n").encode("ascii", "replace"))

    def _recv(self) -> str:
        try:
            chunk = self._s.recv(8192)
        except socket.timeout:
            return ""
        except OSError:
            return ""
        return chunk.decode("ascii", "replace") if chunk else ""

    def read_response(self, ctag: str) -> Tl1Response:
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

    def _parse(self, block: str, ctag: str, comp_re) -> Tl1Response:
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


# ===========================================================================
# Command builder
# ===========================================================================

@dataclass
class Step:
    desc: str
    action: str          # ENT/ED command, '{c}' marks the ctag slot
    check: str = ""      # optional RTRV (see `delete` for the skip direction)
    tolerate: tuple = () # DENY codes treated as success (e.g. SAIN already-IS)
    config: bool = False # a config change (not a create or a power-up);
                         # excluded from --power-up-only runs
    delete: bool = False # a teardown step. With a check, skip when the entity
                         # is ABSENT (create steps skip when PRESENT).
    verify_contains: str = ""   # verification step: RTRV must COMPLD and the
                                # response must contain this substring (state).
    verify_absent: bool = False # verification step: RTRV must DENY (entity gone)


def build_sequence(node: Node, uid: str, pid: str):
    s, sl = node.shelf, node.slot
    card = "SLOT-{}-{}".format(s, sl)
    # CONFIRMED on NE-77: trunk VFAC-2-6-11-1, client AGGR-2-6-7-1
    trunk_aid = "VFAC-{}-{}-{}-1".format(s, sl, node.trunk_port)
    client_aid = "AGGR-{}-{}-{}-1".format(s, sl, node.client_port)

    steps = [Step("login", "ACT-USER::{}:{{c}}::{}".format(uid, pid))]

    steps.append(Step("equip card 400G-XP-LC",
                      "ENT-EQPT::{}:{{c}}::400G-XP-LC".format(card),
                      check="RTRV-EQPT::{}:{{c}}".format(card)))
    for p in node.client_ppms:
        aid = "APPM-{}-{}-{}".format(s, sl, p)
        steps.append(Step("equip client PPM port {}".format(p),
                          "ENT-EQPT::{}:{{c}}::PPM-1".format(aid),
                          check="RTRV-EQPT::{}:{{c}}".format(aid)))
    for p in node.trunk_ppms:
        aid = "PPM-{}-{}-{}".format(s, sl, p)
        steps.append(Step("equip trunk PPM port {}".format(p),
                          "ENT-EQPT::{}:{{c}}::PPM-1".format(aid),
                          check="RTRV-EQPT::{}:{{c}}".format(aid)))

    steps.append(Step("set operating mode (MXP)",
                      "ENT-OPMODE::{}:{{c}}:::{}".format(card, node.opmode),
                      check="RTRV-OPMODE::{}:{{c}}".format(card)))

    # Frequency is a config change: only meaningful while the trunk is OOS
    # (blank card). On an already-IS/connected port the NE returns SROF
    # ("cannot change config with port having connection") -- tolerated, since
    # the freq is already what we want. Excluded entirely from --power-up-only.
    steps.append(Step("set trunk wavelength",
                      "ED-OTU4C2::{}:{{c}}:::FREQ={}".format(trunk_aid, node.freq_nm),
                      tolerate=("SROF",), config=True))
    steps.append(Step("trunk port IS (power up)",
                      "ED-OTU4C2::{}:{{c}}::::IS".format(trunk_aid),
                      tolerate=("SAIN",)))

    steps.append(Step("provision client 100GIGE",
                      "ENT-100GIGE::{}:{{c}}:::NUMOFLANES=4".format(client_aid),
                      check="RTRV-100GIGE::{}:{{c}}".format(client_aid)))
    steps.append(Step("client port IS (power up)",
                      "ED-100GIGE::{}:{{c}}::::IS".format(client_aid),
                      tolerate=("SAIN",)))

    # --- confirm the build by reading state back from the node ---
    steps.append(Step("VERIFY trunk in-service",
                      "RTRV-OTU4C2::{}:{{c}}".format(trunk_aid),
                      verify_contains="IS-"))
    steps.append(Step("VERIFY client in-service",
                      "RTRV-100GIGE::{}:{{c}}".format(client_aid),
                      verify_contains="IS-"))

    steps.append(Step("logout", "CANC-USER::{}:{{c}}".format(uid)))
    return steps


def build_teardown(node: Node, uid: str, pid: str):
    """Reverse of provisioning (config-only): force the populated facilities
    OOS, then delete the client facility. Leaves the card and PPMs equipped.

    Each OOS step tolerates SAIN (already OOS) and IIAC (facility doesn't
    exist), so the teardown is safe to re-run. CMDMDE=FRCD forces the OOS on a
    connected/in-service port.
    """
    s, sl = node.shelf, node.slot
    card = "SLOT-{}-{}".format(s, sl)
    trunk_aid = "VFAC-{}-{}-{}-1".format(s, sl, node.trunk_port)
    client_aid = "AGGR-{}-{}-{}-1".format(s, sl, node.client_port)

    steps = [Step("login", "ACT-USER::{}:{{c}}::{}".format(uid, pid))]

    # take the populated client OOS (only AGGR-2-6-7-1 exists on NE-77)
    steps.append(Step("client port OOS (force)",
                      "ED-100GIGE::{}:{{c}}:::CMDMDE=FRCD:OOS,DSBLD".format(client_aid),
                      tolerate=("SAIN", "IIAC")))
    # take both opmode trunks OOS (11 in use; 12 declared by the opmode)
    steps.append(Step("trunk port 11 OOS (force)",
                      "ED-OTU4C2::{}:{{c}}:::CMDMDE=FRCD:OOS,DSBLD".format(trunk_aid),
                      tolerate=("SAIN", "IIAC")))
    trunk2 = "VFAC-{}-{}-12-1".format(s, sl)
    steps.append(Step("trunk port 12 OOS (force)",
                      "ED-OTU4C2::{}:{{c}}:::CMDMDE=FRCD:OOS,DSBLD".format(trunk2),
                      tolerate=("SAIN", "IIAC")))

    # delete the populated client facility (confirmed on NE-77: DLT-100GIGE
    # returns COMPLD). Skipped if already gone (delete + check).
    steps.append(Step("delete client 100GIGE",
                      "DLT-100GIGE::{}:{{c}}".format(client_aid),
                      check="RTRV-100GIGE::{}:{{c}}".format(client_aid),
                      delete=True))

    # NOTE: full opmode removal (DLT-OPMODE::SLOT:::OPMODE=MXP) is intentionally
    # NOT performed here. On NE-77 it is blocked by SNVS ("Cross Connect
    # Exists") -- the trunk's optical circuit (OCHNC) -- whose deletion is a
    # network-level action. Teardown stops at "ports OOS + client deleted".
    # To go further, delete the trunk's optical circuit first, then:
    #   DLT-OPMODE::SLOT-<s>-<sl>:<ctag>:::OPMODE=MXP;

    # --- confirm the teardown by reading state back from the node ---
    steps.append(Step("VERIFY trunk OOS",
                      "RTRV-OTU4C2::{}:{{c}}".format(trunk_aid),
                      verify_contains="OOS"))
    steps.append(Step("VERIFY client deleted",
                      "RTRV-100GIGE::{}:{{c}}".format(client_aid),
                      verify_absent=True))

    steps.append(Step("logout", "CANC-USER::{}:{{c}}".format(uid)))
    return steps


# ===========================================================================
# Runner
# ===========================================================================

_ctag = itertools.count(1)


def next_ctag() -> str:
    return str(next(_ctag))


def log(msg: str) -> None:
    print(msg, flush=True)


def provision_node(node, uid, pid, dry_run, power_up_only=False,
                   teardown=False) -> bool:
    label = node.name or node.ip
    mode_tag = ("  [TEARDOWN]" if teardown
                else "  [POWER-UP ONLY]" if power_up_only else "")
    log("\n=== {} ({}:{}){} ===".format(label, node.ip, node.tl1_port, mode_tag))
    if teardown:
        steps = build_teardown(node, uid, pid)
    else:
        steps = build_sequence(node, uid, pid)
        if power_up_only:
            # keep only login, the IS power-ups, verify, and logout
            steps = [st for st in steps if not st.check and not st.config]

    if dry_run:
        n = itertools.count(1)
        for st in steps:
            if st.check:
                hint = "skip if absent" if st.delete else "skip if COMPLD"
                log("  [{:>3}] {:26} CHECK: {};  ({})".format(
                    next(n), st.desc, st.check.replace("{c}", "_"), hint))
            if st.verify_contains or st.verify_absent:
                extra = "   expect={}".format(
                    "absent" if st.verify_absent else st.verify_contains)
            elif st.tolerate:
                extra = "   tolerate={}".format(",".join(st.tolerate))
            else:
                extra = ""
            log("  [{:>3}] {:26} {};{}".format(
                next(n), st.desc, st.action.replace("{c}", "_"), extra))
        return True

    sock = None
    try:
        log("  connect {}:{}".format(node.ip, node.tl1_port))
        sock = socket.create_connection((node.ip, node.tl1_port), timeout=20)
        sess = TL1Session(sock, logger=lambda m: log("    " + m))

        verify_failed = False
        for st in steps:
            log("  -> " + st.desc)

            # verification step: RTRV and assert the resulting state
            if st.verify_contains or st.verify_absent:
                ctag = next_ctag()
                sess.send(st.action.replace("{c}", ctag))
                resp = sess.read_response(ctag)
                if st.verify_absent:
                    passed, want = (not resp.ok), "absent (DENY)"
                else:
                    passed, want = (resp.ok and st.verify_contains in resp.raw), st.verify_contains
                if passed:
                    log("     VERIFY PASS (state = {})".format(want))
                else:
                    got = resp.error_code or resp.completion or "?"
                    log("     !! VERIFY FAIL (expected {}, got {})".format(want, got))
                    verify_failed = True
                continue

            if st.check:
                ctag = next_ctag()
                sess.send(st.check.replace("{c}", ctag))
                exists = sess.read_response(ctag).ok
                if st.delete and not exists:
                    log("     not present -> skip")
                    continue
                if not st.delete and exists:
                    log("     already present -> skip")
                    continue
            ctag = next_ctag()
            sess.send(st.action.replace("{c}", ctag))
            resp = sess.read_response(ctag)
            if not resp.ok:
                if resp.error_code in st.tolerate:
                    log("     tolerated ({})".format(resp.error_code))
                    continue
                raise Tl1Error("DENIED: {} (code={})\n       resp: {}".format(
                    st.desc, resp.error_code or "?", resp.raw.strip()))
            log("     OK (COMPLD)")

        if verify_failed:
            log("  !! {}: COMPLETE but VERIFICATION FAILED".format(label))
            return False
        log("  === {}: COMPLETE & VERIFIED ===".format(label))
        return True

    except Tl1Error as e:
        log("  !! {}: TL1 failure -> {}".format(label, e))
        return False
    except OSError as e:
        log("  !! {}: connection error -> {}".format(label, e))
        return False
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
        log("  disconnected from {}".format(label))


def main() -> int:
    ap = argparse.ArgumentParser(description="Provision 400G-XP-LC over TL1 (sandbox edition).")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the TL1 commands without connecting")
    ap.add_argument("--only", help="run only the node whose ip/name matches this")
    ap.add_argument("--power-up-only", action="store_true",
                    help="skip all ENT (create) steps; only set freq + bring IS")
    ap.add_argument("--teardown", action="store_true",
                    help="UNPROVISION: force ports OOS + delete client "
                         "(keeps card+PPMs). Destructive -- drops traffic.")
    args = ap.parse_args()

    uid = os.environ.get("TL1_UID", "CISCO15")
    pid = os.environ.get("TL1_PID", "otbu+1")

    nodes = NODES
    if args.only:
        nodes = [n for n in NODES if args.only in (n.ip, n.name)]
        if not nodes:
            sys.exit("no node matches --only {!r}".format(args.only))

    results = {}
    aborted = False
    for node in nodes:
        name = node.name or node.ip
        if aborted:
            results[name] = None
            continue
        ok = provision_node(node, uid, pid, args.dry_run,
                            power_up_only=args.power_up_only,
                            teardown=args.teardown)
        results[name] = ok
        if not ok and not args.dry_run:
            log("\n!! ABORTING RUN: {} failed; skipping remaining node(s).".format(name))
            aborted = True

    log("\n=== SUMMARY ===")
    for name, ok in results.items():
        status = "OK" if ok else ("SKIPPED" if ok is None else "FAILED")
        log("  {}: {}".format(name, status))
    return 0 if all(v for v in results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
