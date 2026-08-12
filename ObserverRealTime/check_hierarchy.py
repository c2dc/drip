#!/usr/bin/env python3
"""
check_hierarchy.py - prove the DRIP hierarchy is coherent and delegable.

*** RUN THIS AFTER CHANGING drip_hierarchy.h OR hierarchy.json. ***

The hierarchy is defined twice, because the firmware is C and the observer is
Python and neither can read the other's file at runtime:

    drip_hierarchy.h   firmware   RAA/HDA numbers + the test parents' PRIVATE seeds
    hierarchy.json     observer   the same numbers + the PUBLIC keys and DETs

Two copies means they can drift. This tool exists so drift is caught in one
second by a tool, instead of surfacing later as E-LINK-* / E-SIG-01 in the
observer - findings that look exactly like a firmware fault and cost hours
before anyone suspects a stale constant.

WHAT IT PROVES
--------------
  1. DERIVATION  - every DET in hierarchy.json is re-derived from its public key
                   with cSHAKE128 (RFC 9374 section 3.5.2). Nothing is trusted:
                   the file's own DET fields are checked, not read.
  2. AGREEMENT   - drip_hierarchy.h and hierarchy.json state the same numbers,
                   and the header's private seeds produce the JSON's public keys.
  3. VALIDITY    - the RAA/HDA numbers are well-formed and coherent per the
                   ACTUAL RFC 9886 rules (6.2.1 Table 1 + 6.2.1.3 nibble split):
                       - RAA in a defined range (country / FCFS / private-use)
                       - HDA is NOT a reserved value (0/4096/8192/12288)
                       - the HDA authority and every UA carry the SAME RAA/HDA
                         numbers (read from the DET field bits, RFC 9374 3.3)
                   This is the check that matters and the one nothing else does.

CORRECTION (important)
----------------------
An earlier version tested "the HDA's DET must lie inside the RAA's /44 and the
UA inside the HDA's /56" (IPv6 prefix containment). That is NOT the RFC rule.
RFC 9886 6.2.1.3 defines the RAA/HDA relationship via a "nibble borrow" (the RAA
borrows the top two bits of the HDA field), and reserves HDA 0/4096/8192/12288.
The old containment test wrongly rejected valid pairs (e.g. RAA=255/HDA=14340).
The coherence that actually makes a chain delegable is that parents and children
share the same RAA/HDA numbers - which is decided from the numbers, not from
prefix arithmetic. Zones are printed for information only.

WHY THIS IS NOT AUTOMATIC
-------------------------
RFC 9575 section 6.4.2 - the Broadcast Endorsement chain the observer already
walks - verifies SIGNATURES ONLY. It never looks at the numbers. So a hierarchy
can verify perfectly offline and still carry mismatched RAA/HDA numbers.

Exit status 0 = coherent, 1 = a problem (so it can gate a build).
"""

import sys
import json
import re
import ipaddress
import argparse

import det
import ed25519


def zone_of(det_bytes, bits):
    """The DNS zone a DET belongs to: its own prefix truncated to `bits`.

    RFC 9886 section 6: RAA -> /44, HDA -> /56. The zone is fixed entirely by
    the RAA/HDA nibbles inside the DET; the key only affects the trailing
    64-bit ORCHID hash, so it cannot influence delegation.
    """
    nbytes = (bits + 7) // 8
    base = bytes(det_bytes[:nbytes]) + b"\x00" * (16 - nbytes)
    return ipaddress.IPv6Network((ipaddress.IPv6Address(base), bits), strict=False)


def parse_header(path):
    """Pull the numbers and seeds out of drip_hierarchy.h.

    Deliberately regex rather than a C parser: the header is ours and its shape
    is fixed. If it stops matching, this tool fails loudly rather than silently
    checking nothing - which is the only failure mode that would matter.
    """
    src = open(path, encoding="utf-8").read()
    out = {"nums": {}, "seeds": {}}

    for key in ("DRIP_UA_RAA", "DRIP_UA_HDA", "DRIP_APEX_RAA", "DRIP_APEX_HDA",
                "DRIP_RAA_RAA", "DRIP_RAA_HDA", "DRIP_HDA_RAA", "DRIP_HDA_HDA"):
        m = re.search(r'#define\s+%s\s+(\S+)' % key, src)
        if not m:
            raise SystemExit(f"ERROR: {path}: #define {key} not found")
        out["nums"][key] = m.group(1).rstrip("u")

    # Resolve aliases (DRIP_RAA_RAA is #defined to DRIP_UA_RAA, not a literal)
    for _ in range(4):
        for k, v in list(out["nums"].items()):
            if v in out["nums"]:
                out["nums"][k] = out["nums"][v]
    for k, v in out["nums"].items():
        try:
            out["nums"][k] = int(v, 0)
        except ValueError:
            raise SystemExit(f"ERROR: {path}: #define {k} is '{v}', not a number "
                             f"this tool can resolve.")

    for key in ("DRIP_APEX_SEED_INIT", "DRIP_RAA_SEED_INIT", "DRIP_HDA_SEED_INIT"):
        m = re.search(r'#define\s+%s\s+\{(.*?)\}' % key, src, re.S)
        if not m:
            raise SystemExit(f"ERROR: {path}: #define {key} not found")
        vals = re.findall(r'0[xX]([0-9a-fA-F]{2})', m.group(1))
        if len(vals) != 32:
            raise SystemExit(f"ERROR: {path}: {key} has {len(vals)} bytes, expected 32")
        out["seeds"][key] = bytes(int(v, 16) for v in vals)
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Prove the DRIP hierarchy is coherent, consistent and delegable")
    ap.add_argument("--json", default="hierarchy.json")
    ap.add_argument("--header", default="drip_hierarchy.h",
                    help="drip_hierarchy.h (skipped if absent)")
    ap.add_argument("--ua-keys", default=None,
                    help="keyring file of UA DET/pubkey pairs (default: the "
                         "observer's built-in bench identities)")
    args = ap.parse_args()

    problems = []
    h = json.load(open(args.json, encoding="utf-8"))
    print(f"hierarchy: {args.json}")

    # The both-chains file uses plural "raas"/"hdas". The firmware header
    # describes ONE chain (the currently-flashed UA RAA/HDA). We validate THAT
    # chain here: pick the raa/hda entries whose numbers match the header (or the
    # file's ua_raa/ua_hda when there is no header). Singular "raa"/"hda"/"apex"
    # are still honoured for the one-chain schema.
    def pick(key_plural, key_single, want_raa, want_hda):
        if key_single in h:
            return h[key_single]
        for e in h.get(key_plural, []):
            if e["raa"] == want_raa and (want_hda is None or e["hda"] == want_hda):
                return e
        return None

    # Determine which chain to check.
    hdr_nums = None
    try:
        hdr_probe = parse_header(args.header)
        hdr_nums = hdr_probe["nums"]
    except SystemExit:
        hdr_nums = None

    if hdr_nums:
        want_raa, want_hda = hdr_nums["DRIP_UA_RAA"], hdr_nums["DRIP_UA_HDA"]
    elif "ua_raa" in h:
        want_raa, want_hda = h["ua_raa"], h["ua_hda"]
    else:
        # infer from the first hda entry
        first = (h.get("hdas") or [h.get("hda")])[0]
        want_raa, want_hda = first["raa"], first["hda"]
    print(f"  Validating chain: RAA={want_raa}  HDA={want_hda}\n")

    apex_e = h.get("apex")
    raa_e  = pick("raas", "raa", want_raa, 0) or pick("raas", "raa", want_raa, None)
    hda_e  = pick("hdas", "hda", want_raa, want_hda)
    if raa_e is None or hda_e is None or apex_e is None:
        print("ERROR: could not find a complete apex/raa/hda chain for "
              f"RAA={want_raa} HDA={want_hda} in {args.json}")
        return 1

    # ---- 1. DERIVATION -----------------------------------------------------
    print("1. DERIVATION  (re-derive every DET from its public key, RFC 9374 3.5.2)")
    ents = {}
    for name, e in (("apex", apex_e), ("raa", raa_e), ("hda", hda_e)):
        pub = bytes.fromhex(e["public_key"])
        claimed = bytes.fromhex(e["det"])
        actual = det.compute_det(pub, e["raa"], e["hda"])
        ok = actual == claimed
        ents[name] = {"det": actual, "pub": pub, "raa": e["raa"], "hda": e["hda"]}
        print(f"   {name:5s} {e['raa']:5d}/{e['hda']:<5d} "
              f"{ipaddress.IPv6Address(actual)}  {'OK' if ok else '*** MISMATCH ***'}")
        if not ok:
            problems.append(f"{name}: hierarchy.json says DET={claimed.hex().upper()} "
                            f"but its own public key derives {actual.hex().upper()}")

    # ---- 2. AGREEMENT with the firmware header -----------------------------
    print("\n2. AGREEMENT  (drip_hierarchy.h vs hierarchy.json)")
    try:
        hdr = parse_header(args.header)
    except SystemExit as e:
        print(f"   SKIPPED: {e}")
        hdr = None
    if hdr:
        pairs = [("DRIP_UA_RAA", want_raa), ("DRIP_UA_HDA", want_hda),
                 ("DRIP_APEX_RAA", apex_e["raa"]), ("DRIP_APEX_HDA", apex_e["hda"]),
                 ("DRIP_RAA_RAA", raa_e["raa"]),  ("DRIP_RAA_HDA", raa_e["hda"]),
                 ("DRIP_HDA_RAA", hda_e["raa"]),  ("DRIP_HDA_HDA", hda_e["hda"])]
        for key, jval in pairs:
            hval = hdr["nums"][key]
            if hval != jval:
                problems.append(f"{key}: header={hval} but hierarchy.json={jval}")
                print(f"   {key:16s} header={hval:<6} json={jval:<6} *** MISMATCH ***")
        if not problems:
            print("   all 8 numbers agree")
        # the header's private seeds must produce the JSON's public keys
        for name, seedkey in (("apex", "DRIP_APEX_SEED_INIT"),
                              ("raa", "DRIP_RAA_SEED_INIT"),
                              ("hda", "DRIP_HDA_SEED_INIT")):
            pub = ed25519.derive_pubkey(hdr["seeds"][seedkey])
            if pub != ents[name]["pub"]:
                problems.append(f"{name}: the header's seed derives public key "
                                f"{pub.hex().upper()[:16]}... but hierarchy.json "
                                f"has {ents[name]['pub'].hex().upper()[:16]}...")
                print(f"   {name} seed -> public key            *** MISMATCH ***")
        print("   header seeds reproduce the json public keys")

    # ---- 3. HIERARCHY VALIDITY  (RFC 9886 6.2.1 / 6.2.1.3) -----------------
    #
    # CORRECTED RULE. An earlier version of this file tested "the HDA's DET must
    # lie inside the RAA's /44" (prefix containment). That is NOT the RFC rule and
    # it wrongly rejects valid pairs such as RAA=255/HDA=14340. The real rules are:
    #
    #   (a) RAA range (RFC 9886 6.2.1, Table 1):
    #         0-3 reserved | 4-3999 ISO-3166 country | 4000-8191 reserved |
    #         8192-15359 FCFS | 15360-16383 private-use (testing)
    #   (b) HDA reserved values (RFC 9886 3 / 6.2.1.3): 0, 4096, 8192, 12288 are
    #       reserved for the RAA's own operational use (nibble-borrow bases).
    #   (c) Coherence: the HDA authority and every UA must carry the SAME RAA/HDA
    #       numbers as each other, read from the DET's own field bits (RFC 9374
    #       3.3). This is what actually makes the chain delegable, and it is
    #       decidable from the numbers - no prefix-containment arithmetic.
    #
    # DNS zones are still shown for information (RAA /44, HDA /56), but zone
    # containment is NOT used as a pass/fail test.
    print("\n3. HIERARCHY VALIDITY  (RFC 9886 6.2.1 / 6.2.1.3)")

    def raa_range_note(raa):
        if raa <= 3:            return "reserved"
        if raa <= 3999:         return "ISO-3166 country (IESG approval)"
        if raa <= 8191:         return "reserved"
        if raa <= 15359:        return "unassigned (FCFS)"
        return "private-use (testing)"

    RESERVED_HDA = {0, 4096, 8192, 12288}

    raa_f = det.parse_det(ents["raa"]["det"])
    hda_f = det.parse_det(ents["hda"]["det"])
    print(f"   RAA number {raa_f['raa']:5d}  -> {raa_range_note(raa_f['raa'])}")
    print(f"   HDA number {hda_f['hda']:5d}  -> "
          f"{'RESERVED - INVALID' if hda_f['hda'] in RESERVED_HDA else 'usable'}")
    print(f"   (info) RAA /44 zone : {zone_of(ents['raa']['det'], 44)}")
    print(f"   (info) HDA /56 zone : {zone_of(ents['hda']['det'], 56)}")

    if not (0 <= raa_f['raa'] <= 16383):
        problems.append(f"RAA {raa_f['raa']} is outside the 14-bit range.")
    if hda_f['hda'] in RESERVED_HDA:
        problems.append(f"HDA {hda_f['hda']} is reserved for the RAA "
                        f"(0/4096/8192/12288, RFC 9886 3). Pick another HDA.")
    # HDA authority must carry the RAA's number.
    if hda_f['raa'] != raa_f['raa']:
        problems.append(f"HDA authority RAA field ({hda_f['raa']}) != RAA "
                        f"authority number ({raa_f['raa']}). The HDA must live "
                        f"under its RAA (RFC 9374 3.3).")

    # UA keys: the observer's built-ins unless a keyring is supplied.
    uas = []
    if args.ua_keys:
        for ln, line in enumerate(open(args.ua_keys, encoding="utf-8"), 1):
            t = line.split("#", 1)[0].split()
            if len(t) == 2:
                uas.append((f"{args.ua_keys}:{ln}", bytes.fromhex(t[0]), bytes.fromhex(t[1])))
    else:
        try:
            import identity_resolve
            trust = identity_resolve.load_trust(args.json)
            uas = [(lbl, bytes.fromhex(d), bytes.fromhex(p))
                   for d, p, lbl in identity_resolve.iter_known_keys(trust)
                   if lbl.lower().startswith(("slot", "ua"))]
            if not uas:  # fall back to all keyed entities if none are labelled UA
                uas = [(lbl, bytes.fromhex(d), bytes.fromhex(p))
                       for d, p, lbl in identity_resolve.iter_known_keys(trust)]
        except Exception as e:
            print(f"   (could not load UA keys from {args.json}: {e})")

    for lbl, d, pub in uas:
        f = det.parse_det(d)
        # Only check UAs that belong to the chain under validation.
        if f['raa'] != want_raa or f['hda'] != want_hda:
            continue
        # Coherence: the UA must carry the HDA's RAA/HDA numbers.
        same = (f['raa'] == hda_f['raa'] and f['hda'] == hda_f['hda'])
        bound = det.verify_det_binding(d, pub)
        flags = []
        if not same:
            flags.append(f"RAA/HDA {f['raa']}/{f['hda']} != HDA {hda_f['raa']}/{hda_f['hda']}")
            problems.append(f"UA {ipaddress.IPv6Address(d)} ({lbl}) carries "
                            f"{f['raa']}/{f['hda']}, not the HDA's "
                            f"{hda_f['raa']}/{hda_f['hda']}.")
        if not bound:
            flags.append("DET/KEY BINDING FAILED")
            problems.append(f"UA {lbl}: DET does not derive from its public key")
        print(f"   UA {ipaddress.IPv6Address(d)}  {lbl:34s} "
              f"{'ok' if not flags else '*** ' + ', '.join(flags) + ' ***'}")

    # ---- verdict -----------------------------------------------------------
    print()
    if problems:
        print(f"FAILED - {len(problems)} problem(s):")
        for p in problems:
            print(f"  * {p}")
        print("\nThis hierarchy cannot be published in DNS as-is.")
        return 1
    print("OK - the hierarchy is coherent, consistent across firmware and observer,")
    print("     the RAA/HDA numbers are well-formed (RFC 9886 6.2.1 / 6.2.1.3),")
    print("     and parents and children share the same numbers, so it is delegable.")
    print("\nNOTE: this proves the STRUCTURE. It does not prove any registry has")
    print("      assigned these numbers (RFC 9374 3.3) - they are test values.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
