#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - make_vectors.py
#  A small REFERENCE ENCODER that hand-builds ASTM/DRIP messages (valid and
#  deliberately broken) directly from the spec layouts. It does two jobs:
#    1. Writes a Format B test file (--write vectors.txt).
#    2. Self-tests the observer (--selftest): runs observer.run() on the
#       built-in vectors and asserts each broken vector raises exactly the
#       expected error ID, and the valid vectors raise none.
#
#  This is the "golden reference" the ESP32 generator (Checkpoint 3) must
#  later match, byte for byte.
#
#  NOTE: this v1 builds STRUCTURAL vectors. Cryptographically-signed DRIP
#  Wrapper/Link payloads (for E-SIG-01) are produced once RFC 9575 4.2/4.3
#  byte layouts are pinned in the crypto sub-step.
# =============================================================================

import sys
import struct
import argparse

import odid
import observer

# Our test identity (from det.py: sub-steps 1a/1b)
try:
    import det
    UA_DET = det.UA_DET
    UA_PUB = det.UA_PUB
except Exception:                                  # fallback to recorded values
    UA_DET = bytes.fromhex("20010030fa07d0054dfdc31103e51953")
    UA_PUB = None

# Ed25519 private seed for signing valid Wrapper vectors (matches UA_PUB / on-device UA_PRIV_SEED)
try:
    import ed25519
    UA_PRIV_SEED = bytes.fromhex("568BF5E8F08ABAADB68BA1964BC25F2976A8AFC938244A39F76E0AB0C703CCD6")
    HAVE_ED = True
except Exception:
    HAVE_ED = False

VER = 0x2
def _hdr(t): return bytes([(t << 4) | VER])


# ---------------------------------------------------------------------------
#  Message builders (each returns exactly 25 bytes)
# ---------------------------------------------------------------------------
def basic_id(det_bytes=UA_DET, ua_type=0, id_type=4, ssi_type=1, version=VER):
    b = bytes([(0x0 << 4) | version]) + bytes([(id_type << 4) | ua_type])
    uasid = bytes([ssi_type]) + det_bytes              # SSI Type + 16-byte DET
    uasid += b'\x00' * (20 - len(uasid))
    b += uasid + b'\x00' * 3
    assert len(b) == 25
    return b


def self_id(text="DronesRus:Survey", dtype=0):
    d = text.encode()[:23]
    d += b'\x00' * (23 - len(d))
    b = _hdr(0x3) + bytes([dtype]) + d
    assert len(b) == 25
    return b


def operator_id(text="OPERATOR-TEST-01", otype=0):
    o = text.encode()[:20]
    o += b'\x00' * (20 - len(o))
    b = _hdr(0x5) + bytes([otype]) + o + b'\x00' * 3
    assert len(b) == 25
    return b


def system_msg(lat=-23.2237, lon=-45.9009, ts=0x0A1B2C3D):
    b = _hdr(0x4) + bytes([0x00])
    b += struct.pack('<i', int(lat * 1e7)) + struct.pack('<i', int(lon * 1e7))
    b += struct.pack('<H', 1)                           # area count
    b += bytes([0])                                     # area radius
    b += struct.pack('<H', 0) + struct.pack('<H', 0)    # ceiling, floor
    b += bytes([0])                                     # UA classification
    b += struct.pack('<H', 0)                           # operator altitude
    b += struct.pack('<I', ts)                          # timestamp
    b += bytes([0])                                     # reserved
    assert len(b) == 25
    return b


def auth_page0(sam_type, sam_payload, last_page, ts=0x0A1B2C3D,
               auth_type=5, data_page=0, reserved_nibble=0):
    auth_data = bytes([sam_type]) + sam_payload         # first auth byte = SAM Type
    b = _hdr(0x2) + bytes([(auth_type << 4) | data_page])
    b += bytes([(reserved_nibble << 4) | (last_page & 0xF)])
    b += bytes([len(auth_data) & 0xFF])
    b += struct.pack('<I', ts & 0xFFFFFFFF)
    page0 = auth_data[:17]
    page0 += b'\x00' * (17 - len(page0))
    b += page0
    assert len(b) == 25
    return b, auth_data


def auth_pageN(auth_data, idx_into_data, page, auth_type=5):
    c = auth_data[idx_into_data:idx_into_data + 23]
    c += b'\x00' * (23 - len(c))
    b = _hdr(0x2) + bytes([(auth_type << 4) | (page & 0xF)]) + c
    assert len(b) == 25
    return b


def pack(msgs, msg_size=0x19, count=None):
    n = len(msgs) if count is None else count
    b = _hdr(0xF) + bytes([msg_size, n])
    for m in msgs:
        b += m
    return b


def _location_msg():
    """A minimal, valid 25-byte Location/Vector message (type 0x1). Field
       content is not decoded by the signature check, so a placeholder body is
       fine for the crypto self-test (both signer and verifier see the same
       raw bytes)."""
    b = _hdr(0x1) + bytes(24)
    assert len(b) == 25
    return b


def build_extended_wrapper_pages(astm_msgs, det_bytes, vnb, vna, priv_seed):
    """Build the 5 Auth pages of an Extended Transport DRIP Wrapper that signs
       over `astm_msgs`, mirroring the firmware (drip_auth.cpp) exactly:
         Evidence = astm_msgs stable-sorted ascending by type
         signed   = VNB(4,LE) || VNA(4,LE) || Evidence || DET(16)
         wire     = SAM(0x02) || VNB(4) || VNA(4) || DET(16) || Sig(64)  (89 B)
       Returns (pages[5], signed_bytes)."""
    ordered = sorted(astm_msgs, key=lambda m: (m[0] >> 4) & 0xF)   # stable sort
    evidence = b"".join(ordered)
    signed = struct.pack('<I', vnb) + struct.pack('<I', vna) + evidence + det_bytes
    sig = ed25519.sign(priv_seed, signed)
    sam_payload = struct.pack('<I', vnb) + struct.pack('<I', vna) + det_bytes + sig  # 88 B (after SAM type)
    p0, authdata = auth_page0(0x02, sam_payload, last_page=4, ts=vnb)               # 89 B total -> 5 pages
    pages = [p0]
    off = 17
    for pg in range(1, 5):
        pages.append(auth_pageN(authdata, off, pg))
        off += 23
    return pages, signed


# ---------------------------------------------------------------------------
#  Vector set: (label, record_bytes, expected_error_id_or_None, needs_pubkey)
# ---------------------------------------------------------------------------
def build_vectors():
    V = []

    # ---- valid -------------------------------------------------------------
    # Placeholder Wrapper (SAM 0x02, no real signature): STRUCTURAL test only,
    # so run without a pubkey (E-SIG-01/E-DET-02 require a key and are skipped).
    a0_ok, _ = auth_page0(0x02, b'\x00' * 8, last_page=0)
    valid_pack = pack([basic_id(), system_msg(), self_id(), operator_id(), a0_ok])
    V.append(("valid pack (structural, placeholder Wrapper)", valid_pack, None, False))
    V.append(("valid single Basic ID (our DET)", basic_id(), None, True))

    # a valid 2-page auth, reassembles cleanly
    a0_2, ad2 = auth_page0(0x02, bytes(range(0x10, 0x37)), last_page=1)   # 39-byte payload
    a1_2 = auth_pageN(ad2, 17, 1)
    V.append(("valid 2-page Wrapper auth (structural)", pack([basic_id(), a0_2, a1_2]), None, False))

    # ---- broken (one error each) ------------------------------------------
    V.append(("E-FMT-02 wrong version", basic_id(version=0x3), "E-FMT-02", False))
    V.append(("E-PACK-01 size!=0x19", pack([basic_id()], msg_size=0x18), "E-PACK-01", False))
    V.append(("E-PACK-02 count=0", pack([], count=0), "E-PACK-02", False))
    V.append(("E-PACK-03 truncated", pack([basic_id(), self_id()], count=3), "E-PACK-03", False))
    V.append(("E-PACK-04 nested pack", pack([pack([basic_id()], count=1)[:25]]), "E-PACK-04", False))
    a0_at7, _ = auth_page0(0x00, b'\x00' * 4, last_page=0, auth_type=7)
    V.append(("E-AUTH-01 reserved AuthType 7", pack([a0_at7]), "E-AUTH-01", False))
    a0_rsv, _ = auth_page0(0x02, b'\x00' * 4, last_page=0, reserved_nibble=0x1)
    V.append(("E-AUTH-04 last-page reserved bits", pack([a0_rsv]), "E-AUTH-04", False))
    # auth claims last page 2 but page 1 is missing -> E-AUTH-03 (+E-AUTH-05)
    a0_gap, _ = auth_page0(0x02, b'\x00' * 40, last_page=2)
    V.append(("E-AUTH-03 page gap", pack([a0_gap]), "E-AUTH-03", False))
    a0_sam9, _ = auth_page0(0x09, b'\x00' * 4, last_page=0)   # SAM type 0x09 unknown
    V.append(("E-SAM-01 unknown SAM type", pack([a0_sam9]), "E-SAM-01", False))
    # DET with a non-DET prefix (flip the top byte of the prefix)
    bad_prefix_det = bytes([0x30]) + UA_DET[1:]
    V.append(("E-DET-01 bad DET prefix", basic_id(det_bytes=bad_prefix_det), "E-DET-01", False))
    # valid prefix DET but corrupted hash -> binding fails (needs pubkey)
    bad_hash_det = UA_DET[:8] + bytes([UA_DET[8] ^ 0x01]) + UA_DET[9:]
    V.append(("E-DET-02 binding failure", basic_id(det_bytes=bad_hash_det), "E-DET-02", True))

    # ---- signed Extended Wrapper (E-SIG-01) --------------------------------
    if HAVE_ED and UA_PUB is not None:
        vnb = 0x0A1B2C3D
        vna = vnb + 120
        astm = [basic_id(), system_msg(), _location_msg()]   # types 0x0, 0x4, 0x1
        pages, _signed = build_extended_wrapper_pages(astm, UA_DET, vnb, vna, UA_PRIV_SEED)
        # A valid Wrapper pack: the SAME ASTM messages the signature covers + 5 wrapper pages.
        good = pack([basic_id(), _location_msg(), system_msg()] + pages)
        V.append(("valid signed Extended Wrapper", good, None, True))
        # Corrupt the first signature byte (authdata[25] -> page 1, offset 10) -> E-SIG-01
        bad_pages = [bytearray(p) for p in pages]
        bad_pages[1][10] ^= 0x01
        bad = pack([basic_id(), _location_msg(), system_msg()] + [bytes(p) for p in bad_pages])
        V.append(("E-SIG-01 corrupted Wrapper signature", bad, "E-SIG-01", True))

    return V


# ---------------------------------------------------------------------------
#  Output + self-test
# ---------------------------------------------------------------------------
def to_format_b(vectors):
    lines = ["# DRIP Observer test vectors (Format B). Auto-generated by make_vectors.py",
             "# Each line is hex; '# expect: <ID>' tags the following record.", ""]
    for label, rec, expect, _needs in vectors:
        lines.append(f"# {label}")
        if expect:
            lines.append(f"# expect: {expect}")
        lines.append(' '.join(f'{x:02X}' for x in rec))
        lines.append("")
    return "\n".join(lines)


def self_test():
    vectors = build_vectors()
    passed = failed = 0
    for label, rec, expect, needs_pub in vectors:
        pub = UA_PUB if needs_pub else None
        text = ' '.join(f'{x:02X}' for x in rec)
        _fmt, _report, findings = observer.run(text, pub=pub)
        ids = {f.error_id for f in findings}
        if expect is None:
            ok = (len(findings) == 0)
        else:
            ok = (expect in ids)
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1
        detail = "no findings" if not findings else ", ".join(sorted(ids))
        print(f"  [{status}] {label:42s} expect={expect or '(clean)':10s} got: {detail}")
    print(f"\nself-test: {passed} passed, {failed} failed")
    chain_ok = man_ok = True
    if HAVE_ED:
        chain_ok = chain_self_test()
        man_ok = manifest_self_test()
    return failed == 0 and chain_ok and man_ok


def main(argv=None):
    ap = argparse.ArgumentParser(description="DRIP reference encoder / observer self-test")
    ap.add_argument("--write", metavar="FILE", help="write the vectors as a Format B file")
    ap.add_argument("--selftest", action="store_true", help="run the observer self-test")
    args = ap.parse_args(argv)

    if args.write:
        with open(args.write, "w") as fh:
            fh.write(to_format_b(build_vectors()))
        print(f"wrote {args.write}")
    if args.selftest or not args.write:
        ok = self_test()
        return 0 if ok else 1
    return 0



# ===========================================================================
#  DRIP Link chain of trust vectors (Task 3b) — fabricates the same 3-link
#  Broadcast Endorsement chain that drip_registration.cpp builds, with REAL
#  Ed25519 signatures by the test parent keys, then pages each BE into a Link
#  pack. Used to self-test the observer's verify_link_chain().
# ===========================================================================
if HAVE_ED:
    _APEX_SEED = bytes(range(0xA0, 0xC0))
    _RAA_SEED  = bytes(range(0xC0, 0xE0))
    _HDA_SEED  = bytes(range(0xE0, 0x100))
    _APEX_RAA, _APEX_HDA = 0x0000, 0x0000
    _RAA_RAA,  _RAA_HDA  = 0x0001, 0x0000
    _HDA_RAA,  _HDA_HDA  = 0x0001, 0x0001

    def _mk_be(vnb, vna, det_child, hi_child, det_parent, parent_seed):
        signed = struct.pack('<I', vnb) + struct.pack('<I', vna) + det_child + hi_child + det_parent
        return {"vnb": vnb, "vna": vna, "det_child": det_child, "hi_child": hi_child,
                "det_parent": det_parent, "sig": ed25519.sign(parent_seed, signed)}

    def _be_to_pages(be):
        payload = (struct.pack('<I', be['vnb']) + struct.pack('<I', be['vna'])
                   + be['det_child'] + be['hi_child'] + be['det_parent'] + be['sig'])  # 136 B
        p0, authdata = auth_page0(0x01, payload, last_page=6, ts=be['vnb'])              # 137 B -> 7 pages
        pages = [p0]; off = 17
        for pg in range(1, 7):
            pages.append(auth_pageN(authdata, off, pg)); off += 23
        return pages

    def _be_pack(be):
        return pack([basic_id(), _location_msg()] + _be_to_pages(be))

    def build_chain(vnb=201699200, vna=None):
        if vna is None: vna = vnb + 86400
        apex_hi = ed25519.derive_pubkey(_APEX_SEED)
        raa_hi  = ed25519.derive_pubkey(_RAA_SEED)
        hda_hi  = ed25519.derive_pubkey(_HDA_SEED)
        apex_det = det.compute_det(apex_hi, _APEX_RAA, _APEX_HDA, 5)
        raa_det  = det.compute_det(raa_hi,  _RAA_RAA,  _RAA_HDA,  5)
        hda_det  = det.compute_det(hda_hi,  _HDA_RAA,  _HDA_HDA,  5)
        return {
            "apex_raa": _mk_be(vnb, vna, raa_det, raa_hi, apex_det, _APEX_SEED),
            "raa_hda":  _mk_be(vnb, vna, hda_det, hda_hi, raa_det,  _RAA_SEED),
            "hda_ua":   _mk_be(vnb, vna, UA_DET,  UA_PUB, hda_det,  _HDA_SEED),
            "hda_det":  hda_det,
        }

    def _packs_text(bes):
        return "\n".join(' '.join(f'{x:02X}' for x in _be_pack(b)) for b in bes)

    def chain_self_test():
        print("\n--- DRIP Link chain self-test ---")
        passed = failed = 0
        def check(label, bes, expect, now=None):
            nonlocal passed, failed
            _f, _r, findings = observer.run(_packs_text(bes), now=now)
            ids = {f.error_id for f in findings}
            ok = (expect is None and not findings) or (expect is not None and expect in ids)
            print(f"  [{'PASS' if ok else 'FAIL'}] {label:38s} expect={expect or '(clean)':10s} "
                  f"got: {', '.join(sorted(ids)) or 'no findings'}")
            passed += ok; failed += (not ok)

        c = build_chain()
        check("valid full 3-link chain", [c['apex_raa'], c['raa_hda'], c['hda_ua']], None)

        # E-LINK-02: corrupt one signature byte in the RAA,HDA endorsement
        bad = dict(c['raa_hda']); bad['sig'] = bytes([bad['sig'][0] ^ 1]) + bad['sig'][1:]
        check("E-LINK-02 bad parent signature", [c['apex_raa'], bad, c['hda_ua']], "E-LINK-02")

        # E-LINK-03: omit the Apex,RAA link -> RAA,HDA has no path to anchor
        check("E-LINK-03 broken chain (no Apex)", [c['raa_hda'], c['hda_ua']], "E-LINK-03")

        # E-LINK-01: leaf child DET hash corrupted but re-signed (binding fails, sig valid)
        bad_det = UA_DET[:8] + bytes([UA_DET[8] ^ 1]) + UA_DET[9:]
        leaf_bad = _mk_be(c['hda_ua']['vnb'], c['hda_ua']['vna'], bad_det, UA_PUB,
                          c['hda_det'], _HDA_SEED)
        check("E-LINK-01 child DET/HI mismatch", [c['apex_raa'], c['raa_hda'], leaf_bad], "E-LINK-01")

        # E-LINK-04: valid chain, but reference time is after VNA
        check("E-LINK-04 expired window", [c['apex_raa'], c['raa_hda'], c['hda_ua']],
              "E-LINK-04", now=c['hda_ua']['vna'] + 10)

        print(f"  chain self-test: {passed} passed, {failed} failed")
        return failed == 0


# ===========================================================================
#  DRIP Manifest vectors (Task 3b/Manifest) — fabricates a Manifest that
#  references a Wrapper pack hash and a BE:HDA,UA link hash, exactly as the
#  firmware (drip_manifest.cpp) does, and self-tests verify_manifests().
# ===========================================================================
if HAVE_ED:
    import math as _math

    def _page_sam(sam_type, sam_payload, ts):
        total = 1 + len(sam_payload)
        n = (_math.ceil((total - 17) / 23) + 1) if total > 17 else 1
        p0, authdata = auth_page0(sam_type, sam_payload, last_page=n - 1, ts=ts)
        pages = [p0]; off = 17
        for pg in range(1, n):
            pages.append(auth_pageN(authdata, off, pg)); off += 23
        return pages

    def _be_full_sam(be):
        return (bytes([0x01]) + struct.pack('<I', be['vnb']) + struct.pack('<I', be['vna'])
                + be['det_child'] + be['hi_child'] + be['det_parent'] + be['sig'])

    def _manifest_payload(prev8, link_hash8, pack_hashes, vnb, vna,
                          ua_det=UA_DET, ua_seed=UA_PRIV_SEED, force_curr=None, break_sig=False):
        astm = b"".join(pack_hashes)
        ev = bytearray(prev8 + b"\x00" * 8 + link_hash8 + astm)
        curr = det.cshake128(bytes(ev), 8, N=b'', S=b"Remote ID Auth Hash")
        ev[8:16] = force_curr if force_curr is not None else curr
        signed = struct.pack('<I', vnb) + struct.pack('<I', vna) + bytes(ev) + ua_det
        sig = bytearray(ed25519.sign(ua_seed, signed))
        if break_sig:
            sig[0] ^= 0x01
        payload = struct.pack('<I', vnb) + struct.pack('<I', vna) + bytes(ev) + ua_det + bytes(sig)
        return payload, bytes(curr)

    def _manifest_pack(payload, vnb):
        return pack([basic_id(), _location_msg(), system_msg()] + _page_sam(0x03, payload, vnb))

    def manifest_self_test():
        print("\n--- DRIP Manifest self-test ---")
        passed = failed = 0
        vnb = 201699200; vna = vnb + 120

        wp, _ = build_extended_wrapper_pages([basic_id(), system_msg(), _location_msg()],
                                             UA_DET, vnb, vna, UA_PRIV_SEED)
        wrapper_pack = pack([basic_id(), _location_msg(), system_msg()] + wp)
        pack_hash = det.cshake128(wrapper_pack, 8, N=b'', S=b"Remote ID Auth Hash")

        c = build_chain(vnb, vna)
        link_pack = _be_pack(c['hda_ua'])
        link_hash = det.cshake128(_be_full_sam(c['hda_ua']), 8, N=b'', S=b"Remote ID Auth Hash")

        prev0 = bytes(8)  # first manifest seed (zeros for reproducibility)
        pl, curr1 = _manifest_payload(prev0, link_hash, [pack_hash], vnb, vna)
        man_pack = _manifest_pack(pl, vnb)
        chain_packs = [_be_pack(c['apex_raa']), _be_pack(c['raa_hda']), link_pack]

        def check(label, packs_list, expect, now=None):
            nonlocal passed, failed
            text = "\n".join(' '.join(f'{x:02X}' for x in p) for p in packs_list)
            _f, _r, findings = observer.run(text, pub=UA_PUB, now=now)
            ids = {f.error_id for f in findings}
            ok = (expect is None and not findings) or (expect is not None and expect in ids)
            print(f"  [{'PASS' if ok else 'FAIL'}] {label:40s} expect={expect or '(clean)':10s} "
                  f"got: {', '.join(sorted(ids)) or 'no findings'}")
            passed += ok; failed += (not ok)

        check("valid manifest (all refs present)", [wrapper_pack] + chain_packs + [man_pack], None)
        check("E-MAN-02 pack hash not observed", chain_packs + [man_pack], "E-MAN-02")
        check("E-MAN-03 link hash not observed",
              [wrapper_pack, _be_pack(c['apex_raa']), _be_pack(c['raa_hda']), man_pack], "E-MAN-03")

        pl_sig, _ = _manifest_payload(prev0, link_hash, [pack_hash], vnb, vna, break_sig=True)
        check("E-MAN-01 bad signature", [wrapper_pack] + chain_packs + [_manifest_pack(pl_sig, vnb)], "E-MAN-01")

        pl_curr, _ = _manifest_payload(prev0, link_hash, [pack_hash], vnb, vna, force_curr=bytes(8))
        check("E-MAN-05 wrong current hash", [wrapper_pack] + chain_packs + [_manifest_pack(pl_curr, vnb)], "E-MAN-05")

        # E-MAN-04: two manifests where the 2nd Prev != 1st Curr
        pl2, _ = _manifest_payload(bytes([0xAA]) * 8, link_hash, [pack_hash], vnb + 1, vna + 1)
        check("E-MAN-04 broken manifest chain",
              [wrapper_pack] + chain_packs + [man_pack, _manifest_pack(pl2, vnb + 1)], "E-MAN-04")

        print(f"  manifest self-test: {passed} passed, {failed} failed")
        return failed == 0


if __name__ == "__main__":
    sys.exit(main())
