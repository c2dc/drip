#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - observer.py
#  Reads a DRIP capture (Format W = Wireshark bytes-only export, or
#  Format B = flat hex), decodes it via odid.py, validates it against the
#  errors.py catalog, and prints a report.
#
#  Usage:
#     python3 observer.py <file.txt> [--pubkey HEX] [--keyring FILE]
#                                    [--verbose] [--now UNIX] [--max-age SEC]
#
#  --pubkey HEX : 32-byte Ed25519 public key (hex). Enables the DET<->key
#                 binding check (E-DET-02) for DRIP Basic ID messages.
#  --now / --max-age : enable freshness check (E-FRESH-01) against a reference time.
# =============================================================================

import sys
import argparse
import ipaddress
from collections import Counter, defaultdict

import odid
from errors import Finding, ERROR_CATALOG

# det.py provides verify_det_binding() (RFC 9374 DET derivation). Optional:
try:
    import det
    HAVE_DET = True
except Exception:
    HAVE_DET = False

# ed25519.py provides RFC 8032 verify() for the Wrapper signature check. Optional:
try:
    import ed25519
    # The backend keeps ed25519.py as the normative reference and only uses a
    # faster implementation after proving it agrees (RFC 8032 §7.1 TEST 1,
    # valid AND tampered). It also memoises: the ~10 Hz beacon repeat
    # (ASTM §5.4.4.2 BUR0050) re-sends identical packs, and verifying an
    # identical (key,msg,sig) triple again cannot change the answer.
    import ed25519_backend
    HAVE_ED = True
except Exception:
    HAVE_ED = False

# Plausible ODID timestamp range (seconds since 2019-01-01). Table 8 caps at uint32.
TS_RANGE = (0, 2 ** 32 - 1)

# ---------------------------------------------------------------------------
#  Trust anchor for the DRIP Link chain of trust (RFC 9575 §6.4.2).
#  TEST-ONLY: derived from the fixed test APEX_SEED in drip_registration.cpp.
#  A real deployment MUST configure the true Apex (DET prefix owner) key and
#  DET here (or load them from a trust store) instead of these test values.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
#  Trust anchor.
#
#  These are the FALLBACK bench values. The real source of truth is
#  hierarchy.json, loaded at startup if present (or via --anchor FILE), so that
#  swapping in a real DNSSEC-anchored Apex is a DATA change, not a code change.
#
#  Under RFC 9886 7.1 this anchor is exactly what DNSSEC would establish: the
#  observer would learn the Apex key from a DNSSEC-validated lookup instead of
#  from a constant compiled into it. Until then it is hardcoded, and that is the
#  single most important thing this PoC does NOT yet solve (PART 4.3).
# ---------------------------------------------------------------------------
APEX_HI  = bytes.fromhex("4FD099CCD47D7893DFE9EC24414ECB0D9B5420232AAD30D91C465BE33CBE65C4")
APEX_DET = bytes.fromhex("2001003000000005881EC7928833E0FB")
ANCHOR_SOURCE = "built-in bench default"


def load_hierarchy(path="hierarchy.json"):
    """Load the trust anchor from hierarchy.json. Returns True if applied.

    PUBLIC data only. An absent file keeps the built-in default, so nothing
    that worked before this file existed breaks because of it.
    """
    global APEX_HI, APEX_DET, ANCHOR_SOURCE
    import json as _json
    try:
        h = _json.load(open(path, encoding="utf-8"))
        a = h["apex"]
        hi, d = bytes.fromhex(a["public_key"]), bytes.fromhex(a["det"])
    except FileNotFoundError:
        return False
    if len(hi) != 32 or len(d) != 16:
        raise ValueError(f"{path}: apex public_key must be 32 B and det 16 B")
    # Never adopt an anchor that does not hold together. An Apex whose DET does
    # not derive from its own key would silently reject every real drone, and
    # the report would blame the drones.
    if HAVE_DET and not det.verify_det_binding(d, hi):
        raise ValueError(f"{path}: the apex DET does not derive from its public "
                         f"key (RFC 9374 3.5.2). Run check_hierarchy.py.")
    APEX_HI, APEX_DET = hi, d
    ANCHOR_SOURCE = path
    return True

# cSHAKE128 customization string for all DRIP Manifest hashes (RFC 9575 §4.4.3)
MAN_HASH_CS = b"Remote ID Auth Hash"


# ---------------------------------------------------------------------------
#  Validators (each appends Finding objects)
# ---------------------------------------------------------------------------
def validate_message(d, where, findings):
    if d.get("_error") == "bad_length":
        findings.append(Finding("E-FMT-03", where, f"{d['length']} bytes"))
        return
    mtype = d.get("type")
    if mtype not in odid.MSG_TYPES:
        findings.append(Finding("E-FMT-01", where, f"type=0x{mtype:X}"))
    if d.get("version") != odid.PROTO_VERSION:
        findings.append(Finding("E-FMT-02", where, f"version=0x{d.get('version'):X}"))
    if mtype == 0xF:
        findings.append(Finding("E-PACK-04", where, "0xF message nested inside a pack"))

    if mtype == 0x2:                                   # authentication page checks
        at = d.get("auth_type")
        if at is not None and 6 <= at <= 9:
            findings.append(Finding("E-AUTH-01", where, f"AuthType={at}"))
        if d.get("page_num") == 0:
            if d.get("last_page_reserved", 0) != 0:
                findings.append(Finding("E-AUTH-04", where,
                                        f"reserved nibble=0x{d['last_page_reserved']:X}"))
            ts = d.get("timestamp_raw")
            if ts is not None and not (TS_RANGE[0] <= ts <= TS_RANGE[1]):
                findings.append(Finding("E-AUTH-06", where, f"ts={ts}"))

    if mtype == 0x0 and d.get("det") is not None:      # DRIP DET prefix check
        prefix28 = int.from_bytes(d["det"], "big") >> 100
        if prefix28 != (int(odid.DET_PREFIX.network_address) >> 100):
            findings.append(Finding("E-DET-01", where, d.get("det_ipv6", "")))


def validate_pack(pack_info, where, findings):
    if pack_info.get("_error"):
        findings.append(Finding("E-PACK-03", where, pack_info["_error"]))
        return
    if pack_info.get("msg_size") != 0x19:
        findings.append(Finding("E-PACK-01", where, f"size=0x{pack_info['msg_size']:X}"))
    n = pack_info.get("count", 0)
    if n < 1 or n > 9:
        findings.append(Finding("E-PACK-02", where, f"N={n}"))
    need = n * odid.MSG_LEN
    have = pack_info.get("bytes_available", 0)
    if need > have:
        findings.append(Finding("E-PACK-03", where, f"need {need}, have {have}"))


def validate_auth(auth, where, findings, now=None, max_age=None):
    expected = list(range(auth["last_page_index"] + 1))
    if auth["pages_present"] != expected:
        findings.append(Finding("E-AUTH-03", where,
                                f"pages={auth['pages_present']} expected={expected}"))
    if not auth["complete"]:
        findings.append(Finding("E-AUTH-05", where, f"declared length={auth['length']}"))
    if auth["auth_type"] == 5:                          # SAM type only meaningful here
        st = auth["sam_type"]
        if st not in odid.SAM_TYPES:
            findings.append(Finding("E-SAM-01", where,
                                    f"SAM=0x{st:02X}" if st is not None else "empty payload"))
    if now is not None and max_age is not None and auth.get("timestamp_unix") is not None:
        age = now - auth["timestamp_unix"]
        if age > max_age or age < -max_age:
            findings.append(Finding("E-FRESH-01", where, f"age={age}s window=+/-{max_age}s"))


# ---------------------------------------------------------------------------
#  Keyring — DET -> Ed25519 public key
#
#  The observer used to hold ONE key (--pubkey) and apply it to every DET it
#  met. That was correct while the transmitter was a single UA. It is not any
#  more: the bench emulator flies up to 3 virtual UAs, each with its OWN key and
#  DET (RFC 9374 3.5.2 binds a DET to the key it was derived from). With one
#  key, two of three drones would fail E-DET-02/E-SIG-01/E-MAN-01 against a key
#  that was never theirs -- a false accusation, not a finding.
# ---------------------------------------------------------------------------

# The three bench identities, as PUBLIC data (det_generator.cpp IDENTITY_TABLE).
# Regenerate with det.py + ed25519.py:
#     seed0 = bytes.fromhex("568BF5E8...C703CCD6")          # slot 0 (legacy)
#     slot_seed = lambda i: det.shake128(b"DRIP PoC UA slot %d" % i, 32)
#     pub = ed25519.derive_pubkey(seed); d = det.compute_det(pub, 1000, 2000)
# NOTE: the observer no longer hard-codes any identities. Every DET->public_key
# comes from the trusted-identities file (hierarchy.json) via
# identity_resolve.iter_known_keys(). This is the SINGLE SOURCE OF TRUTH - there
# is no BUILTIN_KEYS table to drift out of sync with the JSON.


class DnsFallback:
    """Once-per-DET DNS fallback for untrusted DETs seen while reading a file.

    Behaviour (per the agreed spec):
      * The FIRST time an untrusted DET is seen, do ONE DNS lookup (PTR->TXT).
      * Show the user what DNS returned and whether the DET<->key binding holds.
      * If the binding verified, ASK whether to add it to the trust file:
          - yes -> write it into hierarchy.json's ua[] AND add the key to the
                   live keyring, so it is trusted for the rest of THIS run.
          - no  -> record it as "declined"; never look it up again this run.
      * If the binding FAILED, say so plainly and do NOT offer to add it (a key
        that doesn't derive the DET must never enter a trust file). Recorded as
        "seen" so it is not looked up again.
      * If DNS could not answer, say so; recorded as "seen"; not retried.
    Every DET is consulted AT MOST ONCE per run, regardless of outcome.
    """

    def __init__(self, keyring, anchor, dns_server, interactive=True):
        self.keyring = keyring
        self.anchor = anchor
        self.dns_server = dns_server
        self.interactive = interactive
        self._resolver = None
        self.processed = {}   # det_bytes -> outcome string (the once-per-DET gate)

    def _get_resolver(self):
        if self._resolver is None:
            import identity_lookup
            self._resolver = identity_lookup.DnsPythonResolver(server=self.dns_server)
        return self._resolver

    def consider(self, det_bytes):
        """Called by the keyring on a miss. Returns the public key if the DET
        ended up trusted (added), else None. Does the lookup at most once."""
        det_bytes = bytes(det_bytes)
        if det_bytes in self.processed:
            return self.keyring._by_det.get(det_bytes)   # added earlier, or None

        import identity_lookup
        shown = _det_str(det_bytes)
        print(f"\n[DNS] DET {shown} is NOT in the trusted-identities file.")
        try:
            r = identity_lookup.lookup_det(det_bytes, self._get_resolver())
        except Exception as e:
            print(f"[DNS] lookup could not run: {e}")
            self.processed[det_bytes] = "dns-error"
            return None

        if r.error:
            print(f"[DNS] no identity found in DNS: {r.error}")
            self.processed[det_bytes] = "not-in-dns"
            return None

        print(f"[DNS] found: fqdn={r.fqdn}  mfg={r.mfg}  sn={r.sn}  "
              f"model={r.model}  reg_status={r.reg_status}")
        if r.binding_ok is True:
            print(f"[DNS] DET<->key binding VERIFIED (RFC 9374 3.5.2).")
        elif r.binding_ok is False:
            # Say it plainly; do NOT offer to add.
            print(f"[DNS] DET<->key binding FAILED (E-DET-02): the key published "
                  f"in DNS does not derive this DET. NOT offering to add it to "
                  f"the trust file - it is not trustworthy.")
            self.processed[det_bytes] = "binding-failed"
            return None
        else:
            print(f"[DNS] no usable key in the DNS record "
                  f"({r.pubkey_error or 'no key'}); cannot verify. Not adding.")
            self.processed[det_bytes] = "no-key"
            return None

        # binding verified. The DNS key is already in hand (no further lookup).
        # Offer THREE choices, since verifying and persisting are separate acts:
        #   w = write to the trust file AND use the key this run
        #   t = use the key THIS RUN ONLY (verify these messages) - no file write
        #   n = ignore - do not verify, skip for the rest of the run
        if not self.interactive:
            # Non-interactive: verify this run using the DNS key (safe - it was
            # binding-checked), but never write the file unattended.
            self.keyring.add(det_bytes, r.pubkey)
            print(f"[DNS] (--dns-fallback non-interactive: verifying this run "
                  f"with the DNS key; not writing to {self.anchor})")
            self.processed[det_bytes] = "verified-this-run"
            return r.pubkey
        try:
            ans = input(f"[DNS] DET {shown} verified via DNS. "
                        f"[w]rite to {self.anchor}, [t]rust this run only, "
                        f"or [n]o? [w/t/N] ").strip().lower()
        except EOFError:
            ans = ""

        if ans in ("w", "write", "y", "yes"):
            ok, msg = _dns_write_ua_entry(self.anchor, r.det, r.pubkey,
                                          r.reg_status, r.mfg, r.sn, r.model)
            print(f"[DNS] {msg}")
            if ok:
                self.keyring.add(det_bytes, r.pubkey)   # trusted for rest of run
                self.processed[det_bytes] = "added"
                return r.pubkey
            self.processed[det_bytes] = "write-failed"
            return None
        elif ans in ("t", "trust", "run"):
            # Verify this run only. Uses the key ALREADY fetched above - no second
            # DNS query. Nothing is written to disk.
            self.keyring.add(det_bytes, r.pubkey)
            print(f"[DNS] trusting for THIS RUN only; {self.anchor} not modified.")
            self.processed[det_bytes] = "trusted-this-run"
            return r.pubkey
        else:
            print(f"[DNS] not trusted; ignoring this DET for the rest of the run.")
            self.processed[det_bytes] = "declined"
            return None

    def report(self):
        """End-of-run summary of every untrusted DET that was consulted."""
        if not self.processed:
            return
        print("\nDNS fallback summary (untrusted DETs this run):")
        for d, outcome in self.processed.items():
            print(f"  {_det_str(d):40s}  {outcome}")


class Keyring:
    """Maps a DET to the public key that must have signed for it.

    A --pubkey supplied on the command line is kept as a WILDCARD: it applies to
    any DET with no explicit entry. That preserves the historical behaviour for
    a single unknown drone, while named DET->key entries always win.
    """

    def __init__(self):
        self._by_det = {}
        self._wildcard = None
        self.fallback = None    # optional DnsFallback, consulted on a miss

    def add(self, det_bytes, pub):
        self._by_det[bytes(det_bytes)] = bytes(pub)

    def set_wildcard(self, pub):
        self._wildcard = bytes(pub)

    def for_det(self, det_bytes):
        if det_bytes is None:
            return self._wildcard
        hit = self._by_det.get(bytes(det_bytes))
        if hit is not None:
            return hit
        # Miss: if a DNS fallback is armed, consult it (once per DET). It may add
        # the key to this keyring, in which case we return it now.
        if self.fallback is not None:
            added = self.fallback.consider(det_bytes)
            if added is not None:
                return added
        return self._wildcard

    def __len__(self):
        return len(self._by_det)

    def __bool__(self):
        return bool(self._by_det) or self._wildcard is not None


def default_keyring(anchor="hierarchy.json"):
    """Build the keyring from the trusted-identities file (single source of
    truth). Returns an empty keyring if the file is missing or unreadable, so
    the observer still runs (it just has no keys to verify against)."""
    kr = Keyring()
    try:
        import identity_resolve
        trust = identity_resolve.load_trust(anchor)
        for d_hex, p_hex, _label in identity_resolve.iter_known_keys(trust):
            kr.add(bytes.fromhex(d_hex), bytes.fromhex(p_hex))
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"WARNING: could not load keys from {anchor}: {e}")
    return kr


def _det_str(det_bytes):
    try:
        return str(ipaddress.IPv6Address(bytes(det_bytes)))
    except Exception:
        return bytes(det_bytes).hex()


def check_det_binding(det_bytes, keys, where, findings):
    """E-DET-02: re-derive the DET from the public key and compare (RFC 9374)."""
    if not HAVE_DET:
        return
    # A caller that passes NO keyring is not asking for key-based checks, and
    # must stay silent exactly as before. A keyring that simply lacks THIS DET
    # is a different thing entirely - that is E-KEY-01.
    if keys is None:
        return
    pub = keys.for_det(det_bytes)
    if pub is None:
        # Previously a silent `return`. Silence read as "checked, fine" when it
        # actually meant "never checked".
        findings.append(Finding("E-KEY-01", where, _det_str(det_bytes)))
        return
    try:
        if not det.verify_det_binding(det_bytes, pub):
            findings.append(Finding("E-DET-02", where, _det_str(det_bytes)))
    except Exception as e:
        findings.append(Finding("E-DET-02", where, f"check error: {e}"))


def check_wrapper_signature(auth, decoded_msgs, keys, where, findings):
    """E-SIG-01: verify a DRIP Wrapper (Extended Transport) Ed25519 signature.

    RFC 9575 §4.3.2 + §4.1 Fig 4. The signed bytes are rebuilt as:
        VNB(4) || VNA(4) || Evidence || UA_DET(16)
    where VNB/VNA are the RAW wire bytes (little-endian, not re-encoded, to
    avoid any endianness ambiguity) and Evidence is reconstructed from the
    pack's non-Auth messages (see odid.reconstruct_wrapper_evidence).

    On-wire SAM data (Evidence cleared) = VNB(4)|VNA(4)|DET(16)|Sig(64) = 88 B.
    """
    if not HAVE_ED:
        return
    # A caller that passes NO keyring is not asking for key-based checks, and
    # must stay silent exactly as before. A keyring that simply lacks THIS DET
    # is a different thing entirely - that is E-KEY-01.
    if keys is None:
        return
    if auth.get("auth_type") != 5 or auth.get("sam_type") != 0x02:
        return  # only DRIP Wrapper
    sam = auth.get("sam_data", b"")
    if len(sam) < 88:
        findings.append(Finding("E-SIG-01", where, f"wrapper payload too short ({len(sam)} B)"))
        return
    vnb_bytes = sam[0:4]
    vna_bytes = sam[4:8]
    det_bytes = sam[8:24]
    sig       = sam[24:88]
    # Key selection is driven by the DET carried INSIDE the Wrapper, so each UA
    # in a fleet is checked against its own key.
    pub = keys.for_det(det_bytes)
    if pub is None:
        findings.append(Finding("E-KEY-01", where, _det_str(det_bytes)))
        return
    evidence  = odid.reconstruct_wrapper_evidence(decoded_msgs)
    signed    = vnb_bytes + vna_bytes + evidence + det_bytes
    try:
        if not ed25519_backend.verify(pub, signed, sig):
            findings.append(Finding("E-SIG-01", where,
                                    f"{len(evidence)//25} msg(s) in evidence"))
    except Exception as e:
        findings.append(Finding("E-SIG-01", where, f"verify error: {e}"))


# ---------------------------------------------------------------------------
#  Processing
# ---------------------------------------------------------------------------
def process_pack(pack_bytes, where, keys, findings, report, now=None, max_age=None,
                 mac=None):
    pack = odid.split_pack(pack_bytes)
    report.append((where, {"_pack_raw": bytes(pack_bytes)}))   # for Manifest pack-hash cross-check
    validate_pack(pack, where, findings)
    decoded = [odid.decode_message(m) for m in pack.get("messages_raw", [])]
    for idx, d in enumerate(decoded):
        w = f"{where} msg[{idx}]"
        # Synthetic field, same convention as _pack_raw / _auth. Only Format A
        # (air capture) has a MAC at all; the serial/hex formats do not.
        if mac is not None:
            d["_mac"] = mac
        validate_message(d, w, findings)
        report.append((w, d))
        if d.get("type") == 0x0 and d.get("det") is not None:
            check_det_binding(d["det"], keys, w, findings)

    auths = odid.reassemble_auth(decoded)
    for auth in auths:
        w = f"{where} auth@msg[{auth['start_index']}]"
        validate_auth(auth, w, findings, now=now, max_age=max_age)
        check_wrapper_signature(auth, decoded, keys, w, findings)
        report.append((w, {"_auth": auth}))

    # semantic: DRIP auth present but no DRIP Basic ID in the same pack
    has_drip_auth = any(a["auth_type"] == 5 and a["sam_type"] in odid.SAM_TYPES for a in auths)
    has_drip_bid = any(d.get("type") == 0x0 and d.get("det") is not None for d in decoded)
    if has_drip_auth and not has_drip_bid:
        findings.append(Finding("E-SEM-01", where))


def process_payload(payload, where, keys, findings, report, now=None, max_age=None,
                    mac=None):
    """payload = a Message Pack (first nibble 0xF) or a single 25-byte message."""
    if not payload:
        return
    if (payload[0] >> 4) == 0xF:
        process_pack(payload, where, keys, findings, report, now=now, max_age=max_age,
                     mac=mac)
    else:
        d = odid.decode_message(payload[:odid.MSG_LEN])
        validate_message(d, where, findings)
        report.append((where, d))
        if d.get("type") == 0x0 and d.get("det") is not None:
            check_det_binding(d["det"], keys, where, findings)


def verify_link_chain(bes, findings, now=None):
    """Verify a set of DRIP Link Broadcast Endorsements (RFC 9575 §4.2 / §6.4.2).

    For each unique BE:
      E-LINK-01  child DET must bind to child HI (cSHAKE128, via det.py)
      E-LINK-04  BE must be within its VNB..VNA window (only if `now` given)
      resolve the parent's HI: either the trust anchor (APEX) or the HI carried
        as the child of a higher BE (det_child == this det_parent)
      E-LINK-03  if no parent HI can be resolved -> chain broken
      E-LINK-02  parent signature over the 72-byte signed region must verify
    """
    if not (HAVE_DET and HAVE_ED) or not bes:
        return
    by_child = {be["det_child"]: be for be in bes}     # child DET -> its endorsement
    for be in bes:
        w = f"Link BE child={ipaddress.IPv6Address(be['det_child'])}"

        # E-LINK-01: child DET <-> child HI binding
        try:
            if not det.verify_det_binding(be["det_child"], be["hi_child"]):
                findings.append(Finding("E-LINK-01", w))
        except Exception as e:
            findings.append(Finding("E-LINK-01", w, f"binding error: {e}"))

        # E-LINK-04: validity window (only when a reference time is supplied)
        #
        # UNITS. decode_link_sam() returns vnb/vna as RAW DRIP-epoch seconds
        # (seconds since 2019-01-01); it does NOT add EPOCH_2019. But `now` is
        # a UNIX timestamp - that is what --now is documented as, and what
        # validate_auth() compares against auth["timestamp_unix"]. Comparing the
        # two directly put `now` in the year 2075, so E-LINK-04 fired on every
        # endorsement whenever a reference time was supplied.
        #
        # This stayed hidden because --now defaults to None, which skips the
        # check entirely. It surfaced as soon as the real-time observer began
        # passing an actual clock. Convert to the DRIP epoch before comparing.
        if now is not None:
            now_drip = now - odid.EPOCH_2019
            if not (be["vnb"] <= now_drip <= be["vna"]):
                findings.append(Finding("E-LINK-04", w,
                                        f"vnb={be['vnb']} vna={be['vna']} "
                                        f"now={now_drip:.0f} (DRIP epoch)"))

        # resolve parent HI: trust anchor, or the child-HI of the next BE up
        if be["det_parent"] == APEX_DET:
            parent_hi = APEX_HI
        elif be["det_parent"] in by_child:
            parent_hi = by_child[be["det_parent"]]["hi_child"]
        else:
            findings.append(Finding("E-LINK-03", w,
                f"no parent/anchor for det_parent={ipaddress.IPv6Address(be['det_parent'])}"))
            continue

        # E-LINK-02: parent signature over VNB|VNA|DET_child|HI_child|DET_parent
        if not ed25519_backend.verify(parent_hi, be["signed_region"], be["sig"]):
            findings.append(Finding("E-LINK-02", w))


def _collect_link_bes(report):
    """Extract unique DRIP Link BEs (SAM type 0x01) from the decoded report."""
    seen = set()
    bes = []
    for _w, d in report:
        a = d.get("_auth")
        if not a or a.get("sam_type") != 0x01:
            continue
        be = odid.decode_link_sam(a.get("sam_data", b""))
        if be is None:
            continue
        key = be["det_child"] + be["det_parent"] + be["sig"]
        if key in seen:
            continue
        seen.add(key)
        bes.append(be)
    return bes


def _man_hash8(data):
    """cSHAKE128(data, 64 bits, N='', S='Remote ID Auth Hash') -> 8 bytes (RFC 9575 §4.4.3)."""
    return det.cshake128(bytes(data), 8, N=b'', S=MAN_HASH_CS)


def _collect_manifests(report):
    """Unique DRIP Manifests (SAM 0x03) in report order."""
    seen, out = set(), []
    for w, d in report:
        a = d.get("_auth")
        if not a or a.get("sam_type") != 0x03:
            continue
        m = odid.decode_manifest_sam(a.get("sam_data", b""))
        if m is None:
            continue
        key = bytes(a["sam_data"])
        if key in seen:
            continue
        seen.add(key)
        out.append((w, m))
    return out


def _collect_pack_hashes(report):
    """Hash every observed Message Pack (RFC 9575 §4.4.3.2: full pack, no counter)."""
    return {_man_hash8(d["_pack_raw"]) for _w, d in report if "_pack_raw" in d}


def _collect_link_hashes(report):
    """Hash every observed DRIP Link full SAM (0x01 || sam_data), as the firmware does."""
    hs = set()
    for _w, d in report:
        a = d.get("_auth")
        if a and a.get("sam_type") == 0x01:
            hs.add(_man_hash8(bytes([0x01]) + bytes(a.get("sam_data", b""))))
    return hs


def collect_identities(report, keys=None):
    """Group everything observed by DRIP identity.

    Keyed on the DET, not the MAC: the DET *is* the identity (RFC 9374 §3.5.2
    binds it to a key). The MAC is only the radio that carried it, and ASTM
    F3411-22a §5.4.5.6 NOTE 2 explicitly permits a UA using Specific Session ID
    Type (which DRIP is, ID Type 4) to rotate MACs for privacy. So "how many
    drones are in the air" = how many distinct DETs.
    """
    ids = {}

    def slot(det_b):
        return ids.setdefault(bytes(det_b), {
            "macs": set(), "packs": 0, "wrap": set(), "man": set(), "key": None})

    # Basic ID messages -> DET, MAC, pack count
    for w, d in report:
        if d.get("type") == 0x0 and d.get("det"):
            e = slot(d["det"])
            e["packs"] += 1
            if d.get("_mac"):
                e["macs"].add(d["_mac"])

    # Wrapper signatures (unique), keyed by the DET inside the SAM
    for w, d in report:
        a = d.get("_auth")
        if not a or a.get("auth_type") != 5 or a.get("sam_type") != 0x02:
            continue
        sam = a.get("sam_data", b"")
        if len(sam) < 88:
            continue
        slot(sam[8:24])["wrap"].add(bytes(sam[24:88]))

    # Manifest signatures (unique)
    for w, m in _collect_manifests(report):
        if m.get("det"):
            slot(m["det"])["man"].add(bytes(m["sig"]))

    if keys is not None:
        for det_b, e in ids.items():
            e["key"] = keys.for_det(det_b)
    return ids


def report_identities(ids, findings):
    """Print the identity table and raise W-MAC-02 where warranted."""
    print(f"\nIdentities observed: {len(ids)} drone(s)")
    if not ids:
        return
    label_of = {}
    try:
        import identity_resolve
        trust = identity_resolve.load_trust("hierarchy.json")
        for d, _p, lbl in identity_resolve.iter_known_keys(trust):
            label_of[bytes.fromhex(d)] = lbl.split("(")[0].split("-")[0].strip()
    except Exception:
        pass
    print(f"\n  {'#':<3}{'DET':<40} {'MAC(s)':<20} {'packs':>6}  {'key':<10} auth")
    for i, (det_b, e) in enumerate(sorted(ids.items(), key=lambda kv: -kv[1]["packs"]), 1):
        macs = sorted(e["macs"]) or ["(n/a)"]
        keylab = label_of.get(det_b, "keyring" if e["key"] else "-")
        if e["key"] is None:
            auth = "NO KEY - not verified"
        else:
            auth = f"OK  ({len(e['wrap'])} wrap, {len(e['man'])} man)"
        print(f"  {i:<3}{_det_str(det_b):<40} {macs[0]:<20} {e['packs']:>6}  {keylab:<10} {auth}")
        for extra in macs[1:]:
            print(f"  {'':<3}{'':<40} {extra:<20}")
        # W-MAC-02: NOT an ASTM violation (see errors.py) — a bench expectation.
        if len(e["macs"]) > 1:
            findings.append(Finding("W-MAC-02", _det_str(det_b),
                                    f"{len(e['macs'])} MACs: {', '.join(macs)}"))
    # One MAC carrying several DETs is visible above as rows sharing a MAC.
    # It is NOT covered by NOTE 2 and is the more serious case, but a validator
    # for it is a separate, un-approved stage.


def verify_manifests(report, findings, keys=None, now=None):
    """Verify DRIP Manifests (RFC 9575 §4.4). Cross-checks against packs/links
       observed elsewhere in the same capture; chains manifests by Prev/Curr."""
    if not HAVE_DET:
        return
    mans = _collect_manifests(report)
    if not mans:
        return
    pack_hashes = _collect_pack_hashes(report)
    link_hashes = _collect_link_hashes(report)
    # ------------------------------------------------------------------
    # FLEET FIX: the Manifest hash chain is PER UA (RFC 9575 4.4.2) — each
    # aircraft maintains its own Prev/Curr ledger. This used to walk ONE global
    # cursor over every manifest in the capture, which is right for one drone
    # and wrong for several: with 3 UAs interleaved it compares drone 0's Curr
    # against drone 1's Prev and reports E-MAN-04 on essentially every manifest.
    # The chain is now tracked per DET. (decode_manifest_sam already returns the
    # UA DET, so no new decoding is needed.)
    # ------------------------------------------------------------------
    prev_by_det = {}
    for w, m in mans:
        det_b = m.get("det")
        pub = keys.for_det(det_b) if keys is not None else None
        # E-MAN-01: UA signature over VNB|VNA|Evidence|DET — with THIS UA's key
        # keys is None => caller did not ask for signature checks (silent).
        if HAVE_ED and keys is not None and pub is None:
            findings.append(Finding("E-KEY-01", w, _det_str(det_b)))
        elif HAVE_ED and pub and not ed25519_backend.verify(pub, m["signed_region"], m["sig"]):
            findings.append(Finding("E-MAN-01", w))
        # E-MAN-05: self-hash = cSHAKE128(Prev | null | Link | ASTM hashes)
        calc = _man_hash8(m["prev"] + b"\x00" * 8 + m["link_hash"] + b"".join(m["astm_hashes"]))
        if calc != m["curr"]:
            findings.append(Finding("E-MAN-05", w, f"curr={m['curr'].hex()} calc={calc.hex()}"))
        # E-MAN-02: each ASTM (pack) hash must match an observed pack
        for h in m["astm_hashes"]:
            if h not in pack_hashes:
                findings.append(Finding("E-MAN-02", w, f"unmatched pack hash {h.hex()}"))
        # E-MAN-03: link hash must match an observed BE:HDA,UA
        if m["link_hash"] not in link_hashes:
            findings.append(Finding("E-MAN-03", w, f"unmatched link hash {m['link_hash'].hex()}"))
        # E-MAN-04: chain, PER UA (skip the first manifest of each UA, whose
        # Prev is that drone's seed nonce)
        prev_curr = prev_by_det.get(det_b)
        if prev_curr is not None and m["prev"] != prev_curr:
            findings.append(Finding("E-MAN-04", w,
                                    f"prev={m['prev'].hex()} expected={prev_curr.hex()}"))
        prev_by_det[det_b] = m["curr"]


class UnknownFormatError(Exception):
    """No parser recognised the input. Raised instead of guessing."""


# Populated by run() for Format A; read by print_report(). Kept module-level so
# run() can keep returning exactly 3 values (make_vectors.py unpacks 3).
capture_health = {}


def run(text, keys=None, now=None, max_age=None, pub=None, progress=False):
    """Decode + validate `text`. Returns (format_label, report, findings).

    `pub` is a BACK-COMPAT shim for callers that predate the keyring
    (make_vectors.py passes pub=UA_PUB). A bare key means "apply this to any
    DET", which is exactly a wildcard entry -- so it is wrapped into one rather
    than being a second code path that could drift.

    Auto-detects Format L (ESP32 serial log), Format A (DRIP_Sniffer air
    capture), Format W (Wireshark bytes export) or Format B (flat hex).

    Raises UnknownFormatError if none of them match.

    Every branch is now a POSITIVE test. Format B used to be the unconditional
    `else`, so an unrecognised file was DECLARED to be flat hex and decoded
    anyway. Handed an air capture, that turned a flawless 555-frame file into
    10157 findings and read as "your firmware is broken" -- a wrong answer
    delivered confidently, which is worse than no answer.
    """
    if pub is not None and keys is None:
        keys = Keyring()
        keys.set_wildcard(pub)

    findings = []
    report = []
    capture_health.clear()
    if odid.looks_like_format_l(text):
        fmt = "L (ESP32 serial log)"
        for entry in odid.parse_format_l(text):
            where = (f"tx[{entry['tx_cnt']:#04x}] "
                     f"cnt=0x{entry['counter']:02X} "
                     f"cycle={entry['cycle']}")
            process_payload(entry["pack_bytes"], where, keys,
                            findings, report, now=now, max_age=max_age)
    elif odid.looks_like_format_a(text):
        fmt = "A (air capture - DRIP_Sniffer)"
        a_frames, a_damaged = odid.parse_format_a(text)
        # A frame whose byte count contradicts the sniffer's own '#F len='
        # never arrived intact. It cannot testify about the drone that sent it,
        # so it is reported as capture damage rather than decoded into
        # DRIP "violations" that are really serial byte loss.
        for meta, got in a_damaged:
            findings.append(Finding("W-CAP-01", "capture",
                                    f"declared len={meta.get('len')}, got {got} B"))
        capture_health["frames"] = len(a_frames) + len(a_damaged)
        capture_health["damaged"] = len(a_damaged)
        for fi, (meta, frame) in enumerate(a_frames):
            ie = odid.extract_drip_ie(frame)
            if ie is None:
                continue          # e.g. a frame truncated when capture stopped
            hdr = odid.parse_mac_header(frame)
            # The transmitter MAC goes in the label so every finding is
            # attributable when several drones are on the air. It is NOT yet
            # validated against the DET -- that is a later stage.
            tag = odid.mac_str(hdr["addr2"]) if hdr else "??:??:??:??:??:??"
            where = f"frame[{fi}] {tag} cnt=0x{ie['counter']:02X}"
            process_payload(ie["payload"], where, keys, findings, report,
                            now=now, max_age=max_age, mac=tag)
            if progress and fi and fi % 2000 == 0:
                print(f"# {fi} frames...", file=sys.stderr, flush=True)
    elif odid.looks_like_format_w(text):
        fmt = "W (Wireshark bytes export)"
        for fi, frame in enumerate(odid.parse_format_w(text)):
            ie = odid.extract_drip_ie(frame)
            if ie is None:
                continue
            where = f"frame[{fi}] cnt=0x{ie['counter']:02X}"
            process_payload(ie["payload"], where, keys, findings, report, now=now, max_age=max_age)
    elif odid.looks_like_format_b(text):
        fmt = "B (flat hex)"
        for ri, (rec, _expect) in enumerate(odid.parse_format_b(text)):
            process_payload(rec, f"record[{ri}]", keys, findings, report, now=now, max_age=max_age)
    else:
        raise UnknownFormatError(odid.diagnose_format(text))

    # DRIP Link chain of trust: gather all unique Link BEs and verify the chain
    verify_link_chain(_collect_link_bes(report), findings, now=now)
    # DRIP Manifest verification: signature, self-hash, pack/link cross-check, chaining
    verify_manifests(report, findings, keys=keys, now=now)
    return fmt, report, findings


# ---------------------------------------------------------------------------
#  Reporting
# ---------------------------------------------------------------------------
def _fmt_msg_line(where, d):
    if "_auth" in d:
        a = d["_auth"]
        sam = a.get("sam_name") or (f"0x{a['sam_type']:02X}" if a["sam_type"] is not None else "?")
        return (f"  {where}: Auth reassembled  type={a['auth_type']} "
                f"pages={a['pages_present']} len={a['length']} "
                f"SAM={sam} complete={a['complete']}")
    t = d.get("type_name", "?")
    extra = ""
    if d.get("type") == 0x0 and d.get("det_ipv6"):
        extra = f"  DET={d['det_ipv6']}"
    elif d.get("type") == 0x3:
        extra = f"  desc='{d.get('description','')}'"
    elif d.get("type") == 0x5:
        extra = f"  op='{d.get('operator_id','')}'"
    elif d.get("type") == 0x4:
        extra = f"  lat={d.get('operator_lat'):.5f} lon={d.get('operator_lon'):.5f}"
    return f"  {where}: {t}{extra}"


def print_report(fmt, report, findings, verbose=False, keys=None):
    print(f"Input format: {fmt}")
    msg_items = [(w, d) for w, d in report if "_pack_raw" not in d]
    print(f"DRIP payloads decoded: {len({w.split(' msg')[0].split(' auth')[0] for w, _ in msg_items})}")
    print(f"Decoded items: {len(msg_items)}")
    if not HAVE_DET:
        print("(note: det.py not importable - DET<->key binding check disabled)")

    # message-type histogram
    hist = Counter()
    for _w, d in msg_items:
        if "_auth" in d:
            hist["Authentication (reassembled)"] += 1
        else:
            hist[d.get("type_name", "?")] += 1
    print("\nMessage-type counts:")
    for name, c in hist.most_common():
        print(f"  {c:6d}  {name}")

    if verbose:
        print("\nDecoded items:")
        for w, d in msg_items:
            print(_fmt_msg_line(w, d))

    # Capture health, printed BEFORE the identity table: if the capture itself
    # is damaged, that context has to arrive before any finding is read.
    if capture_health.get("frames"):
        tot = capture_health["frames"]; dmg = capture_health["damaged"]
        pct = 100.0 * (tot - dmg) / tot
        print(f"\nCapture health: {tot - dmg:,}/{tot:,} frames intact ({pct:.2f}%)")
        if dmg:
            print(f"  {dmg} frame(s) DISCARDED - damaged in the capture pipeline "
                  f"(serial byte loss), not on the air.")
            print(f"  These are W-CAP-01, not DRIP defects. Findings from the "
                  f"surrounding frames may be collateral.")

    # Identity report. Raises W-MAC-02, so it must run before findings are
    # grouped for printing.
    idents = collect_identities(report, keys=keys)
    report_identities(idents, findings)

    # ---- findings grouped by DET (which drone) ----------------------------
    # Answers "which identity do these findings belong to". A finding is linked
    # to a DET by either (a) its detail string being that DET, or (b) a MAC in
    # its `where` that the identity table maps to that DET. Findings with no DET
    # link (format/pack-level) are bucketed as "unattributed".
    if findings:
        det_strs = {_det_str(db): db for db in idents}          # "2001:.." -> bytes
        mac_to_det = {}                                         # "aa:bb.." -> det str
        for db, e in idents.items():
            for mac in e["macs"]:
                mac_to_det[str(mac).lower()] = _det_str(db)

        def det_of(f):
            # (a) DET appears verbatim in the detail
            if f.detail:
                for ds in det_strs:
                    if ds in f.detail:
                        return ds
            # (b) a known MAC appears in the location string
            w = (f.where or "").lower()
            for mac, ds in mac_to_det.items():
                if mac in w:
                    return ds
            return None

        per_det = defaultdict(lambda: defaultdict(int))         # detstr -> {eid: count}
        unattributed = defaultdict(int)
        for f in findings:
            ds = det_of(f)
            if ds is None:
                unattributed[f.error_id] += 1
            else:
                per_det[ds][f.error_id] += 1

        print("\nFindings by DET:")
        # Show every observed identity, even those with 0 findings (so a trusted
        # drone visibly contributes nothing).
        for db, e in sorted(idents.items(), key=lambda kv: -kv[1]["packs"]):
            ds = _det_str(db)
            counts = per_det.get(ds, {})
            total = sum(counts.values())
            keylab = "trusted" if e["key"] else "NO KEY"
            macs = ",".join(sorted(str(m) for m in e["macs"])) or "(n/a)"
            print(f"  {ds}  [{keylab}]  {total} finding(s)")
            if counts:
                brk = ", ".join(f"{eid} x{n}" for eid, n in sorted(counts.items()))
                print(f"        {brk}")
        if unattributed:
            tot = sum(unattributed.values())
            brk = ", ".join(f"{eid} x{n}" for eid, n in sorted(unattributed.items()))
            print(f"  (unattributed - format/pack level)  {tot} finding(s)")
            print(f"        {brk}")

    # findings grouped by error id
    print("\nFindings:")
    if not findings:
        print("  (none)")
    else:
        by_id = defaultdict(list)
        for f in findings:
            by_id[f.error_id].append(f)
        for eid in sorted(by_id):
            desc, constraint = ERROR_CATALOG.get(eid, ("?", ""))
            items = by_id[eid]
            print(f"  {eid}  x{len(items)}  {desc}")
            print(f"          constraint: {constraint}")
            for f in items[:5 if not verbose else len(items)]:
                print(f"          - @ {f.where}" + (f"  ({f.detail})" if f.detail else ""))
            if not verbose and len(items) > 5:
                print(f"          - ... and {len(items) - 5} more")
    print(f"\nTotal findings: {len(findings)}")


# ---------------------------------------------------------------------------
#  --resolve : single-DET resolution against the trusted-identities file.
#
#  This is Step 1 of the identity-resolution feature. It is OFFLINE and makes no
#  network/DNSSEC query. It reports a LAYERED verdict (structure / allow-list /
#  crypto) and never prints a bare "VALID". See identity_resolve.py.
# ---------------------------------------------------------------------------
def _parse_det_arg(s):
    """Accept a DET as 32 hex chars OR the colonful IPv6 form. Returns 16 bytes."""
    s = s.strip()
    if ":" in s:
        return ipaddress.IPv6Address(s).packed
    h = s.replace(" ", "")
    if len(h) != 32:
        raise ValueError(f"DET must be 32 hex chars (16 bytes) or IPv6 form; "
                         f"got {len(h)} chars")
    return bytes.fromhex(h)


def _cmd_resolve(det_arg, anchor_path):
    try:
        import identity_resolve
    except Exception as e:
        print(f"ERROR: --resolve needs identity_resolve.py in this folder: {e}")
        return 2

    try:
        det_bytes = _parse_det_arg(det_arg)
    except ValueError as e:
        print(f"ERROR: {e}")
        return 2

    try:
        trust = identity_resolve.load_trust(anchor_path)
    except FileNotFoundError:
        print(f"ERROR: trusted-identities file not found: {anchor_path}")
        print("       (pass one with --anchor FILE)")
        return 2
    except ValueError as e:
        print(f"ERROR: {anchor_path}: {e}")
        return 2

    r = identity_resolve.resolve_det(det_bytes, trust)
    _print_resolution(r, anchor_path)
    # Exit non-zero if any finding fired (script-friendly), like the main path.
    return 0 if not r.findings else 1


def _print_resolution(r, anchor_path):
    """Human-readable layered verdict for one DET."""
    f = r.fields
    print(f"DET  {r.det_v6()}")
    print(f"     {r.det_hex()}")
    print(f"Trusted-identities file: {anchor_path}")
    print()
    # (a) structural decode — always available, key or no key.
    print("Decoded fields (RFC 9374 3.3):")
    print(f"  prefix : {f['prefix28']:07x}   ({'ok, 2001:30::/28' if r.prefix_ok else 'WRONG'})")
    print(f"  RAA    : {f['raa']}")
    print(f"  HDA    : {f['hda']}")
    print(f"  Suite  : {f['suite']}   ({'EdDSA/cSHAKE128' if f['suite'] == 5 else 'non-standard'})")
    print(f"  hash64 : {f['hash64'].hex().upper()}")
    print(f"  RAA /44 zone : {r.raa_zone}")
    print(f"  HDA /56 zone : {r.hda_zone}")
    print(f"  reverse FQDN : {r.fqdn}")
    print()

    if not r.prefix_ok:
        print("VERDICT: NOT A DET — prefix is not 2001:30::/28 (E-DET-01).")
        _print_findings(r)
        return

    # (b) allow-list, two levels.
    print("Trust (RFC 9886 6 delegation + local allow-list):")
    if r.raa_trusted:
        print(f"  RAA trusted : yes  (RAA {r.raa_trusted['raa']}, "
              f"DET {r.raa_trusted['det'].upper()})")
    else:
        print("  RAA trusted : no")
    if r.hda_trusted:
        print(f"  HDA trusted : yes  -> HDA_TRUSTED level "
              f"(HDA {r.hda_trusted['raa']}/{r.hda_trusted['hda']}, "
              f"DET {r.hda_trusted['det'].upper()})")
    else:
        print("  HDA trusted : no")
    if r.ua_enrolled:
        print("  UA enrolled : yes  -> UA_ENROLLED level "
              "(this exact DET is individually listed)")
    else:
        print("  UA enrolled : no   (not individually listed in 'ua')")
    print()

    # (c) crypto — only if a key is on file.
    print("DET<->key binding (RFC 9374 3.5.2):")
    if r.binding == "VERIFIED":
        print(f"  registered key : {r.registered_key.hex().upper()}")
        print("  binding        : VERIFIED  (key derives this DET)")
    elif r.binding == "MISMATCH":
        print(f"  registered key : {r.registered_key.hex().upper()}")
        print("  binding        : MISMATCH  (key does NOT derive this DET) — E-DET-02")
    else:  # NOT_CHECKED
        print("  registered key : none on file")
        print("  binding        : NOT CHECKED — no key registered for this DET (E-KEY-01)")
    print()

    # One-line plain-English summary, spelling out exactly what held. Never a
    # bare "VALID": the reader must be able to tell structure from crypto.
    claim = f"claims RAA={f['raa']}/HDA={f['hda']}"
    if r.binding == "VERIFIED":
        lvl = "individually enrolled" if r.ua_enrolled else "trusted via its HDA"
        print(f"SUMMARY: DET {r.det_hex()} {claim}, is on the allow-list "
              f"({lvl}), its zones nest, and its registered key VERIFIES the "
              f"binding.")
    elif r.on_allow_list:
        lvl = "individually enrolled" if r.ua_enrolled else "trusted via its HDA"
        if r.binding == "MISMATCH":
            print(f"SUMMARY: DET {r.det_hex()} {claim}, is on the allow-list "
                  f"({lvl}) and its zones nest, BUT the registered key does not "
                  f"derive this DET (binding MISMATCH — E-DET-02).")
        else:
            print(f"SUMMARY: DET {r.det_hex()} {claim}, is on the allow-list "
                  f"({lvl}) and its zones nest. No public key is registered for "
                  f"this DET, so the binding was not checked.")
    else:
        print(f"SUMMARY: DET {r.det_hex()} {claim}, but it is NOT on the "
              f"trusted-identities allow-list "
              f"({'zones do not nest either' if not r.nests else 'zones nest, but no trusted entry lists it'}).")

    _print_findings(r)


def _print_findings(r):
    if not r.findings:
        return
    print()
    print("Findings:")
    for eid, detail in r.findings:
        desc = ERROR_CATALOG.get(eid, ("(unknown)", ""))[0]
        print(f"  [{eid}] {desc}")
        if detail:
            print(f"         {detail}")


# ---------------------------------------------------------------------------
#  --dns-lookup : Step 2. Resolve a DET via DNS (PTR->TXT), verify the binding,
#  and offer to write the identity into the trusted-identities file.
#
#  DNSSEC here is PRESENCE-ONLY (mirrors the partner reference); it is reported
#  but never treated as authentication. See identity_lookup.py header.
# ---------------------------------------------------------------------------
def _dns_write_ua_entry(anchor_path, det_bytes, pubkey, reg_status, mfg, sn, model):
    """Append a resolved identity to the trust file's 'ua' array.

    Returns (ok, message). Refuses to CLOBBER: if the DET is already listed, it
    reports that and does not duplicate. Testable without any I/O prompt.
    """
    import json
    try:
        h = json.load(open(anchor_path, encoding="utf-8"))
    except FileNotFoundError:
        return False, f"trust file not found: {anchor_path}"
    except ValueError as e:
        return False, f"{anchor_path} is not valid JSON: {e}"

    det_hex = det_bytes.hex().upper()
    ua = h.setdefault("ua", [])
    for existing in ua:
        if existing.get("det", "").upper() == det_hex:
            return False, (f"DET {det_hex} is already in {anchor_path} — "
                           f"not modifying it")

    # RAA/HDA are carried in the DET itself (RFC 9374 3.3); record them so the
    # entry is self-describing and Step 1's nesting check can use them.
    if HAVE_DET:
        f = det.parse_det(det_bytes)
        raa, hda = f["raa"], f["hda"]
    else:
        raa = hda = None

    entry = {"det": det_hex}
    if raa is not None:
        entry["raa"] = raa
        entry["hda"] = hda
    if pubkey is not None:
        entry["public_key"] = pubkey.hex().upper()
    # Provenance: this came from DNS, not a hand-edit. reg_status/mfg/sn/model
    # are informational (the trust decision rests on the DET + key + nesting).
    role = f"from DNS ({mfg or '?'} {sn or ''}".strip() + ")"
    if reg_status:
        role += f" reg_status={reg_status}"
    entry["_role"] = role

    ua.append(entry)
    try:
        with open(anchor_path, "w", encoding="utf-8") as fh:
            json.dump(h, fh, indent=2)
            fh.write("\n")
    except OSError as e:
        return False, f"could not write {anchor_path}: {e}"
    return True, f"wrote DET {det_hex} into {anchor_path} 'ua' array"


def _cmd_dns_lookup(det_arg, anchor_path, dns_server):
    try:
        import identity_lookup
    except Exception as e:
        print(f"ERROR: --dns-lookup needs identity_lookup.py in this folder: {e}")
        return 2

    try:
        det_bytes = _parse_det_arg(det_arg)
    except ValueError as e:
        print(f"ERROR: {e}")
        return 2

    server = dns_server or identity_lookup.DEFAULT_DNS_SERVER
    print(f"DNS lookup for DET {det_bytes.hex().upper()}")
    print(f"  resolver: {server}")
    try:
        resolver = identity_lookup.DnsPythonResolver(server=server)
    except RuntimeError as e:
        print(f"ERROR: {e}")
        print("       Install it with:  pip install dnspython")
        return 2

    r = identity_lookup.lookup_det(det_bytes, resolver)
    return _finish_dns_lookup(r, anchor_path)


def _finish_dns_lookup(r, anchor_path):
    """Shared print + interactive-write path (also used by the mock tests)."""
    print(f"  DET   : {r.det_v6()}")
    if r.error and r.fqdn is None:
        print(f"  RESULT: lookup failed — {r.error}")
        return 1

    print(f"  FQDN  : {r.fqdn}")
    print()
    print("  TXT record:")
    print(f"    mfg        : {r.mfg}")
    print(f"    sn         : {r.sn}")
    print(f"    model      : {r.model}")
    print(f"    reg_status : {r.reg_status}")
    print(f"    pubkey     : {r.pubkey_b64}"
          f"{'' if not r.pubkey else '  (' + str(len(r.pubkey)) + ' bytes)'}")
    print()

    # DNSSEC — presence only, stated honestly.
    if r.dnssec_present:
        print("  DNSSEC : RRSIG present — NOT validated (presence-only; see docs)")
    else:
        print("  DNSSEC : no RRSIG in answer")

    # Binding — the check that actually matters for trust.
    if r.error:
        print(f"  BINDING: not checked — {r.error}")
    elif r.binding_ok is None:
        print("  BINDING: not checked — det.py unavailable")
    elif r.binding_ok:
        print("  BINDING: VERIFIED — the DNS key derives this DET (RFC 9374 3.5.2)")
    else:
        print("  BINDING: FAILED — the DNS key does NOT derive this DET (E-DET-02)")
    print()

    # Offer to write — but only when it is safe to.
    if r.binding_ok is not True:
        print("Not offering to save: the DET<->key binding did not verify, so "
              "this identity is not trustworthy. Nothing written.")
        return 1

    try:
        ans = input(f"Write this identity into {anchor_path}'s 'ua' array? [y/N] ")
    except EOFError:
        ans = ""
    if ans.strip().lower() in ("y", "yes"):
        ok, msg = _dns_write_ua_entry(anchor_path, r.det, r.pubkey,
                                      r.reg_status, r.mfg, r.sn, r.model)
        print(("OK: " if ok else "NOT WRITTEN: ") + msg)
        if ok:
            # Post-write coherence: re-load via the resolver and confirm it
            # parses + nests, so a bad append is caught immediately (your #2).
            try:
                import identity_resolve
                trust = identity_resolve.load_trust(anchor_path)
                res = identity_resolve.resolve_det(r.det, trust)
                if res.nests:
                    print("     verified: file still parses and the DET nests.")
                else:
                    print("     WARNING: written, but the DET does not nest under "
                          "a trusted RAA/HDA zone (E-ZONE-01). Check the file.")
            except Exception as e:
                print(f"     WARNING: could not re-verify the file: {e}")
        return 0 if ok else 1
    else:
        print("Not written.")
        return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Offline DRIP/ASTM observer")
    ap.add_argument("file", nargs="?",
                    help="capture file - Format L (ESP32 serial log), "
                         "A (DRIP_Sniffer air capture), W (Wireshark bytes) "
                         "or B (flat hex). Optional with --list-keys.")
    ap.add_argument("--pubkey", metavar="HEX",
                    help="32-byte Ed25519 public key (hex). Used for any DET that has no "
                         "keyring entry -- i.e. a single unknown drone.")
    ap.add_argument("--keyring", metavar="FILE",
                    help="file of 'DET_HEX PUBKEY_HEX' pairs, one per line ('#' comments "
                         "allowed). Adds to / overrides the built-in bench identities.")
    ap.add_argument("--no-builtin-keys", action="store_true",
                    help="do not preload the 3 known bench identities (slots 0-2)")
    ap.add_argument("--list-keys", action="store_true",
                    help="print the keyring and exit")
    ap.add_argument("--resolve", metavar="DET",
                    help="resolve a single DET (32 hex chars, or the colonful "
                         "IPv6 form) against the trusted-identities file "
                         "(--anchor, default hierarchy.json) and exit. Offline: "
                         "decodes the DET, checks zone nesting and allow-list "
                         "membership, and verifies the DET<->key binding IF a "
                         "key is on file. Does NOT touch the network (Step 1).")
    ap.add_argument("--dns-lookup", metavar="DET",
                    help="look up a DET in DNS (PTR->TXT) via the partner "
                         "resolver, verify the DET<->key binding, and offer to "
                         "write the identity into the trusted-identities file "
                         "(--anchor). NEEDS NETWORK + dnspython (Step 2).")
    ap.add_argument("--dns-server", metavar="IP", default=None,
                    help="resolver for --dns-lookup (default 141.227.148.117, "
                         "the partner's driplab.example server).")
    ap.add_argument("--dns-fallback", action="store_true",
                    help="while reading a capture, when a DET is NOT in the "
                         "trusted-identities file, look it up in DNS once, show "
                         "it, and offer to add it (writes to --anchor on yes). "
                         "One DNS query per untrusted DET per run. Needs network "
                         "+ dnspython. Off by default.")
    ap.add_argument("--anchor", metavar="FILE", default="hierarchy.json",
                    help="hierarchy.json holding the trust anchor (Apex DET + "
                         "public key). Absent = use the built-in bench anchor. "
                         "Swap in a real DNSSEC-anchored Apex here.")
    ap.add_argument("--pure-python", action="store_true",
                    help="force the ed25519.py reference implementation "
                         "(~1300x slower; use to cross-check a result)")
    ap.add_argument("--now", type=int, help="reference Unix time for freshness check")
    ap.add_argument("--max-age", type=int, help="max allowed |age| in seconds (with --now)")
    ap.add_argument("--verbose", action="store_true", help="print every decoded item")
    args = ap.parse_args(argv)

    # ---- build the keyring (single source of truth: the anchor file) -------
    # --no-builtin-keys now means "do not load the trusted-identities file";
    # only --keyring / --pubkey supply keys. Kept for the same use as before.
    keys = Keyring() if args.no_builtin_keys else default_keyring(args.anchor)

    if args.pubkey:
        if not HAVE_DET:
            print("ERROR: --pubkey was supplied but det.py could not be imported.")
            print("       Place det.py in the same folder as observer.py and retry.")
            return 2
        hexkey = args.pubkey.strip()
        if len(hexkey) != 64:
            print(f"ERROR: --pubkey must be 64 hex chars (32 bytes); got {len(hexkey)} chars.")
            return 2
        try:
            keys.set_wildcard(bytes.fromhex(hexkey))
        except ValueError as e:
            print(f"ERROR: --pubkey is not valid hex: {e}")
            return 2

    if args.keyring:
        try:
            with open(args.keyring, encoding="utf-8") as fh:
                for ln, line in enumerate(fh, 1):
                    t = line.split("#", 1)[0].split()
                    if not t:
                        continue
                    if len(t) != 2:
                        print(f"ERROR: {args.keyring}:{ln}: expected 'DET_HEX PUBKEY_HEX'")
                        return 2
                    d_hex, p_hex = t
                    if len(d_hex) != 32 or len(p_hex) != 64:
                        print(f"ERROR: {args.keyring}:{ln}: DET must be 32 hex chars "
                              f"and pubkey 64; got {len(d_hex)}/{len(p_hex)}")
                        return 2
                    keys.add(bytes.fromhex(d_hex), bytes.fromhex(p_hex))
        except OSError as e:
            print(f"ERROR: cannot read --keyring: {e}")
            return 2

    if args.resolve:
        return _cmd_resolve(args.resolve, args.anchor)

    if args.dns_lookup:
        return _cmd_dns_lookup(args.dns_lookup, args.anchor, args.dns_server)

    if args.list_keys:
        print(f"Keyring: {len(keys)} DET-bound key(s)"
              f"{' + 1 wildcard (--pubkey)' if keys.for_det(None) else ''}")
        # Labels come from the trusted-identities file (single source of truth).
        labels = {}
        try:
            import identity_resolve
            trust = identity_resolve.load_trust(args.anchor)
            for d_hex, _p, lbl in identity_resolve.iter_known_keys(trust):
                labels[bytes.fromhex(d_hex)] = lbl
        except Exception:
            pass
        for d in keys._by_det:
            lbl = labels.get(d, "(from --keyring)")
            print(f"  {_det_str(d):40s}  {lbl}")
            print(f"    key {keys.for_det(d).hex().upper()}")
        if keys.for_det(None):
            print(f"  {'(any other DET)':40s}  wildcard from --pubkey")
        return 0

    if not args.file:
        print("ERROR: no capture file given. (A file is optional only with --list-keys.)")
        return 2

    with open(args.file, encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    # Trust anchor first: everything downstream is verified against it.
    try:
        if load_hierarchy(args.anchor):
            print(f"Trust anchor: {ANCHOR_SOURCE}  "
                  f"apex={_det_str(APEX_DET)}")
        elif args.anchor != "hierarchy.json":
            print(f"ERROR: --anchor {args.anchor}: file not found")
            return 2
    except ValueError as e:
        print(f"ERROR: {e}")
        return 2

    if args.pure_python and HAVE_ED:
        ed25519_backend.force_pure_python()
    if HAVE_ED:
        print(f"Ed25519 backend: {ed25519_backend.backend_name()}")
        print(f"  self-test: {ed25519_backend.selftest_note()}")

    # Arm the once-per-DET DNS fallback if requested.
    dns_fb = None
    if args.dns_fallback:
        import sys as _sys
        server = args.dns_server or None
        try:
            import identity_lookup
            server = server or identity_lookup.DEFAULT_DNS_SERVER
        except Exception:
            pass
        dns_fb = DnsFallback(keys, args.anchor, server,
                             interactive=_sys.stdin.isatty())
        keys.fallback = dns_fb

    try:
        fmt, report, findings = run(text, keys=keys, now=args.now,
                                    max_age=args.max_age, progress=True)
    except UnknownFormatError as e:
        # Refuse rather than guess. See run()'s docstring.
        print(f"ERROR: {e}")
        return 2
    print_report(fmt, report, findings, verbose=args.verbose, keys=keys)
    if dns_fb is not None:
        dns_fb.report()
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
