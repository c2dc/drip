#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - identity_lookup.py
#  STEP 2: retrieve a drone's identity from DNS, given its DET.
#
#  Ports the DNS lookup from the researcher's Android reference
#  (org.securedroneid.android.data.AircraftObject.dnsLookup / parseTXTRecord)
#  to the Python observer: a DET seen on the air is resolved to the registered
#  identity (mfg, serial, model, reg_status, and the public key), and the
#  DET<->key binding verified locally.
#
#  TWO-HOP SCHEME (confirmed against live `dig`, 2026-07-18) - NOT RFC 9886 HIP-RR:
#    Hop 1 (PTR):  dig @141.227.148.117 -x <DET>
#        0.b.c.2...ip6.arpa. 86400 IN PTR snfr2025000123.driplab.example.
#    Hop 2 (TXT):  dig @141.227.148.117 TXT snfr2025000123.driplab.example.
#        ... IN TXT "mfg=...; sn=...; model=...; reg_status=...; pubkey=<base64>"
#
#  TXT FORMAT: key=value pairs split on ';' - matches parseTXTRecord field-for-
#  field (mfg, sn, model, reg_status, pubkey). pubkey = base64 of a 32-byte
#  Ed25519 key (their code rejects length != 32; so do we). 32 B => Suite 5.
#
#  DNSSEC - PRESENCE ONLY (DELIBERATE, MATCHES THE REFERENCE; NOT SAFE):
#    The Android reference sets dnssecValid=true just because an RRSIG is PRESENT
#    (AircraftObject ~line 286-288); it never validates it or chains to root. We
#    replicate that to match them, but report it as "dnssec_present", never
#    "valid". *** RRSIG-present is NOT RRSIG-validated; a forged answer with a
#    bogus RRSIG passes. Real validation (AD bit / RRSIG chain) is a later step.
#
#  PLUGGABLE RESOLVER: the live query needs a route to 141.227.148.117 (absent on
#  a locked build box). lookup_det() takes an injected Resolver:
#    DnsPythonResolver - real queries via dnspython (your machine)
#    MockResolver      - canned answers, for offline tests
#
#  SOURCES: DET<->key binding RFC 9374 3.5.2 (det.verify_det_binding); reverse
#  ip6.arpa. RFC 3596 2.5; TXT format = researcher's zone; DNS_SERVER default =
#  Constants.DNS_SERVER = "141.227.148.117".
# =============================================================================

import base64
import ipaddress

try:
    import det
    HAVE_DET = True
except Exception:
    HAVE_DET = False

# Default DNS server - traceable to Constants.DNS_SERVER. Override with --dns-server.
DEFAULT_DNS_SERVER = "141.227.148.117"

# TXT keys the researcher's zone publishes (AircraftObject.parseTXTRecord).
TXT_KEYS = ("mfg", "sn", "model", "reg_status", "pubkey")


def det_to_ptr_fqdn(det_bytes):
    """DET -> reverse ip6.arpa. name. Exactly what `dig -x <DET>` queries
    (verified against the live server's QUESTION SECTION).

    NOTE: the Android buildReversedIPv6() reversed the raw 32 hex CHARACTERS and
    appended 'ip6.arpa' with no trailing dot. That coincidentally yields the same
    labels (each hex char is a nibble) but is fragile; we build from the
    canonical 128-bit expansion and include the trailing dot."""
    addr = ipaddress.IPv6Address(bytes(det_bytes))
    nibbles = f"{int(addr):032x}"
    return ".".join(reversed(nibbles)) + ".ip6.arpa."


# ===========================================================================
#  Resolver interface + implementations.
# ===========================================================================
class Resolver:
    """DNS transport.
    query_ptr(name) -> {"target": <fqdn>, "rrsig": <bool>} or None
    query_txt(name) -> {"txt": <str>,     "rrsig": <bool>} or None
    'rrsig' = an RRSIG was PRESENT (not validated)."""
    def query_ptr(self, name):
        raise NotImplementedError

    def query_txt(self, name):
        raise NotImplementedError


class DnsPythonResolver(Resolver):
    """Real DNS via dnspython. Runs on the operator's machine.
    Mirrors SimpleResolver(Constants.DNS_SERVER) + DO bit set (RRSIGs returned
    when the zone is signed). dnspython is an OPTIONAL dependency, imported here
    at construction, so the module still loads (with MockResolver) without it."""
    def __init__(self, server=DEFAULT_DNS_SERVER, timeout=5.0):
        try:
            import dns.resolver
            import dns.rdatatype
            import dns.exception
        except Exception as e:
            raise RuntimeError("DnsPythonResolver needs dnspython: "
                               f"pip install dnspython (import failed: {e})")
        self.server = server
        self.timeout = timeout
        self._r = dns.resolver.Resolver(configure=False)
        self._r.nameservers = [server]
        self._r.lifetime = timeout
        # DO bit -> ask for DNSSEC RRSIGs. We do NOT enable validation; we only
        # observe RRSIG presence, like the reference. See the DNSSEC note above.
        self._r.use_edns(0, 0, 1232)

    def _query(self, name, rrtype):
        import dns.resolver, dns.exception, dns.rdatatype
        try:
            ans = self._r.resolve(name, rrtype, raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
                dns.resolver.NoAnswer, dns.exception.Timeout):
            return None, False
        if ans.rrset is None:
            return None, False
        rrsig_present = False
        try:
            for rr in ans.response.answer:
                if rr.rdtype == dns.rdatatype.RRSIG:
                    rrsig_present = True
                    break
        except Exception:
            pass
        return ans, rrsig_present

    def query_ptr(self, name):
        ans, sig = self._query(name, "PTR")
        if ans is None:
            return None
        target = str(ans[0].target) if hasattr(ans[0], "target") else str(ans[0])
        return {"target": target, "rrsig": sig}

    def query_txt(self, name):
        ans, sig = self._query(name, "TXT")
        if ans is None:
            return None
        rd = ans[0]
        try:
            txt = b"".join(rd.strings).decode("utf-8", "replace")
        except Exception:
            txt = str(rd).strip('"')
        return {"txt": txt, "rrsig": sig}


class MockResolver(Resolver):
    """Canned answers for offline testing.
    ptr : { "<reverse name>": ("<fqdn>", <rrsig_bool>) }
    txt : { "<fqdn>":         ("<txt>",  <rrsig_bool>) }
    Missing key -> None (NXDOMAIN / no answer)."""
    def __init__(self, ptr=None, txt=None):
        self.ptr = ptr or {}
        self.txt = txt or {}

    def query_ptr(self, name):
        v = self.ptr.get(name)
        return None if v is None else {"target": v[0], "rrsig": v[1]}

    def query_txt(self, name):
        v = self.txt.get(name)
        return None if v is None else {"txt": v[0], "rrsig": v[1]}


# ===========================================================================
#  TXT parsing - matches AircraftObject.parseTXTRecord field-for-field.
# ===========================================================================
def parse_txt_record(txt):
    """Parse 'mfg=...; sn=...; model=...; reg_status=...; pubkey=<base64>'.
    Returns the five keys (missing -> ""), plus 'pubkey_bytes' (32 raw bytes) or
    None, plus 'pubkey_error'. Unknown keys ignored, like the reference."""
    out = {k: "" for k in TXT_KEYS}
    out["pubkey_bytes"] = None
    out["pubkey_error"] = None

    cleaned = txt.replace('"', "").strip()
    for part in cleaned.split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k, v = k.strip(), v.strip()
        if k in out:
            out[k] = v

    if out["pubkey"]:
        try:
            raw = base64.b64decode(out["pubkey"], validate=True)
        except Exception as e:
            out["pubkey_error"] = f"base64 decode failed: {e}"
        else:
            if len(raw) != 32:
                out["pubkey_error"] = (f"public key is {len(raw)} bytes, "
                                       f"expected 32 (Ed25519 / Suite 5)")
            else:
                out["pubkey_bytes"] = raw
    return out


# ===========================================================================
#  Result object.
# ===========================================================================
class DnsIdentity:
    __slots__ = ("det", "ptr_name", "fqdn", "mfg", "sn", "model", "reg_status",
                 "pubkey", "pubkey_b64", "pubkey_error", "binding_ok",
                 "dnssec_present", "error")

    def __init__(self, det_bytes):
        self.det = bytes(det_bytes)
        self.ptr_name = det_to_ptr_fqdn(det_bytes)
        self.fqdn = None
        self.mfg = self.sn = self.model = self.reg_status = ""
        self.pubkey = None
        self.pubkey_b64 = ""            # the raw base64 string from the TXT record
        self.pubkey_error = None
        self.binding_ok = None          # None = not checked (no key / no det.py)
        self.dnssec_present = False     # presence only - NOT validated
        self.error = None

    def det_hex(self):
        return self.det.hex().upper()

    def det_v6(self):
        return str(ipaddress.IPv6Address(self.det))

    def pubkey_hex(self):
        return self.pubkey.hex().upper() if self.pubkey else None


# ===========================================================================
#  Entry point - the port of dnsLookup() + parseTXTRecord().
# ===========================================================================
def lookup_det(det_bytes, resolver):
    """Resolve a DET to its DNS identity via PTR -> TXT. Returns a DnsIdentity.
    Normal 'not found' cases are reported in result.error, not raised."""
    det_bytes = bytes(det_bytes)
    if len(det_bytes) != 16:
        raise ValueError("DET must be exactly 16 bytes")

    r = DnsIdentity(det_bytes)

    ptr = resolver.query_ptr(r.ptr_name)          # Hop 1: PTR (dig -x <DET>)
    if ptr is None:
        r.error = f"PTR lookup returned no answer for {r.ptr_name}"
        return r
    r.fqdn = ptr["target"]
    if ptr["rrsig"]:
        r.dnssec_present = True

    txt = resolver.query_txt(r.fqdn)              # Hop 2: TXT on the PTR target
    if txt is None:
        r.error = f"TXT lookup returned no answer for {r.fqdn}"
        return r
    if txt["rrsig"]:
        r.dnssec_present = True

    parsed = parse_txt_record(txt["txt"])
    r.mfg, r.sn, r.model, r.reg_status = (
        parsed["mfg"], parsed["sn"], parsed["model"], parsed["reg_status"])
    r.pubkey_b64 = parsed["pubkey"]          # raw base64 string as published
    r.pubkey = parsed["pubkey_bytes"]
    r.pubkey_error = parsed["pubkey_error"]

    # DET<->key binding (RFC 9374 3.5.2) - same check as verifyDETHashLocal.
    if r.pubkey is None or not HAVE_DET:
        r.binding_ok = None
    else:
        r.binding_ok = bool(det.verify_det_binding(det_bytes, r.pubkey))

    return r


def to_ua_entry(r):
    """Build the hierarchy.json 'ua' object for this identity. RAA/HDA are read
    from the DET's own bits (RFC 9374 3.3), never guessed."""
    if HAVE_DET:
        f = det.parse_det(r.det)
        raa, hda = f["raa"], f["hda"]
    else:
        upper = int.from_bytes(r.det[:8], "big")
        raa, hda = (upper >> 22) & 0x3FFF, (upper >> 8) & 0x3FFF
    entry = {"det": r.det_hex(), "raa": raa, "hda": hda}
    if r.pubkey is not None:
        entry["public_key"] = r.pubkey_hex()
    note = f"from DNS {r.fqdn}"
    if r.sn:
        note += f" (sn={r.sn})"
    note += "; dnssec_present" if r.dnssec_present else "; dnssec NOT present"
    entry["_role"] = note
    return entry
