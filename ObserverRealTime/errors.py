#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - errors.py
#  Error catalog, each entry derived from a specific ASTM / RFC constraint.
#  Each error has a stable ID, a short description, and the governing clause.
# =============================================================================

ERROR_CATALOG = {
    # --- ASTM structural -----------------------------------------------------
    "E-FMT-01":  ("Unknown / unsupported message type",
                  "ASTM F3411-22a Table 3 (valid: 0x0-0x5, 0xF)"),
    "E-FMT-02":  ("Wrong protocol version (expected 0x2)",
                  "ASTM F3411-22a 5.4.5.4 / Table 4"),
    "E-FMT-03":  ("Bad record length (a single message must be 25 bytes)",
                  "ASTM F3411-22a 5.4.5.4"),
    # --- Message Pack --------------------------------------------------------
    "E-PACK-01": ("Message Pack 'Message Size' field is not 0x19 (25)",
                  "ASTM F3411-22a Table 13"),
    "E-PACK-02": ("Message Pack count N out of range (must be 1..9)",
                  "ASTM F3411-22a Table 13"),
    "E-PACK-03": ("Message Pack truncated (declared N*25 exceeds bytes present)",
                  "ASTM F3411-22a Table 13"),
    "E-PACK-04": ("Nested Message Pack (a 0xF message inside a pack)",
                  "ASTM F3411-22a 5.4.5.22"),
    # --- Authentication message ---------------------------------------------
    "E-AUTH-01": ("Reserved / invalid Auth Type (6-9)",
                  "ASTM F3411-22a Tables 8 / 9"),
    "E-AUTH-02": ("Page-0 Data Page Number is not 0",
                  "ASTM F3411-22a Table 8"),
    "E-AUTH-03": ("Authentication page numbering error (gap / order / > last page)",
                  "ASTM F3411-22a 5.4.5.15"),
    "E-AUTH-04": ("Last Page Index reserved bits [7:4] are non-zero",
                  "ASTM F3411-22a Table 8"),
    "E-AUTH-05": ("Auth Length inconsistent with reassembled pages",
                  "ASTM F3411-22a 5.4.5.15"),
    "E-AUTH-06": ("Authentication timestamp out of valid range",
                  "ASTM F3411-22a Table 8"),
    # --- DRIP / SAM (RFC 9575 / RFC 9374) -----------------------------------
    "E-SAM-01":  ("Unknown / invalid DRIP SAM Type (expected 0x01-0x04)",
                  "RFC 9575 Table 1"),
    "E-DET-01":  ("DET prefix is not 2001:30::/28",
                  "RFC 9374 Table 1"),
    "E-DET-02":  ("DET <-> public-key binding failure (cSHAKE128 mismatch)",
                  "RFC 9374 3.5.2"),
    "E-KEY-01":  ("No public key known for this DET - signature/binding NOT checked",
                  "observer keyring (RFC 9374 3.5.2 binds a DET to one key)"),
    # --- DET resolution against the trusted-identities file (identity_resolve.py) ---
    "E-TRUST-01":("DET is not in the trusted-identities file at any level "
                  "(no trusted HDA delegation, not individually enrolled)",
                  "observer trusted-identities file (hierarchy.json 'ua'/'hda')"),
    "E-ZONE-01": ("DET does not nest under any trusted RAA /44 or HDA /56 zone",
                  "RFC 9886 6 (zone delegation is fixed by the RAA/HDA nibbles)"),

    # ---- W-* : WARNINGS. NOT conformance failures. -------------------------
    # A W- code means "unexpected for THIS bench emulator", never "violates a
    # standard". Kept prefix-distinct from E- so the two can never be conflated
    # in a report handed to a certification reader.
    "W-CAP-01":  ("Frame discarded: byte count contradicts the sniffer's own "
                  "declared length - the frame was damaged in the CAPTURE "
                  "PIPELINE (serial byte loss), not on the air. NOT a DRIP or "
                  "ASTM defect, and says nothing about the drone that sent it",
                  "DRIP_Sniffer '#F ... len=' contract. The 802.11 FCS is "
                  "checked in hardware before a frame is ever delivered to the "
                  "sniffer, so RF corruption cannot reach here; missing bytes "
                  "mean the serial link or the logger dropped them."),

    "W-MAC-02":  ("Same DET seen from multiple transmitter MACs - PERMITTED by "
                  "ASTM (see basis); flagged only because this bench emulator "
                  "uses a fixed MAC per slot, so >1 MAC means a second "
                  "transmitter, a firmware fault, or a misconfiguration",
                  "NOT a violation. ASTM F3411-22a 5.4.5.6 NOTE 2: when using "
                  "Specific Session ID Type (which DRIP is, ID Type 4), "
                  "implementations MAY use random rather than static MAC "
                  "addresses. Verified against the page image."),
    "E-SIG-01":  ("DRIP Wrapper signature verification failed (Ed25519)",
                  "RFC 9575 4.3  [extension point - see observer.py]"),
    "E-FRESH-01":("Authentication timestamp stale / in the future vs window",
                  "RFC 9575 (freshness / replay)"),
    # --- DRIP Link chain of trust (RFC 9575 §4.2 / §6.4.2) ------------------
    "E-LINK-01": ("Link child DET does not bind to child HI (cSHAKE128 mismatch)",
                  "RFC 9374 3.5.2 / RFC 9575 4.2"),
    "E-LINK-02": ("Link parent signature invalid (Ed25519)",
                  "RFC 9575 4.2"),
    "E-LINK-03": ("Link chain broken - no path from this endorsement to the trust anchor",
                  "RFC 9575 6.4.2"),
    "E-LINK-04": ("Link Broadcast Endorsement outside its validity window (VNB..VNA)",
                  "RFC 9575 3.2.4.3"),
    # --- DRIP Manifest (RFC 9575 §4.4) --------------------------------------
    "E-MAN-01": ("Manifest signature invalid (Ed25519 over VNB|VNA|Evidence|DET)",
                 "RFC 9575 4.4 / 4.1"),
    "E-MAN-02": ("Manifest ASTM hash matches no observed Message Pack",
                 "RFC 9575 4.4.3.2"),
    "E-MAN-03": ("Manifest Link hash matches no observed BE:HDA,UA",
                 "RFC 9575 4.4.2"),
    "E-MAN-04": ("Manifest chain broken (Prev != previous Manifest's Current hash)",
                 "RFC 9575 4.4.2 / 4.4.3"),
    "E-MAN-05": ("Manifest Current hash incorrect (cSHAKE128 over Prev|null|Link|ASTM)",
                 "RFC 9575 4.4.3"),
    # --- Semantic / cross-message -------------------------------------------
    "E-SEM-01":  ("DRIP authentication present but no DRIP Basic ID (Type 4 / SSI 1) in pack",
                  "RFC 9374 / ASTM F3411-22a 5.4.5"),
}


class Finding:
    """A single validation problem, tied to where it was found."""
    __slots__ = ("error_id", "where", "detail")

    def __init__(self, error_id, where, detail=""):
        self.error_id = error_id
        self.where = where
        self.detail = detail

    def description(self):
        return ERROR_CATALOG.get(self.error_id, ("(unknown error id)", ""))[0]

    def constraint(self):
        return ERROR_CATALOG.get(self.error_id, ("", ""))[1]

    def __str__(self):
        s = f"[{self.error_id}] {self.description()}  @ {self.where}"
        if self.detail:
            s += f"  -- {self.detail}"
        return s
