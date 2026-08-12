#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - flight_tracks.py
#  Extracts per-drone position tracks (for mapping / summaries) from a capture,
#  reusing odid.py's parsers and decoders. This is a separate concern from
#  observer.py (which focuses on error/validation reporting): this module only
#  answers "where has each drone been".
#
#  GROUPING: a Location message has no identity of its own (ASTM Table 6 has no
#  DET field). Real captures do not always put Basic ID in the SAME pack as
#  every Location message (confirmed against real data: a drone re-announces
#  its Basic ID periodically, not on every transmission). We therefore track
#  identity as PERSISTENT STATE across the whole capture: once a Basic ID is
#  seen, every subsequent Location is attributed to it until a new Basic ID
#  appears - the same correlation strategy a real RID receiver uses. The
#  identity itself is the DRIP DET when the Basic ID uses SSI Type 1 (IETF
#  DRIP), or a generic hex label from the raw session ID otherwise - real
#  captures are not guaranteed to be DRIP-native (confirmed: a captured
#  third-party implementation uses SSI Type 246, not 1). A Location seen
#  before any Basic ID is bucketed under "unknown".
#
#  TIME: ASTM System (Table 11) carries NO timestamp field in this firmware
#  (see f3411_messages.h — F3411System has no timestamp member); any
#  "timestamp" decoded from it is the zero-filled reserved bytes, not real
#  time. We do NOT use it. Instead, each point's approximate time is the VNB
#  of the nearest DRIP auth message (Wrapper/Link/Manifest) found in the same
#  pack — a real, RFC 9575 §3.2.4.3 timestamp we already verify elsewhere in
#  this project. Point ORDER on the path is always transmission order in the
#  file, independent of any timestamp field.
# =============================================================================

import odid


def _basic_id_label(d):
    """Return a display label for a Basic ID message's identity, regardless of
       whether it uses a DRIP DET (SSI Type 1) or another ID scheme (this
       capture may be from a non-DRIP ODID implementation - confirmed to occur
       in practice). DRIP DETs get their IPv6 form; anything else gets a hex
       label from the raw ID bytes so grouping/mapping still works generally."""
    if d.get("id_type") == 4 and d.get("det_ipv6"):
        return d["det_ipv6"]                      # DRIP DET (SSI Type 1)
    raw = d.get("uas_id_raw")
    if raw:
        hexid = bytes(raw).rstrip(b"\x00").hex()
        ssi = d.get("ssi_type")
        return f"ssi{ssi}:{hexid}" if ssi is not None else f"id:{hexid}"
    txt = d.get("uas_id_text")
    return txt if txt else None


def _pack_det_and_vnb(decoded_msgs):
    """From one pack's decoded messages, return (identity_label_or_None, vnb_or_None).
       label is None if this pack has no Basic ID (caller keeps the prior one)."""
    det = None
    for d in decoded_msgs:
        if d.get("type") == 0x0:
            label = _basic_id_label(d)
            if label:
                det = label
    vnb = None
    auths = odid.reassemble_auth(decoded_msgs)
    if auths:
        vnb = auths[0].get("timestamp_unix")  # page-0 timestamp = signing VNB-adjacent time
    return det, vnb


def _new_track(label):
    return {"label": label, "points": []}


def _process_decoded(decoded_msgs, where, tracks, state):
    """state = {"det": current persistent DET or None, "unknown_n": int}"""
    pack_det, vnb = _pack_det_and_vnb(decoded_msgs)
    if pack_det is not None:
        state["det"] = pack_det          # a fresh Basic ID updates the running identity

    key = state["det"]
    for d in decoded_msgs:
        if d.get("type") != 0x1:            # Location/Vector only
            continue
        k = key
        if k is None:
            state["unknown_n"] += 1
            k = f"unknown-{state['unknown_n']}"
        if k not in tracks:
            tracks[k] = _new_track(key if key else k)
        tracks[k]["points"].append({
            "lat": d.get("lat"), "lon": d.get("lon"),
            "alt_m": d.get("alt_geodetic_m"),
            "speed_mps": d.get("speed_mps"), "heading_deg": d.get("direction_deg"),
            "vnb": vnb, "where": where,
        })


# ---------------------------------------------------------------------------
#  PUBLIC WRAPPERS (added for live_observer.py - purely additive)
#
#  The real-time observer must feed ONE pack at a time and keep the running
#  identity between calls, which extract_tracks() cannot express because it owns
#  both the loop and the state. These two functions expose what already exists;
#  no existing behaviour is altered and extract_tracks() still calls the private
#  helper directly, exactly as before.
#
#  Sharing this code rather than re-implementing it is the point: the live map
#  and make_map.py must never disagree about where a drone was.
# ---------------------------------------------------------------------------
def new_state():
    """A fresh persistent-identity state for process_decoded()."""
    return {"det": None, "unknown_n": 0}


def process_decoded(decoded_msgs, where, tracks, state):
    """Fold one pack's decoded messages into `tracks`, carrying `state` across
       calls. See the module docstring for the identity-persistence rule."""
    _process_decoded(decoded_msgs, where, tracks, state)


def extract_tracks(text):
    """Parse `text` (Format L, A, W, or B - auto-detected, same as observer.run)
       and return {key: {"label": str, "points": [ {...} ]}}. Points within a
       track are in transmission/file order. DET identity persists across
       packs (see module docstring) for the whole capture."""
    tracks = {}
    state = {"det": None, "unknown_n": 0}

    if odid.looks_like_format_l(text):
        for entry in odid.parse_format_l(text):
            where = f"tx[{entry['tx_cnt']:#04x}]"
            payload = entry["pack_bytes"]
            if not payload:
                continue
            if (payload[0] >> 4) == 0xF:
                info = odid.split_pack(payload)
                decoded = [odid.decode_message(m) for m in info.get("messages_raw", [])]
                _process_decoded(decoded, where, tracks, state)
    elif odid.looks_like_format_a(text):
        # Format A: over-the-air capture (DRIP_Sniffer). Each frame carries its
        # own Basic ID + Location, so interleaved drones separate correctly on
        # the DET alone -- but the transmitter MAC is now available too, and is
        # used in the label so a multi-drone track is attributable.
        a_frames, _a_damaged = odid.parse_format_a(text)
        for fi, (meta, frame) in enumerate(a_frames):
            ie = odid.extract_drip_ie(frame)
            if ie is None:
                continue
            hdr = odid.parse_mac_header(frame)
            tag = odid.mac_str(hdr["addr2"]) if hdr else "??"
            where = f"frame[{fi}] {tag}"
            payload = ie["payload"]
            if payload and (payload[0] >> 4) == 0xF:
                info = odid.split_pack(payload)
                decoded = [odid.decode_message(m) for m in info.get("messages_raw", [])]
                _process_decoded(decoded, where, tracks, state)
    elif odid.looks_like_format_w(text):
        for fi, frame in enumerate(odid.parse_format_w(text)):
            ie = odid.extract_drip_ie(frame)
            if ie is None:
                continue
            where = f"frame[{fi}]"
            payload = ie["payload"]
            if payload and (payload[0] >> 4) == 0xF:
                info = odid.split_pack(payload)
                decoded = [odid.decode_message(m) for m in info.get("messages_raw", [])]
                _process_decoded(decoded, where, tracks, state)
    elif odid.looks_like_format_b(text):
        # Format B: a pack line correlates Basic ID + Location directly;
        # a bare Location line (no pack) uses the persistent running DET.
        for ri, (rec, _expect) in enumerate(odid.parse_format_b(text)):
            where = f"record[{ri}]"
            if not rec:
                continue
            if (rec[0] >> 4) == 0xF:
                info = odid.split_pack(rec)
                decoded = [odid.decode_message(m) for m in info.get("messages_raw", [])]
                _process_decoded(decoded, where, tracks, state)
            else:
                d = odid.decode_message(rec)
                _process_decoded([d], where, tracks, state)
    else:
        # Same rule as observer.run(): refuse rather than guess. Format B used
        # to be the unconditional `else` here too, so an unrecognised file was
        # silently decoded as flat hex and produced "Found 0 drone(s)" --
        # indistinguishable from a capture with no drones in it.
        raise ValueError(odid.diagnose_format(text))

    return tracks


def track_summary(tracks):
    """One-line-per-drone summary: label, point count, first/last position."""
    lines = []
    for key, t in tracks.items():
        pts = t["points"]
        if not pts:
            continue
        p0, p1 = pts[0], pts[-1]
        lines.append(
            f"{t['label']:40s} pts={len(pts):5d}  "
            f"first=({p0['lat']:.6f},{p0['lon']:.6f},{p0['alt_m']}m)  "
            f"last=({p1['lat']:.6f},{p1['lon']:.6f},{p1['alt_m']}m)"
        )
    return lines
