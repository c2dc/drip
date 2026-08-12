#include "drip_auth.h"
#include "drip_auth_page.h"     // drip_auth_scatter(), drip_put_le32()
#include "drip_time.h"          // drip_timestamp()
#include "drip_debug.h"         // drip_debug_enabled() — status-line gating
#include <string.h>
#include <Arduino.h>

// ---------------------------------------------------------------------------
// DRIP Wrapper over Extended Transports — RFC 9575 §4.3.2
//
// CHANGE FROM PRIOR VERSION (standard Wrapper -> Extended Wrapper):
//   * The wrapped messages are NO LONGER carried on the wire. The Evidence
//     field is filled (for signing only) with the pack's ASTM messages, the
//     signature is computed, and Evidence is then CLEARED (§4.3.2 / Fig 7).
//   * The wire payload is therefore a fixed 89 octets -> 5 pages (was 114 -> 6).
//   * The signer input is VNB‖VNA‖Evidence‖DET, where Evidence = the pack's
//     non-Auth messages in ascending Message Type order (was a single Location).
//   * VNB/VNA remain little-endian (confirmed correct — see drip_auth.h).
// ---------------------------------------------------------------------------

// Wire payload: SAM(1) + VNB(4) + VNA(4) + DET(16) + Sig(64) = 89 octets.
#define WRAPPER_WIRE_BYTES   89
static_assert(WRAPPER_WIRE_BYTES <= 17 + (DRIP_WRAPPER_MAX_PAGES - 1) * 23,
              "Extended Wrapper payload does not fit in 5 Auth pages");

// RFC 9575 §4.3.3: a Wrapper may authenticate at most four ASTM Messages.
#define WRAPPER_MAX_EVIDENCE_MSGS   4

// ---------------------------------------------------------------------------
// Gather the pack's non-Authentication messages, STABLE-sorted ascending by
// ASTM Message Type (§4.3.2 / §4.3). Ties (same type, e.g. two Basic IDs) keep
// their original pack order. The receiver MUST use the identical ordering rule.
// Returns the count; fills idx[] with pack message indices in signing order.
// ---------------------------------------------------------------------------
static uint8_t collect_evidence_order(const MessagePack *pack,
                                      uint8_t idx[MSG_PACK_MAX_MSGS]) {
    uint8_t n = 0;
    for (uint8_t i = 0; i < pack->count; i++) {
        const uint8_t *m = pack->buf + MSG_PACK_HDR_BYTES + (size_t)i * F3411_MSG_BYTES;
        uint8_t type = (m[0] >> 4) & 0x0F;
        if (type == F3411_TYPE_AUTH) continue;          // exclude Auth (§4.3.2)

        uint8_t pos = n;                                 // stable insertion by type
        while (pos > 0) {
            const uint8_t *mp = pack->buf + MSG_PACK_HDR_BYTES
                                + (size_t)idx[pos - 1] * F3411_MSG_BYTES;
            if (((mp[0] >> 4) & 0x0F) <= type) break;
            idx[pos] = idx[pos - 1];
            pos--;
        }
        idx[pos] = i;
        n++;
    }
    return n;
}

// ---------------------------------------------------------------------------
bool drip_wrapper_build(const DETIdentity  &id,
                        const MessagePack  *astm_pack,
                        uint8_t             out[DRIP_WRAPPER_MAX_PAGES][F3411_MSG_BYTES],
                        uint8_t            *page_count_out) {
    const uint32_t vnb = drip_timestamp();
    const uint32_t vna = vnb + DRIP_VNA_OFFSET_S;

    // ---- 1. Evidence order = pack's non-Auth messages, ascending by type ----
    uint8_t idx[MSG_PACK_MAX_MSGS];
    uint8_t n = collect_evidence_order(astm_pack, idx);
    if (n > WRAPPER_MAX_EVIDENCE_MSGS) {
        Serial.printf("[Wrapper] WARNING: %u messages to wrap exceeds the RFC 9575 "
                      "§4.3.3 limit of 4; receiver may reject.\n", n);
    }

    // ---- 2. SIGNED bytes: VNB ‖ VNA ‖ Evidence ‖ UA_DET  (§4.1 Figure 4) -----
    uint8_t  signed_data[4 + 4 + MSG_PACK_MAX_MSGS * F3411_MSG_BYTES + DET_BYTES];
    uint16_t sd = 0;
    drip_put_le32(&signed_data[sd], vnb); sd += 4;                 // VNB (LE)
    drip_put_le32(&signed_data[sd], vna); sd += 4;                 // VNA (LE)
    for (uint8_t k = 0; k < n; k++) {                             // Evidence
        const uint8_t *m = astm_pack->buf + MSG_PACK_HDR_BYTES
                           + (size_t)idx[k] * F3411_MSG_BYTES;
        memcpy(&signed_data[sd], m, F3411_MSG_BYTES); sd += F3411_MSG_BYTES;
    }
    memcpy(&signed_data[sd], id.det, DET_BYTES); sd += DET_BYTES;  // UA DET

    // Sign with THIS UA's key (multi-drone change: was det_sign(), which could
    // only ever use the one module-global key).
    uint8_t sig[64];
    bool sign_ok = det_sign_with(id, signed_data, sd, sig);
    if (!sign_ok)
        Serial.println("[Wrapper] WARN: Ed25519 signing failed — signature zero-filled");

    // ---- 3. WIRE payload (89 octets, Evidence CLEARED, §4.3.2 / Fig 7) -------
    uint8_t payload[WRAPPER_WIRE_BYTES];
    memset(payload, 0, sizeof(payload));
    payload[0] = DRIP_SAM_TYPE_WRAPPER;             // SAM Type 0x02
    drip_put_le32(&payload[1], vnb);                // VNB (LE)            [1..4]
    drip_put_le32(&payload[5], vna);                // VNA (LE)            [5..8]
    memcpy(&payload[9],  id.det, DET_BYTES);        // UA DET (16)         [9..24]
    memcpy(&payload[25], sig, 64);                  // UA Signature (64)   [25..88]
    // Evidence is intentionally ABSENT (cleared) per §4.3.2.

    // ---- 4. Scatter into Auth pages (Length = 89 -> 5 pages) ----------------
    uint8_t pages = drip_auth_scatter(payload, WRAPPER_WIRE_BYTES, vnb,
                                      out, DRIP_WRAPPER_MAX_PAGES);
    if (pages == 0) {
        Serial.println("[Wrapper] ERROR: payload did not fit in pages");
        return false;
    }
    *page_count_out = pages;

    // STATUS line — gated. This fires once per Cycle A per drone; at 3 drones
    // that is part of a ~15 line/s stream that buries typed commands. The
    // signing WARN above is deliberately NOT gated: silence must mean
    // "signing fine", never "no idea".
    if (drip_debug_enabled())
        Serial.printf("[Wrapper] Extended OK — %u msg(s) signed, %u pages, "
                      "VNB=%u VNA=%u sign=%s\n",
                      n, pages, vnb, vna, sign_ok ? "OK" : "FAIL");
    return sign_ok;
}
