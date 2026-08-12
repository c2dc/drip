#include "drip_manifest.h"
#include "drip_auth_page.h"     // shared correct page framing (Findings 1 & 2)
#include "cshake128.h"
#include "drip_time.h"
#include "drip_debug.h"   // drip_debug_enabled() — status-line gating
#include <string.h>
#include <Arduino.h>

extern "C" {
#include "esp_random.h"  // hardware RNG — requires WiFi/BT RF to be active
}

// ---------------------------------------------------------------------------
// cSHAKE128 customisation string for all DRIP Manifest hashes (OGA Suite 5).
// ---------------------------------------------------------------------------
static const uint8_t HASH_CS[]     = "Remote ID Auth Hash";
static const size_t  HASH_CS_LEN   = 19;

// ---------------------------------------------------------------------------
static void manifest_hash8(const uint8_t *data, size_t len, uint8_t out[8]) {
    cshake128(data, len, HASH_CS, HASH_CS_LEN, out, 64);   // 64 bits = 8 bytes
}

// ---------------------------------------------------------------------------
void drip_manifest_init(DRIPManifestState *state) {
    memset(state, 0, sizeof(*state));
    uint32_t r0 = esp_random();
    uint32_t r1 = esp_random();
    memcpy(&state->prev_manifest_hash[0], &r0, 4);
    memcpy(&state->prev_manifest_hash[4], &r1, 4);
    state->initialized = false;

    Serial.print("[Manifest] init — prev_hash seeded (RNG): ");
    for (int i = 0; i < 8; i++) Serial.printf("%02X", state->prev_manifest_hash[i]);
    Serial.println();
}

// ---------------------------------------------------------------------------
void drip_manifest_update_pack(DRIPManifestState *state,
                                const uint8_t     *pack_bytes,
                                uint8_t            pack_len) {
    manifest_hash8(pack_bytes, (size_t)pack_len, state->pack_hash);
    if (drip_debug_enabled()) {                 // per-cycle status — gated
        Serial.print("[Manifest] pack_hash updated: ");
        for (int i = 0; i < 8; i++) Serial.printf("%02X", state->pack_hash[i]);
        Serial.println();
    }
}

// ---------------------------------------------------------------------------
// CHANGED THIS TURN: the Link is now a 137-octet Broadcast Endorsement spanning
// 7 pages, not a 25-byte stub. Per RFC §4.4.2 the Manifest references the DRIP
// Link carrying BE: HDA,UA, so we hash that BE's SAM Authentication Data.
// Callers pass drip_reg_hda_ua_sam(...) (or the loaded BE:HDA,UA SAM bytes).
// ---------------------------------------------------------------------------
void drip_manifest_update_link(DRIPManifestState *state,
                                const uint8_t     *link_sam,
                                size_t             link_sam_len) {
    manifest_hash8(link_sam, link_sam_len, state->link_hash);
    if (drip_debug_enabled()) {                 // per-cycle status — gated
        Serial.print("[Manifest] link_hash updated (BE:HDA,UA): ");
        for (int i = 0; i < 8; i++) Serial.printf("%02X", state->link_hash[i]);
        Serial.println();
    }
}

// ---------------------------------------------------------------------------
bool drip_manifest_build(DRIPManifestState *state,
                          const DETIdentity &id,
                          uint8_t            out[DRIP_MANIFEST_MAX_PAGES][F3411_MSG_BYTES],
                          uint8_t           *page_count_out) {

    uint32_t vnb = drip_timestamp();
    uint32_t vna = vnb + DRIP_VNA_OFFSET_S;        // RFC §3.2.4.3

    // ----- Evidence (32 bytes), Current Manifest Hash null then filled -----
    uint8_t evidence[MANIFEST_EVIDENCE_BYTES];
    memcpy(&evidence[0],  state->prev_manifest_hash, 8);  // Previous
    memset(&evidence[8],  0x00,                      8);  // Current (null for now)
    memcpy(&evidence[16], state->link_hash,           8);  // DRIP Link (BE:HDA,UA)
    memcpy(&evidence[24], state->pack_hash,           8);  // ASTM Message (Pack) Hash

    uint8_t curr_manifest_hash[8];
    manifest_hash8(evidence, MANIFEST_EVIDENCE_BYTES, curr_manifest_hash);
    memcpy(&evidence[8], curr_manifest_hash, 8);

    // ----- SAM payload (121 bytes) — RFC 9575 §4.1 Figure 4 / §4.4 -----
    // Round-2 remediation R3:
    //   R3.1: VNB serialised ahead of VNA (Figure-4 field order; previously
    //         VNB appeared only in the ASTM page-0 Timestamp header).
    //   R3.2: Algorithm-ID octet REMOVED — not a Figure-4 field; the algorithm
    //         is bound by the DET's HHIT OGA Suite (5 = EdDSA/cSHAKE128,
    //         RFC 9374 Table 7).
    // The signer input below is UNCHANGED — the wire now matches the signed bytes.
    uint8_t payload[MANIFEST_PAYLOAD_BYTES];
    memset(payload, 0, MANIFEST_PAYLOAD_BYTES);

    payload[0] = DRIP_SAM_TYPE_MANIFEST;                       // SAM Type 0x03
    drip_put_le32(&payload[1], vnb);                           // [1..4]  VNB (LE)
    drip_put_le32(&payload[5], vna);                           // [5..8]  VNA (LE)
    memcpy(&payload[9],  evidence, MANIFEST_EVIDENCE_BYTES);   // [9..40] Evidence (32)
    memcpy(&payload[41], id.det,   DET_BYTES);                 // [41..56] UA DET (16)

    // ----- Sign: VNB || VNA || Evidence || DET (56 bytes), RFC §4.1 Figure 4 -
    uint8_t signed_data[4 + 4 + MANIFEST_EVIDENCE_BYTES + DET_BYTES];
    memset(signed_data, 0, sizeof(signed_data));
    drip_put_le32(&signed_data[0], vnb);
    drip_put_le32(&signed_data[4], vna);
    memcpy(&signed_data[8],  evidence, MANIFEST_EVIDENCE_BYTES);
    memcpy(&signed_data[40], id.det,   DET_BYTES);

    // Sign with THIS UA's key (multi-drone change: was det_sign(), one global key).
    bool sign_ok = det_sign_with(id, signed_data, sizeof(signed_data), &payload[57]); // [57..120] Sig (64)
    if (!sign_ok) {
        Serial.println("[Manifest] WARN: Ed25519 signing failed — signature zero-filled");
    }

    // ----- Correct framing via the shared helper -----
    // (was: hand-rolled scatter with byte1 = 0x55 / continuation byte1 = p and
    //  no dedicated Last Page Index octet.)
    uint8_t pages = drip_auth_scatter(payload, MANIFEST_PAYLOAD_BYTES, vnb,
                                      out, DRIP_MANIFEST_MAX_PAGES);
    if (pages == 0) {
        Serial.println("[Manifest] ERROR: payload did not fit in pages");
        return false;
    }

    // ----- Roll state forward -----
    memcpy(state->prev_manifest_hash, curr_manifest_hash, 8);
    state->initialized = true;
    *page_count_out = pages;

    if (drip_debug_enabled()) {                 // per-cycle status — gated
        Serial.printf("[Manifest] Built OK — %u pages, VNB=%u VNA=%u sign=%s\n",
                      pages, vnb, vna, sign_ok ? "OK" : "FAIL");
        Serial.print("[Manifest] curr_hash: ");
        for (int i = 0; i < 8; i++) Serial.printf("%02X", curr_manifest_hash[i]);
        Serial.println();
    }

    return sign_ok;
}
