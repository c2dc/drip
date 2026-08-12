#pragma once
#include <stdint.h>
#include <stddef.h>
#include "det_generator.h"
#include "f3411_messages.h"

// ---------------------------------------------------------------------------
// DRIP Manifest  —  RFC 9575 §4.4
//
// SAM Type = 0x03. Transmitted in Cycle C of the 3-phase, 3 Hz rotation.
//
// Evidence layout — 32 bytes (4 × 8-byte hashes) — RFC §4.4.2 + §4.4.3:
//   [0- 7] Previous Manifest Hash   (random nonce on first run, §4.4.2)
//   [8-15] Current Manifest Hash    (self-referential: null -> hash -> fill)
//   [16-23] DRIP Link (BE: HDA,UA) Hash
//   [24-31] ASTM Message (Pack) Hash
//
// Full SAM payload — 121 bytes — RFC 9575 §4.1 Figure 4 / §4.4
// (Round-2 remediation R3: VNB inserted ahead of VNA, Algorithm-ID octet
//  removed — see drip_manifest.cpp):
//   [0]       SAM Type = 0x03
//   [1-4]     VNB (LE, DRIP epoch)
//   [5-8]     VNA (LE) = VNB + 120 s
//   [9-40]    Evidence (32 = Previous ‖ Current ‖ Link ‖ Pack hashes, 8 B each)
//   [41-56]   UA DET (16)
//   [57-120]  Ed25519 signature (64)
//
// Signed data — RFC §4.1 Figure-4 order: VNB || VNA || Evidence || DET (56 B)
// — unchanged by R3; the wire layout now matches the signed bytes.
//
// PAGING: pages produced by drip_auth_scatter() (shared helper): dedicated
// Last Page Index octet and AuthType 0x5 on every page. The ASTM page-0
// Timestamp header carries VNB at bytes 4-7. Appendix B.1:
// manifest_page_count = ceil((89 + 8×(1+3) − 17)/23) + 1 = 6  ✓ (121 ≤ 132)
// ---------------------------------------------------------------------------

#define DRIP_MANIFEST_MAX_PAGES    6
// DRIP_MANIFEST_ALG_ED25519 removed (R3.2): no Algorithm-ID field exists in the
// Figure-4 structure — the algorithm is bound by the DET's HHIT OGA Suite.
#define MANIFEST_EVIDENCE_BYTES   32
#define MANIFEST_PAYLOAD_BYTES   121    // 1 + 4(VNB) + 4(VNA) + 32 + 16 + 64

static_assert(MANIFEST_PAYLOAD_BYTES == 121, "Manifest payload size mismatch");
static_assert(17 + (DRIP_MANIFEST_MAX_PAGES - 1) * 23 >= MANIFEST_PAYLOAD_BYTES,
              "Manifest payload does not fit in allocated pages");

struct DRIPManifestState {
    uint8_t prev_manifest_hash[8];
    uint8_t link_hash[8];   // hash of BE:HDA,UA SAM data
    uint8_t pack_hash[8];
    bool    initialized;
};

// Initialise state and seed prev_manifest_hash (after beacon_tx_raw_init(), so
// esp_random() is a true hardware RNG). One state per virtual drone.
void drip_manifest_init(DRIPManifestState *state);

// Record the cSHAKE128 hash of the Wrapper Message Pack (call from Cycle A).
void drip_manifest_update_pack(DRIPManifestState *state,
                                const uint8_t     *pack_bytes,
                                uint8_t            pack_len);

// Record the cSHAKE128 hash of the DRIP Link carrying BE:HDA,UA (RFC §4.4.2).
//
// CHANGED THIS TURN: the Link is now a 137-octet Broadcast Endorsement, so this
// takes the BE:HDA,UA SAM Authentication Data and its length (e.g. the buffer
// from drip_reg_hda_ua_sam()), not a single 25-byte message.
void drip_manifest_update_link(DRIPManifestState *state,
                                const uint8_t     *link_sam,
                                size_t             link_sam_len);

// Build the 6-page Manifest Auth Message (call from Cycle C).
//   id : the virtual UA's identity — supplies the DET carried in the Manifest
//        AND the key that signs it. Multi-drone change: each UA keeps its own
//        DRIPManifestState (its own Prev/Curr hash chain, RFC 9575 §4.4.2) and
//        signs with its own key.
bool drip_manifest_build(DRIPManifestState *state,
                          const DETIdentity &id,
                          uint8_t            out[DRIP_MANIFEST_MAX_PAGES][F3411_MSG_BYTES],
                          uint8_t           *page_count_out);
