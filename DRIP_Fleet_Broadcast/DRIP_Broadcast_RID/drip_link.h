#pragma once
#include <stdint.h>
#include "det_generator.h"
#include "f3411_messages.h"

// ---------------------------------------------------------------------------
// DRIP Link = Broadcast Endorsement (BE)  — RFC 9575 §4.2 / Figure 5
//
// Replaces the previous DET-only stub (Finding 3). A Link is a full Broadcast
// Endorsement: a parent (HDA / RAA / Apex) signing a binding of a child's DET
// to the child's Host Identity (public key), so an OFFLINE Observer can build
// trust in the DET<->HI binding without network access (RFC 9575 §6.3).
//
// SAM Authentication Data layout (137 octets, RFC §4.2 Figure 5):
//   [0]        SAM Type = 0x01 (Link)                        (RFC §3.2.3 / §4)
//   [1..4]     VNB           (Valid Not Before, LE)
//   [5..8]     VNA           (Valid Not After,  LE)
//   [9..24]    DET of Child  (16)
//   [25..56]   HI  of Child  (32, Ed25519 public key)
//   [57..72]   DET of Parent (16)
//   [73..136]  Signature by Parent (64, Ed25519)
//
// Signature input (made by the PARENT key, computed at registration time):
//   VNB || VNA || DET_child || HI_child || DET_parent          (72 octets)
//   (the SAM Type octet is the multiplexer prefix and is NOT signed, matching
//    the §4.1 convention where the SAM Type is excluded from the signed set.)
//
// 137 octets -> 7 Auth pages (RFC Appendix B.1: link_page_count = 7):
//   page 0 carries 17, pages 1..6 carry 23 each (last page partly padded).
//
// NOTE: the UA never *creates* a BE — it stores ones produced by its parents at
// registration and replays them. This builder only SERIALISES a pre-signed BE.
// Production firmware loads BroadcastEndorsement records from secure storage
// (NVS); the DRIP_TEST_BE build (drip_registration.*) fabricates a self-
// consistent test chain instead. See drip_registration.h.
// ---------------------------------------------------------------------------

#define DRIP_LINK_MAX_PAGES   7
#define DRIP_LINK_SAM_BYTES   137   // 1 + 4 + 4 + 16 + 32 + 16 + 64
#define DRIP_BE_HI_BYTES      32    // Ed25519 public key (Host Identity)
#define DRIP_BE_SIG_BYTES     64    // Ed25519 signature

// A single Broadcast Endorsement record (one link of the BE chain).
struct BroadcastEndorsement {
    uint32_t vnb;                          // Valid Not Before (DRIP epoch)
    uint32_t vna;                          // Valid Not After  (DRIP epoch)
    uint8_t  det_child [DET_BYTES];        // 16
    uint8_t  hi_child  [DRIP_BE_HI_BYTES]; // 32  (child Ed25519 public key)
    uint8_t  det_parent[DET_BYTES];        // 16
    uint8_t  sig       [DRIP_BE_SIG_BYTES];// 64  (parent's signature)
};

static_assert(sizeof(uint8_t[DRIP_LINK_SAM_BYTES]) == 137, "Link SAM size");

// Serialise a pre-signed BE into ASTM Auth pages (page count returned).
// out must be at least [DRIP_LINK_MAX_PAGES][F3411_MSG_BYTES].
// Returns the number of pages (7) or 0 if max_pages is too small.
uint8_t drip_link_build_be(const BroadcastEndorsement *be,
                           uint8_t out[][F3411_MSG_BYTES],
                           uint8_t max_pages);

// Serialise just the 137-octet SAM Authentication Data of a BE (no paging).
// Used by the Manifest to hash BE:HDA,UA per RFC §4.4.2.
void drip_link_serialize_sam(const BroadcastEndorsement *be,
                             uint8_t sam[DRIP_LINK_SAM_BYTES]);
