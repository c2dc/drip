#pragma once
#include <stdint.h>
#include "det_generator.h"
#include "f3411_messages.h"
#include "message_pack.h"

// ---------------------------------------------------------------------------
// DRIP Wrapper over EXTENDED TRANSPORTS  — RFC 9575 §4.3.2 / Figure 7
//
// On Wi-Fi (an Extended Transport) the Wrapper signs over the ASTM messages
// CO-LOCATED in the same Message Pack, then CLEARS the Evidence field. Only the
// signature travels on the air; the receiver rebuilds the signed bytes from the
// pack's own messages (§4.3.2):
//   "the receiver concatenate all the messages in the Message Pack (excluding
//    the Authentication Message found in the same Message Pack) in ASTM Message
//    Type order and set the Evidence field ... before ... verification."
//
// SAM Authentication Data ON THE WIRE — 89 octets, Evidence cleared:
//   [0]       SAM Type = 0x02                          (RFC 9575 Table 1)
//   [1..4]    VNB (little-endian, DRIP epoch)          (§3.2.4.3, F3411 LE)
//   [5..8]    VNA (little-endian) = VNB + 120 s        (§3.2.4.3)
//   [9..24]   UA DET (16)
//   [25..88]  UA Ed25519 signature (64)
//   -> ASTM "Length" field = 89  ->  5 Auth pages (Appendix B.1, "0 ASTM msgs").
//
// SIGNED bytes (UA-Signed Evidence Structure, §4.1 Figure 4 field order):
//   VNB(4) || VNA(4) || Evidence || UA_DET(16)
//   Evidence = the pack's NON-Authentication messages (types 0x0,0x1,0x3,0x4,0x5)
//              in ASCENDING Message Type order, each the full 25 octets
//              (§4.3 / §4.3.2). Up to 4 messages (§4.3.3).
//
// LITTLE-ENDIAN NOTE: VNB/VNA are little-endian both in the signed bytes and on
// the wire. This was confirmed from the RFC 9575 Appendix B.2.1 raw example
// (VNA-VNB resolves to a clean interval only in LE) and §3.2.4.3 ("follow the
// format defined in [F3411]", which is little-endian). (Previous standard-form
// code was already LE; that is correct and is retained.)
//
// CALLER CONTRACT (the Wrapper must sign over messages that already exist):
//   1. message_pack_init(&pack);
//   2. add the up-to-4 ASTM messages to be authenticated (message_pack_add);
//   3. drip_wrapper_build(id, &pack, pages, &page_count);    // signs over them
//   4. message_pack_add() each returned page into the SAME pack;
//   5. transmit the pack.
// ---------------------------------------------------------------------------

#define DRIP_WRAPPER_MAX_PAGES   5     // Extended Wrapper is fixed at 89 B -> 5 pages

// Build the Extended-Transport DRIP Wrapper authentication pages for the ASTM
// messages currently held in `astm_pack` (Auth messages, if any, are excluded).
//   id             : the virtual UA's identity — supplies BOTH the DET that goes
//                    on the wire AND the private key that signs. Passing the
//                    identity (rather than a bare DET + an implicit global key)
//                    is what allows several UAs to coexist: a Wrapper is only
//                    meaningful if the DET it carries and the key that signed it
//                    are the same entity (RFC 9374 §3.5.2 binding).
//   astm_pack      : pack holding the ASTM messages to authenticate
//   out            : receives up to 5 Auth pages (25 bytes each)
//   page_count_out : number of pages produced (5)
// Returns true on success (and if the Ed25519 signature was produced).
bool drip_wrapper_build(
    const DETIdentity  &id,
    const MessagePack  *astm_pack,
    uint8_t             out[DRIP_WRAPPER_MAX_PAGES][F3411_MSG_BYTES],
    uint8_t            *page_count_out
);
