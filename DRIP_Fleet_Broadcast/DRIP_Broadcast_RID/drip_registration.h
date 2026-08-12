#pragma once
#include <stdint.h>
#include "drip_config.h"   // defines DRIP_TEST_BE — MUST be visible in every
                           // translation unit, not just the .ino (Arduino quirk)
#include "drip_link.h"
#include "det_generator.h"

// ---------------------------------------------------------------------------
// DRIP test registration / Broadcast Endorsement chain  — VALIDATION ONLY
//
//   *** This entire unit is compiled ONLY when DRIP_TEST_BE is defined. ***
//   *** It MUST NOT be compiled into a production / flight image.       ***
//
// Purpose (agreed scope): fabricate a SELF-CONSISTENT BE chain so the encoder,
// the 7-page Link framing, and the signed-field ordering can be validated
// end-to-end against a DRIP receiver — without real registration data.
//
//   Apex --(BE: Apex,RAA)--> RAA --(BE: RAA,HDA)--> HDA --(BE: HDA,UA_i)--> UA_i
//
// Each link is a REAL Ed25519 signature by the parent key over
//   VNB || VNA || DET_child || HI_child || DET_parent
// so a verifier holding the (preconfigured) Apex HI can walk the chain:
//   verify(Apex,RAA) -> trust RAA HI -> verify(RAA,HDA) -> trust HDA HI
//   -> verify(HDA,UA_i) -> trust UA_i's DET<->HI binding.
//
// ---------------------------------------------------------------------------
// MULTI-DRONE CHANGE (this revision)
//
// The chain used to have exactly one leaf, because there was exactly one UA.
// The bench fleet emulates up to DET_IDENTITY_SLOTS UAs, and RFC 9575 §6.4.2
// requires EVERY UA to chain to the trust anchor — so the HDA now issues ONE
// BE PER UA. The upper two links are shared, which is also the real shape: an
// HDA registers many UAs but is itself endorsed once by its RAA.
//
//   drip_reg_init(ua_det, ua_hi)  -> REPLACED by drip_reg_init_fleet(ids, n)
//   drip_reg_next_link()          -> now takes the drone slot
//   drip_reg_hda_ua_sam(out)      -> now takes the drone slot
//
// Each slot also keeps its OWN Cycle-B rotation cursor, so drone 2 is not
// forced to transmit the same link of the chain as drone 0 in the same round.
//
// Garbage/zero fill was rejected on purpose: it would validate paging only, not
// the byte order fed to the signer, because nothing would verify.
//
// SAFETY: the parent identities use the experimental test prefix and arbitrary
// illustrative RAA/HDA values (NOT IANA-registered). No conformant verifier
// will accept this chain as a real registered hierarchy — which is exactly what
// we want for a test artefact. A loud warning is printed at init.
//
// Requires the Arduino "Crypto" library (Ed25519) — i.e. det_generator.cpp
// Path A (#define USE_ARDUINO_CRYPTO_LIB). PSA-only builds are not supported
// for test-BE signing (and Path B was removed this revision).
// ---------------------------------------------------------------------------

#ifdef DRIP_TEST_BE

// BE validity window. BEs are long-lived registration artefacts, so VNA is set
// far ahead of VNB (unlike the ~120 s UA-signed-evidence window).
#define DRIP_BE_VALIDITY_S   86400UL   // 24 h test window

// Build the fake Apex/RAA/HDA keypairs, derive their DETs, sign the two shared
// upper links, and sign ONE BE:HDA,UA per supplied identity.
// Call once in setup(), after the identities are loaded (so the real UA DETs +
// HIs are available) and after WiFi is up.
//
//   ids     : array of loaded UA identities (one per virtual drone)
//   n       : how many (1 .. DET_IDENTITY_SLOTS)
//   verbose : true  -> print the FAKE-chain warning, the three parent DETs,
//                      and one line per UA leaf (~5+n lines).
//             false -> print a single summary line.
//
// WHY verbose IS A PARAMETER, not a read of drip_debug_enabled():
//   this runs from the fleet's provisioning path, NOT inside a drone's build,
//   so the global debug flag holds whatever the last-built drone left there —
//   it would be stale and the output would flap unpredictably. The caller
//   knows the real intent, so it states it.
//
// The caller is expected to pass true on the FIRST call (so the "this chain is
// fake" warning and the anchor DETs are always on the record at boot) and
// false for later re-signs, which happen on every `fleet` / `fleet set` and
// would otherwise bury the operator's own commands.
void drip_reg_init_fleet(const DETIdentity *ids, uint8_t n, bool verbose);

// Return the next BE to transmit for slot `slot`'s Cycle B, rotating per a test
// schedule that approximates RFC 9575 §6.3 (HDA,UA most frequent; RAA,HDA and
// Apex,RAA interspersed). Each slot has an independent cursor.
// Returns nullptr if the slot was never provisioned.
const BroadcastEndorsement *drip_reg_next_link(uint8_t slot);

// Serialise slot `slot`'s BE:HDA,UA SAM data (137 octets) into 'out' for
// Manifest hashing (RFC §4.4.2 references BE:HDA,UA specifically).
// Returns the length (137), or 0 if the slot was never provisioned.
uint8_t drip_reg_hda_ua_sam(uint8_t slot, uint8_t out[DRIP_LINK_SAM_BYTES]);

#endif // DRIP_TEST_BE
