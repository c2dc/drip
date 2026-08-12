#pragma once
#include <stdint.h>
#include "drip_hierarchy.h"
#include <stddef.h>

// ---------------------------------------------------------------------------
// DRIP Entity Tag (DET) — RFC 9374
//
// A DET is an HHIT: a 128-bit self-asserting identifier derived from an
// Ed25519 public key via cSHAKE128 (ORCHID construction, RFC 7343 + RFC 9374).
//
// Bit layout of the 16-byte HHIT  — RFC 9374 §3.3, Figure 1:
//   [ Prefix 28b = 2001:0030::/28 | HID 28b = RAA14||HDA14 | HHSI 8b = 0x05 | Hash 64b ]
//   i.e. the Suite ID (HHSI/OGA) sits BETWEEN the HID and the hash (byte 7),
//   NOT right after the prefix. (Corrected per RFC 9374 Fig 1 — previously the
//   Suite and HID were swapped, which produced a non-conformant DET.)
//
// ---------------------------------------------------------------------------
// MULTI-DRONE CHANGE (this revision)
//
// The PoC used to hold exactly ONE identity, and det_sign() signed with a
// module-private seed that no caller could choose. The bench fleet emulates up
// to 3 virtual UAs, each of which MUST have its own key and therefore its own
// DET (RFC 9374 §3.5.2 — a DET is bound to the key it was derived from; two
// UAs sharing one key would be one UA wearing two names).
//
// So identity is now a VALUE (DETIdentity) drawn from a hardcoded slot table,
// and signing takes the identity to sign with (det_sign_with).
//
//   struct DETKeyPair  -> REMOVED, replaced by DETIdentity (adds .seed/.valid)
//   det_sign(...)      -> REMOVED, replaced by det_sign_with(id, ...)
//   det_load_hardcoded -> KEPT as the slot-0 wrapper (slot 0 IS the old identity,
//                         byte-for-byte), so a 1-drone fleet behaves exactly as
//                         the single-drone PoC always did.
// ---------------------------------------------------------------------------

#define DET_BYTES           16
#define ED25519_SEED_BYTES  32   // private key seed
#define ED25519_PUBKEY_BYTES 32
#define SESSION_ID_BYTES    20   // ASTM F3411-22a UAS ID field width

// Suite ID 5 = EdDSA/cSHAKE128  — RFC 9374 Table 7 (this is the HHSI/OGA value)
#define HHIT_OGA_ID         0x05

// Test hierarchy — these are the locked PoC values (RAA=1000, HDA=2000).
// Per RFC 9374 §3.3 production values MUST be obtained from the IANA DRIP
// Registry; do not use research values in deployment.
//
// NOTE: every fleet slot shares RAA/HDA on purpose — one HDA registering
// several UAs is exactly the real hierarchy shape (RFC 9575 §6.4.2). Only the
// ORCHID hash (lower 64 bits), which is key-derived, differs between slots.
// The UA hierarchy numbers now live in ONE place for the whole project.
// Change them in drip_hierarchy.h, never here. The old names are kept as
// aliases so existing call sites (and any external notes) still work.
#define HHIT_TEST_RAA       DRIP_UA_RAA
#define HHIT_TEST_HDA       DRIP_UA_HDA

// How many hardcoded test identities exist in the slot table
// (det_generator.cpp, IDENTITY_TABLE). To emulate more than 3 drones you must
// add rows here AND raise FLEET_MAX in drone_fleet.h — see the note there.
#define DET_IDENTITY_SLOTS  3

// ---------------------------------------------------------------------------
// One virtual UA's cryptographic identity.
//
// *** TEST ARTEFACT: .seed is a PRIVATE KEY sitting in plain flash. ***
// Acceptable only because every key in this project is a published bench value
// with no real registration behind it. A real UA keeps its seed in secure
// storage and never exposes it in a struct like this.
// ---------------------------------------------------------------------------
struct DETIdentity {
    uint8_t det[DET_BYTES];                 // the HHIT (16 bytes) — RFC 9374 Fig 1
    uint8_t pubkey[ED25519_PUBKEY_BYTES];   // HI (Host Identity)
    uint8_t seed[ED25519_SEED_BYTES];       // Ed25519 private seed (RFC 8032)
    bool    valid;                          // false => signing unavailable
};

// Derive a DET from an Ed25519 public key for an ARBITRARY (RAA, HDA) hierarchy.
// RFC 9374 §3.5.2 + Figure 1 (Suite 5, EdDSA25519 HOST_ID). This is the single
// DET implementation used for the UA DETs and, in DRIP_TEST_BE builds, for the
// fabricated Apex/RAA/HDA parent DETs (drip_registration.cpp).
void det_compute(const uint8_t pubkey[ED25519_PUBKEY_BYTES],
                 uint16_t raa, uint16_t hda, uint8_t det[DET_BYTES]);

// Load hardcoded test identity `slot` (0 .. DET_IDENTITY_SLOTS-1).
// Derives the public key from the seed, self-checks it against the recorded
// public key, computes the DET and self-checks it against the recorded DET.
// Returns false if slot is out of range or the Ed25519 backend is unavailable
// (in which case .det is still correct but .valid is false and signing fails).
bool det_load_identity(uint8_t slot, DETIdentity &out);

// Back-compat convenience: slot 0 IS the original single-drone PoC identity
// (DET 2001:0030:FA07:D005:31E0:1AED:4E7E:CF5C). Identical to
// det_load_identity(0, out).
bool det_load_hardcoded(DETIdentity &out);

// Sign arbitrary data with a SPECIFIC identity's Ed25519 private key.
// Returns false (and zero-fills sig) if the identity is invalid or signing fails.
//
// Replaces the old det_sign(), which could only ever sign with one hidden key —
// the single blocker that made a multi-identity fleet impossible.
bool det_sign_with(const DETIdentity &id,
                   const uint8_t *data, size_t len, uint8_t sig[64]);

// Encode a DET as the 20-byte ASTM F3411-22a UAS ID Session ID field.
// Byte 0 = 0x01 (SSI Type IETF DRIP), bytes 1–16 = DET, bytes 17–19 = 0x00.
// Per ASTM F3411-22a Table 5 (Specific Session ID) and RFC 9374 §4.
void det_to_session_id(const uint8_t det[DET_BYTES], uint8_t out[SESSION_ID_BYTES]);

// Print "<label> = 2001:0030:...." to Serial (boot diagnostics / fleet list).
void det_print(const char *label, const uint8_t det[DET_BYTES]);
