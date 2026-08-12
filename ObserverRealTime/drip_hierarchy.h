// =============================================================================
//  drip_hierarchy.h — THE SINGLE SOURCE OF TRUTH FOR THE DRIP HIERARCHY
//
//  ***  IF YOU ARE SWAPPING IN A REAL HIERARCHY, THIS IS THE FILE.  ***
//
//  Everything that defines WHO the registration authorities are, and what
//  numbers they hold, lives here and ONLY here:
//
//      * the RAA / HDA numbers of every entity (Apex, RAA, HDA, and the UAs)
//      * the private seeds of the three test parents
//
//  det_generator.h and drip_registration.cpp include this and define none of
//  it themselves. Previously these values were spread across four files in two
//  languages, agreeing only because they were generated together — and nothing
//  told you when you missed one. A missed edit surfaced as E-LINK-* in the
//  observer, i.e. looking exactly like a firmware fault.
//
//  The Python side has its own copy of the PUBLIC half in hierarchy.json.
//  After changing anything here, run:
//
//      python3 check_hierarchy.py --header drip_hierarchy.h --json hierarchy.json
//
//  which re-derives every DET, proves the zones nest, and proves this file and
//  hierarchy.json still agree. It is the only thing standing between an edit
//  here and a silent mismatch.
//
// -----------------------------------------------------------------------------
//  THE RULE THAT MATTERS: THE HIERARCHY MUST NEST
//
//  RFC 9886 §6 derives every DNS zone from the RAA/HDA nibbles carried INSIDE
//  the DET (RFC 9374 §3.5.2):
//
//      Apex   owns  2001:30::/28              (the whole ORCHID prefix)
//      RAA    owns  2001:3x:xxx0::/44         <- fixed by its RAA number
//      HDA    owns  2001:3x:xxxy:yy00::/56    <- fixed by its RAA *and* HDA
//      UA     lives inside its HDA's /56
//
//  So a child's DET MUST fall inside its parent's zone, and that is decided
//  ENTIRELY by these numbers — the keys only affect the trailing 64-bit hash.
//
//  A parent therefore has to carry the SAME RAA/HDA numbers as the children it
//  registers. That is not a convention, it is arithmetic: give the HDA
//  different numbers and its /56 simply does not contain its own UAs, and there
//  is no delegation chain for DNSSEC to sign.
//
//  HISTORICAL NOTE (why this file exists): the bench previously used
//  Apex=0/0, RAA=1/0, HDA=1/1 while the UAs used 1000/2000. Those numbers are
//  self-consistent for the OFFLINE signature walk (RFC 9575 §6.4.2 only checks
//  signatures, never zones), so every self-test passed. But:
//
//      HDA 1/1        -> DET 2001:30:40:105:...  -> zone 2001:30:40:100::/56
//      UA  1000/2000  -> DET 2001:30:fa07:d005:...
//      UA inside the HDA's zone?  ->  FALSE
//
//  The chain verified perfectly and was undelegable. Fixed below by giving the
//  parents the UAs' own numbers.
// =============================================================================

#ifndef DRIP_HIERARCHY_H
#define DRIP_HIERARCHY_H

#include <stdint.h>

// -----------------------------------------------------------------------------
//  1. THE HIERARCHY NUMBERS
//
//  RFC 9374 §3.5.2: RAA and HDA are 14-bit fields. Valid range 0..16383.
//
//  *** TEST VALUES. No IANA registration stands behind them (RFC 9374 §3.3).
//  *** Replace with the assigned numbers when a real hierarchy is available.
//  *** Change them HERE ONLY, then rerun check_hierarchy.py.
// -----------------------------------------------------------------------------

// The UA's numbers. Every virtual UA in the fleet is registered by the same
// HDA, which is the realistic shape: one HDA registers many aircraft.
#define DRIP_UA_RAA        255u    // 0x00FF
#define DRIP_UA_HDA        14340u  // 0x3804

// The Apex owns the whole 2001:30::/28 prefix and sits above all RAAs, so it
// holds no RAA/HDA of its own. Zero is the "no delegation applied yet" value.
#define DRIP_APEX_RAA      0u
#define DRIP_APEX_HDA      0u

// The RAA that issued DRIP_UA_RAA. It must carry the SAME RAA number as the
// UAs beneath it (see "THE RULE THAT MATTERS" above) and HDA=0, because an RAA
// is the entity that hands OUT HDA numbers and has not been given one.
#define DRIP_RAA_RAA       DRIP_UA_RAA
#define DRIP_RAA_HDA       0u

// The HDA that registered the UAs. It must carry BOTH of the UAs' numbers, or
// its /56 zone will not contain them.
#define DRIP_HDA_RAA       DRIP_UA_RAA
#define DRIP_HDA_HDA       DRIP_UA_HDA

// Compile-time enforcement that the parent authorities carry the SAME RAA/HDA
// numbers as the UAs. This is what keeps the fabricated Apex->RAA->HDA->UA chain
// coherent: an RAA issues its own RAA number, and an HDA carries both the RAA it
// lives under and its own HDA number. These guards cannot validate a DET (that
// needs the keys -> check_hierarchy.py); they catch the number-mismatch mistake.
//
// NOTE on zones (RFC 9886 §3, §6.2.1.3): the RAA occupies a /44 and the HDA a
// /56 in DNS, but the boundary is the "nibble borrow" of §6.2.1.3 (the RAA
// borrows the top two bits of the HDA field), NOT a plain prefix-containment of
// the HDA's DET inside the RAA's /44. Do not reintroduce a "/44 contains HDA
// DET" test here; that is not the RFC rule. check_hierarchy.py implements the
// real range/reserved-value checks.
#if (DRIP_RAA_RAA != DRIP_UA_RAA)
#error "drip_hierarchy.h: DRIP_RAA_RAA must equal DRIP_UA_RAA (an RAA issues the \
RAA number its UAs live under)."
#endif
#if (DRIP_HDA_RAA != DRIP_UA_RAA) || (DRIP_HDA_HDA != DRIP_UA_HDA)
#error "drip_hierarchy.h: DRIP_HDA_RAA/DRIP_HDA_HDA must equal DRIP_UA_RAA/ \
DRIP_UA_HDA (the HDA that registered the UAs carries both of their numbers)."
#endif
#if (DRIP_UA_RAA > 16383u) || (DRIP_UA_HDA > 16383u)
#error "drip_hierarchy.h: RAA and HDA are 14-bit fields (RFC 9374 §3.3); \
maximum 16383."
#endif
// RFC 9886 §3: HDA values 0, 4096, 8192, 12288 are RESERVED for the RAA's own
// operational use (the nibble-borrow bases). A UA/HDA must not use them.
#if (DRIP_UA_HDA == 0u) || (DRIP_UA_HDA == 4096u) || (DRIP_UA_HDA == 8192u) || (DRIP_UA_HDA == 12288u)
#error "drip_hierarchy.h: DRIP_UA_HDA is a reserved value (0/4096/8192/12288, \
RFC 9886 §3 / §6.2.1.3). Pick another HDA."
#endif

// -----------------------------------------------------------------------------
//  2. THE TEST PARENT KEYS
//
//  *** THESE ARE PUBLISHED PRIVATE KEYS. They are test material and provide NO
//  *** security whatsoever — anyone reading this repository can forge the whole
//  *** chain. They exist so the bench can fabricate a self-consistent
//  *** Apex→RAA→HDA→UA chain with no registry.
//
//  A REAL deployment does NOT hold these: the Apex/RAA/HDA private keys stay
//  with the registries, which sign the Broadcast Endorsements offline. Only the
//  resulting BEs (and the PUBLIC keys) would ever reach a UA. When a real
//  hierarchy arrives, drip_registration.cpp is what gets replaced — the
//  fabrication step goes away and the real BEs are provisioned instead.
//
//  Only used when DRIP_TEST_BE is defined (drip_config.h).
// -----------------------------------------------------------------------------

#define DRIP_APEX_SEED_INIT { \
    0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7, 0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF, \
    0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7, 0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF }

#define DRIP_RAA_SEED_INIT { \
    0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7, 0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF, \
    0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7, 0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF }

#define DRIP_HDA_SEED_INIT { \
    0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7, 0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF, \
    0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7, 0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF }

// -----------------------------------------------------------------------------
//  3. EXPECTED RESULT (informational — derived, not input)
//
//  With the numbers and seeds above, the firmware prints these at boot. They
//  are reproduced in hierarchy.json for the Python side, and check_hierarchy.py
//  re-derives them from scratch rather than trusting either copy.
//
//    Apex 0/0        2001:30:0:5:70f9:e8e9:b564:f448
//    RAA  255/0      2001:30:3fc0:5:9024:e82a:8fd0:afb8       zone 2001:30:3fc0::/44
//    HDA  255/14340  2001:30:3ff8:405:d162:233e:9b7e:feee     zone 2001:30:3ff8:400::/56
//    UA0  255/14340  2001:30:3ff8:405:d952:5618:fbc9:c3cf     (new keypair)
//    UA1  255/14340  2001:30:3ff8:405:8412:4323:5d3c:a050
//    UA2  255/14340  2001:30:3ff8:405:a57e:87ab:5388:cbb8
//
//  DET METHOD: RAW 32-byte key (RFC 9374 reference / Moskowitz det-gen.py),
//  NOT the 4-byte-wrapped HIP HOST_ID parameter. UA0 = d952:5618:fbc9:c3cf was
//  verified byte-for-byte against the reference generator and a live deployment.
//
//  RAA/HDA = 255/14340. RAA 255 is in the ISO 3166-1 country range; used here
//  as a test stand-in. HDA 14340 is valid (block 11, != reserved base 12288).
//
//  A UA's DET depends on its OWN RAA/HDA and its OWN key, never on its parents'.
// -----------------------------------------------------------------------------

#endif // DRIP_HIERARCHY_H
