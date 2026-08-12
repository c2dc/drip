#pragma once

// ---------------------------------------------------------------------------
// Project-wide build configuration.
//
// Put compile-time switches HERE (not in the .ino). In the Arduino build model
// each .cpp is compiled separately, and a #define in the .ino is visible only
// inside the .ino itself — it does NOT reach drip_registration.cpp etc. Defining
// the flag in this shared header (included by every unit that needs it) makes it
// consistent across all translation units.
//
// DRIP_TEST_BE : provision a self-consistent FAKE Apex/RAA/HDA Broadcast
//                Endorsement chain (drip_registration.*) for validation only.
//                *** Comment this line out for a production / flight image. ***
// ---------------------------------------------------------------------------

#define DRIP_TEST_BE
