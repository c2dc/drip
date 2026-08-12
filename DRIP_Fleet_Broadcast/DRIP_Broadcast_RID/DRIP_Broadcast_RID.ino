// DRIP Broadcast RID — ESP32 Firmware  (MULTI-DRONE BENCH EMULATOR)
//
// Implements ASTM F3411-22a Broadcast Remote ID over WiFi Beacon
// with DRIP authentication (RFC 9374 DET + RFC 9575 Link + Wrapper + Manifest).
//
// ---------------------------------------------------------------------------
// WHAT THIS BUILD IS
//   A BENCH EMULATOR. One ESP32 impersonates 1..3 independent virtual UAs, each
//   with its own DET, its own Ed25519 key, its own MAC address, its own flight
//   track and its own DRIP state. It is NOT flight firmware, and several
//   deliberate divergences are documented at their source (grep "DIVERGENCE").
//
//   Selectable at runtime over serial:
//       fleet 1 / fleet 2 / fleet 3          1-3 drones, distinct flights
//       fleet 3 same 5                       3 drones all replaying flight 5
//       fleet set 1 12                       give slot 1 flight 12
//       fleet list | focus <slot> | debug off|on|<slot>
//       list | info | next | reset | stop | <number>     (act on the focused slot)
//
//   N = 1 is the degenerate case: slot 0 IS the original PoC identity
//   (DET 2001:0030:FA07:D005:31E0:1AED:4E7E:CF5C), so a 1-drone fleet behaves
//   exactly like the single-drone firmware always did.
//
// ---------------------------------------------------------------------------
// TRANSMISSION CYCLE — per drone, 3 Hz, rotating across three phases:
//
//   Cycle A (cycle % 3 == 0)  — DRIP Wrapper  — 8 messages
//     [0] Basic ID   [1] Location   [2] System   [3-7] Auth Wrapper (5 pages,
//     Extended Transport, RFC 9575 §4.3.2 — Evidence cleared on the wire)
//
//   Cycle B (cycle % 3 == 1)  — DRIP Link / BE chain — 9 messages
//     [0] Basic ID   [1] Location   [2-8] Auth Link (7 pages, BE Figure 5)
//     *** System is intentionally NOT sent in Cycle B — see CYCLE-B NOTE below.
//
//   Cycle C (cycle % 3 == 2)  — DRIP Manifest — 9 messages
//     [0] Basic ID   [1] Location   [2] System   [3-8] Auth Manifest (6 pages)
//
//   Drones are PHASE-STAGGERED: drone i starts at phase i and rebuilds 333/N ms
//   after drone i-1, so at most one Ed25519 signature is ever in flight.
//   Each drone's beacon is then REPEATED at ~10 Hz with an unchanged Message
//   Counter (ASTM §5.4.4.2 permits repeating unchanged data) — see drone_fleet.h.
//
// ---------------------------------------------------------------------------
// CYCLE-B NOTE (design decision — retained from the single-drone build)
//   A compliant DRIP Link is a Broadcast Endorsement of 137 octets = 7 ASTM
//   Auth pages (RFC 9575 §4.2, Appendix B.1). Basic ID + Location + System +
//   7 Link pages = 10 messages, but a Message Pack in one 802.11 VSIE is capped
//   at 9 messages / 255-byte IE body (message_pack.h). To fit, Cycle B carries
//   Basic ID + Location + the 7 Link pages (= 9). System is omitted from Cycle B
//   only; it is still broadcast in Cycles A and C (it is a static message, so
//   its refresh rate is unaffected). Reversible if you prefer the Link in its
//   own dedicated pack/beacon instead.
// ---------------------------------------------------------------------------
//
// DRIP_TEST_BE: compile-time switch that provisions a SELF-CONSISTENT fake
// Apex/RAA/HDA Broadcast Endorsement chain (drip_registration.*) so the Link
// and signatures can be validated against a DRIP receiver. *** Never enable in
// a production/flight image. *** Comment it out to build without a Link.
//
// ---------------------------------------------------------------------------
// CHANGES THIS REVISION (multi-drone)
//   * loop() no longer builds packs. It is now: fleet_cmd(); fleet_tick(millis());
//     All of the A/B/C logic moved VERBATIM into drone_fleet.cpp, once per drone.
//   * The singletons g_kp / g_manifest / g_msg_counter / g_cycle are gone —
//     they became per-drone fields of VirtualDrone (drone_fleet.h).
//   * loop() no longer calls delay(333). The fleet is deadline-driven, because
//     three drones staggered 111 ms apart cannot be served by one blocking
//     delay. loop() now spins freely and fleet_tick() acts only when a drone's
//     deadline has passed.
//   * beacon_tx.* (SoftAP + esp_wifi_set_vendor_ie) was DELETED and replaced by
//     beacon_tx_raw.* (hand-built beacons, esp_wifi_80211_tx, one MAC per drone).
//     The AP path physically cannot represent more than one UA: an AP has one
//     BSSID, and real receivers correlate tracks by transmitter MAC.
//   * flight_sim is no longer used as a fallback. It is a stateless global route,
//     so every drone would sit on the identical synthetic point. flight_sim.*
//     remains in the tree, uncalled.
// ---------------------------------------------------------------------------

// Build flags live in drip_config.h so DRIP_TEST_BE reaches ALL .cpp files
// (an .ino #define is local to the sketch translation unit only).
#include "drip_config.h"   // defines DRIP_TEST_BE for the test/validation build

#include <Arduino.h>

extern "C" {
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
}

#include "beacon_tx_raw.h"   // raw 802.11 injection, one MAC per virtual drone
#include "drone_fleet.h"     // the virtual UA fleet + its scheduler + commands

// ---------------------------------------------------------------------------
void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n=== DRIP Broadcast RID -- ESP32 (multi-drone bench emulator) ===");
    Serial.println("    up to 3 virtual UAs, each with its own DET / key / MAC / track");
    Serial.println("    per drone: 3 Hz Wrapper/Link/Manifest rotation, ~10 Hz beacons");

    esp_err_t nvs = nvs_flash_init();
    if (nvs == ESP_ERR_NVS_NO_FREE_PAGES || nvs == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs = nvs_flash_init();
    }
    ESP_ERROR_CHECK(nvs);
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    // NOTE: esp_netif_init() is called inside beacon_tx_raw_init(), which owns
    // the whole Wi-Fi bring-up (STA + promiscuous + channel 6).

    // Radio first: fleet_init() -> drip_manifest_init() seeds the hash chain
    // from esp_random(), which needs the RF hardware to be running to be a true
    // hardware RNG.
    beacon_tx_raw_init();

    // Loads the identity table, provisions the BE chain, and starts ONE drone on
    // flight 0 — i.e. exactly the original single-drone PoC.
    fleet_init();

    Serial.println("[OK] Setup complete -- type 'fleet 3' for three drones.");
}

// ---------------------------------------------------------------------------
void loop() {
    fleet_cmd();            // poll serial (fleet / focus / debug / legacy cmds)
    fleet_tick(millis());   // non-blocking: serves only drones whose deadline hit
}
