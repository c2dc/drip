#pragma once
#include <stdint.h>
#include "message_pack.h"
#include "det_generator.h"   // DET_IDENTITY_SLOTS

// ---------------------------------------------------------------------------
// Raw 802.11 Beacon injection for ASTM F3411-22a Broadcast RID — MULTI-DRONE
//
// Wi-Fi channel: 6 (2.4 GHz) — ASTM F3411-22a §5.4.9.1 (BWFB0010) permits a
//                single "social" channel; channel 6 is the one this PoC uses.
// VSIE OUI: FA-0B-BC, Vendor Type: 0x0D — ASTM F3411-22a Table 20
//
// ---------------------------------------------------------------------------
// WHY THIS REPLACES beacon_tx.* (the AP + esp_wifi_set_vendor_ie path)
//
// The old transmitter ran the ESP32 as a SoftAP and injected the Remote ID
// payload into the beacons the AP firmware generates. That works for ONE drone
// and one drone only: the AP has one BSSID, so every pack leaves from the same
// MAC address. Real Remote ID receivers (OpenDroneID OSM, DroneScanner)
// correlate tracks BY TRANSMITTER MAC, so N virtual UAs sharing one MAC would
// be displayed as a single aircraft flickering between N identities — the
// emulator would be lying, and our own Python observer could not even detect it
// (odid.py starts parsing at offset 36 and never reads the MAC).
//
// So the frames are now built by hand and injected with esp_wifi_80211_tx(),
// which lets each virtual UA carry its OWN source address.
//
// ---------------------------------------------------------------------------
// PROVEN ON HARDWARE (SPIKE_Beacon_Inject, this board, ESP32 core 3.3.8)
//   * Injection works in STA + promiscuous mode. It returns ESP_ERR_INVALID_ARG
//     in AP mode, which is what the old beacon_tx.h recorded and wrongly
//     attributed to the API itself — IDF documents that en_sys_seq must be
//     false once a "connection has been set up", and a started AP is exactly
//     that.
//   * en_sys_seq MUST be false (measured: false -> ESP_OK).
//   * The driver does NOT rewrite the source MAC: three spoofed MACs appeared
//     as three distinct BSSIDs in a Wi-Fi analyser.
//   * NO linker hack is needed. The widely-copied
//     ieee80211_raw_frame_sanity_check override does NOT even link on core
//     3.3.8 (strong symbol in libnet80211.a) and is NOT required.
//
// ---------------------------------------------------------------------------
// DOCUMENTED DIVERGENCES (bench emulator — faithful where it can be)
//   1. ONE radio impersonates up to 3 UAs. Real UAs are 3 independent radios.
//   2. MACs are locally-administered (02:...), not manufacturer-assigned. ASTM
//      §5.4.5.5 NOTE 2 explicitly contemplates non-static MACs for Specific
//      Session ID, so this is defensible — but it is still not a real NIC.
//   3. The TSF Timestamp field is left 0 / driver-filled. A real UA's TSF is
//      its own radio's clock; three virtual UAs cannot have three real TSFs.
//   4. Sequence numbers are synthesised per slot (see below) rather than being
//      a real per-radio counter.
//   5. The SSID content is ours; ASTM does not specify it. It exists only so
//      the beacon is a well-formed 802.11 frame.
//
// SEQUENCE NUMBERS: because en_sys_seq is false, the driver does NOT fill the
// Sequence Control field — it would stay 0 on every frame, which no real
// transmitter does. Each slot therefore keeps its own 12-bit counter, so each
// virtual UA has an independent sequence space like a real radio.
// ---------------------------------------------------------------------------

#define WIFI_CHANNEL_DRIP   6

// Largest frame we can emit: 24 (MAC hdr) + 12 (fixed) + 12 (SSID IE)
// + 10 (rates) + 3 (DS) + 2 + 5 + 228 (max pack) = 296. Rounded up.
#define BEACON_RAW_MAX_FRAME  320

// Start Wi-Fi in STA + promiscuous mode on channel 6 and prepare the per-slot
// frame cache. Call once in setup(), after nvs_flash_init / esp_netif_init /
// esp_event_loop_create_default.
void beacon_tx_raw_init();

// Build, cache and transmit slot `slot`'s beacon carrying `pack`.
// Call once per THAT drone's 3 Hz cycle (i.e. when its pack content changes).
//   msg_counter : ASTM §5.4.4.2 Message Pack counter for this drone
void beacon_tx_raw_send(uint8_t slot, const MessagePack *pack, uint8_t msg_counter);

// Re-transmit slot `slot`'s cached frame unchanged (new sequence number only).
//
// ASTM §5.4.4.2 (BUR0050): "If the data being transmitted has not changed,
// incrementing the Message Counter is optional." This is what lets us beacon at
// ~10 Hz while the pack content updates at 3 Hz — exactly what the old AP path
// did implicitly (the AP beaconed ~10 Hz over an IE refreshed at 3 Hz), and
// what keeps the drones discoverable by channel-hopping scanners.
// No-op if the slot has never been sent or is stopped.
void beacon_tx_raw_repeat(uint8_t slot);

// Stop transmitting for slot `slot` (its beacons cease entirely — the virtual
// UA leaves the air, which is what a landed/powered-down drone does).
void beacon_tx_raw_stop(uint8_t slot);

// This slot's spoofed source MAC (6 bytes), for logging. Never nullptr for a
// valid slot.
const uint8_t *beacon_tx_raw_mac(uint8_t slot);
