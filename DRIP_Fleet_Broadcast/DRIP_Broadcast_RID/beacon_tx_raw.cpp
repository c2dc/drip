#include "beacon_tx_raw.h"
#include <string.h>
#include <Arduino.h>

extern "C" {
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
}

// ---------------------------------------------------------------------------
// Per-drone spoofed MAC addresses.
//
// First octet 0x02 = 0000 0010:
//   bit 0 (I/G) = 0 -> unicast (a beacon's SOURCE must be an individual address)
//   bit 1 (U/L) = 1 -> LOCALLY ADMINISTERED
// Locally-administered addresses are guaranteed never to collide with a real
// manufacturer-assigned NIC — important when putting spoofed frames on a shared
// bench. 0x44 0x52 0x49 0x50 spells "DRIP"; the last octet is the slot index.
//
// To add a 4th drone, add a row here AND raise DET_IDENTITY_SLOTS
// (det_generator.h) AND FLEET_MAX (drone_fleet.h).
// ---------------------------------------------------------------------------
static const uint8_t SLOT_MAC[DET_IDENTITY_SLOTS][6] = {
    { 0x02, 0x44, 0x52, 0x49, 0x50, 0x00 },   // 02:44:52:49:50:00  drone 0
    { 0x02, 0x44, 0x52, 0x49, 0x50, 0x01 },   // 02:44:52:49:50:01  drone 1
    { 0x02, 0x44, 0x52, 0x49, 0x50, 0x02 },   // 02:44:52:49:50:02  drone 2
};

// ---------------------------------------------------------------------------
// Per-slot frame cache. Holding the built frame lets beacon_tx_raw_repeat()
// re-send it at ~10 Hz without rebuilding or re-signing anything.
// ---------------------------------------------------------------------------
struct SlotTx {
    uint8_t  frame[BEACON_RAW_MAX_FRAME];
    uint16_t len;
    uint16_t seq;        // 12-bit 802.11 sequence number for this virtual radio
    bool     armed;      // a frame has been built at least once
};
static SlotTx  g_tx[DET_IDENTITY_SLOTS];
static bool    g_ready = false;

// Byte offsets into the frame we build (IEEE 802.11-2016 §9.3.3.3).
#define OFF_SEQ_CTRL   22    // Sequence Control, 2 bytes LE

// ---------------------------------------------------------------------------
void beacon_tx_raw_init() {
    memset(g_tx, 0, sizeof(g_tx));

    esp_netif_init();
    // NOTE: no esp_netif_create_default_wifi_ap() — we are NOT an AP. The AP
    // beacon engine would transmit with the real interface MAC, adding a
    // phantom transmitter that is not one of our drones.

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));   // never persist to NVS

    // STA mode, never connected: injection is accepted here (proven by the
    // SPIKE_Beacon_Inject bench test), and nothing else beacons.
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Promiscuous + explicit channel: the prerequisite for raw injection, and it
    // pins us to channel 6 with no STA association to roam away.
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_channel(WIFI_CHANNEL_DRIP, WIFI_SECOND_CHAN_NONE));

    g_ready = true;

    uint8_t if_mac[6] = {0};
    esp_wifi_get_mac(WIFI_IF_STA, if_mac);
    Serial.printf("[TX] raw injection ready — STA+promiscuous, channel %d\n",
                  WIFI_CHANNEL_DRIP);
    Serial.printf("[TX] real STA MAC %02X:%02X:%02X:%02X:%02X:%02X "
                  "(NOT used on the air — every beacon is spoofed per drone)\n",
                  if_mac[0], if_mac[1], if_mac[2], if_mac[3], if_mac[4], if_mac[5]);
}

// ---------------------------------------------------------------------------
// Build a complete Beacon frame for `slot` carrying `pack`.
// Returns the frame length, or 0 on error.
//
// Layout (IEEE 802.11-2016 §9.3.3.3 + ASTM F3411-22a §5.4.9.2 / Table 20):
//   [ 0.. 1] Frame Control  : 0x80 0x00 -> type 0 (management), subtype 8 (beacon)
//   [ 2.. 3] Duration       : 0 (hardware)
//   [ 4.. 9] Addr1 (DA)     : broadcast
//   [10..15] Addr2 (SA)     : this drone's MAC
//   [16..21] Addr3 (BSSID)  : this drone's MAC
//   [22..23] Sequence Ctrl  : frag(4b)=0 | seq(12b) — we fill it (en_sys_seq=false)
//   [24..31] Timestamp/TSF  : 0 (divergence — see beacon_tx_raw.h)
//   [32..33] Beacon Interval: 0x0064 = 100 TU (~102.4 ms) — ASTM (BWFB0040) caps at 200 TU
//   [34..35] Capability     : 0x0421 = ESS | Short Preamble | Short Slot Time (open)
//   then tagged params: SSID(0), Supported Rates(1), DS Param(3), Vendor(221)
// ---------------------------------------------------------------------------
static uint16_t build_frame(uint8_t slot, const MessagePack *pack,
                            uint8_t msg_counter, uint8_t *out) {
    const uint8_t pack_len  = message_pack_bytes(pack);
    const int     vsie_body = 5 + (int)pack_len;   // OUI(3)+Type(1)+Counter(1)+pack

    if (vsie_body > 255) {
        Serial.printf("[TX] slot %u: VSIE body %d > 255 — pack too large\n",
                      (unsigned)slot, vsie_body);
        return 0;
    }

    int i = 0;

    // ---- MAC header (24) ----
    out[i++] = 0x80; out[i++] = 0x00;                 // Frame Control: Beacon
    out[i++] = 0x00; out[i++] = 0x00;                 // Duration
    for (int k = 0; k < 6; k++) out[i++] = 0xFF;                 // Addr1 = broadcast
    for (int k = 0; k < 6; k++) out[i++] = SLOT_MAC[slot][k];    // Addr2 = SA
    for (int k = 0; k < 6; k++) out[i++] = SLOT_MAC[slot][k];    // Addr3 = BSSID
    out[i++] = 0x00; out[i++] = 0x00;                 // Sequence Control (filled later)

    // ---- Fixed parameters (12) ----
    for (int k = 0; k < 8; k++) out[i++] = 0x00;      // Timestamp (TSF) — divergence
    out[i++] = 0x64; out[i++] = 0x00;                 // Beacon Interval = 100 TU
    out[i++] = 0x21; out[i++] = 0x04;                 // Capability = 0x0421 (open ESS)

    // ---- SSID IE (0) ----
    // Not an ASTM field: the Remote ID payload is the vendor IE. A beacon with
    // no SSID IE is malformed and some receivers drop it, so each drone gets a
    // distinct, obviously-synthetic SSID.
    const char *ssid_prefix = "DRIP-RID-";
    const uint8_t ssid_len = (uint8_t)(strlen(ssid_prefix) + 1);
    out[i++] = 0x00;
    out[i++] = ssid_len;
    for (size_t k = 0; k < strlen(ssid_prefix); k++) out[i++] = (uint8_t)ssid_prefix[k];
    out[i++] = (uint8_t)('0' + slot);

    // ---- Supported Rates IE (1) ----
    // High bit set = basic rate. 1/2/5.5/11 basic; 18/24/36/54 additional.
    out[i++] = 0x01; out[i++] = 0x08;
    out[i++] = 0x82; out[i++] = 0x84; out[i++] = 0x8B; out[i++] = 0x96;
    out[i++] = 0x24; out[i++] = 0x30; out[i++] = 0x48; out[i++] = 0x6C;

    // ---- DS Parameter Set IE (3) ----
    out[i++] = 0x03; out[i++] = 0x01; out[i++] = WIFI_CHANNEL_DRIP;

    // ---- Vendor Specific IE (221 / 0xDD) — ASTM F3411-22a Table 20 ----
    //   [0xDD][Length = 8+N*25][FA 0B BC][0x0D][Message Counter][Message Pack]
    // Byte-identical to what the superseded AP path emitted (old beacon_tx.cpp
    // lines 70-75), so the payload a receiver sees is unchanged — only the
    // frame carrying it is now ours.
    out[i++] = 0xDD;
    out[i++] = (uint8_t)vsie_body;
    out[i++] = 0xFA; out[i++] = 0x0B; out[i++] = 0xBC;   // OUI (ASD-STAN)
    out[i++] = 0x0D;                                      // Vendor Type = Open Drone ID
    out[i++] = msg_counter;                               // ASTM §5.4.4.2
    memcpy(&out[i], pack->buf, pack_len); i += pack_len;

    return (uint16_t)i;
}

// Stamp this slot's next 802.11 sequence number into the cached frame.
// Sequence Control: bits 0-3 fragment (0), bits 4-15 sequence (12-bit, wraps).
static void stamp_sequence(SlotTx *tx) {
    uint16_t sc = (uint16_t)((tx->seq & 0x0FFF) << 4);
    tx->frame[OFF_SEQ_CTRL]     = (uint8_t)(sc & 0xFF);
    tx->frame[OFF_SEQ_CTRL + 1] = (uint8_t)(sc >> 8);
    tx->seq = (uint16_t)((tx->seq + 1) & 0x0FFF);
}

// ---------------------------------------------------------------------------
void beacon_tx_raw_send(uint8_t slot, const MessagePack *pack, uint8_t msg_counter) {
    if (!g_ready || slot >= DET_IDENTITY_SLOTS) return;
    SlotTx *tx = &g_tx[slot];

    uint16_t len = build_frame(slot, pack, msg_counter, tx->frame);
    if (len == 0) { tx->armed = false; return; }
    tx->len   = len;
    tx->armed = true;

    stamp_sequence(tx);
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, tx->frame, tx->len, false);
    if (err != ESP_OK)
        Serial.printf("[TX] slot %u esp_wifi_80211_tx error: 0x%X (%s)\n",
                      (unsigned)slot, (unsigned)err, esp_err_to_name(err));
}

void beacon_tx_raw_repeat(uint8_t slot) {
    if (!g_ready || slot >= DET_IDENTITY_SLOTS) return;
    SlotTx *tx = &g_tx[slot];
    if (!tx->armed || tx->len == 0) return;

    // Same bytes, same Message Counter (ASTM §5.4.4.2 allows this when the data
    // has not changed) — only the 802.11 sequence number advances.
    stamp_sequence(tx);
    esp_wifi_80211_tx(WIFI_IF_STA, tx->frame, tx->len, false);
}

void beacon_tx_raw_stop(uint8_t slot) {
    if (slot >= DET_IDENTITY_SLOTS) return;
    // Simply stop transmitting: this virtual UA disappears from the air, which
    // is exactly what a landed / powered-down drone does. (The old AP path had
    // to strip an IE instead, because the AP kept beaconing regardless.)
    g_tx[slot].armed = false;
    Serial.printf("[TX] slot %u off the air (beacons stopped).\n", (unsigned)slot);
}

const uint8_t *beacon_tx_raw_mac(uint8_t slot) {
    if (slot >= DET_IDENTITY_SLOTS) return SLOT_MAC[0];
    return SLOT_MAC[slot];
}
