// =============================================================================
//  DRIP_Sniffer — ESP32 #2 : over-the-air capture of ASTM F3411-22a Broadcast RID
//
//  STAGE 1 of the observer redesign. This board does NOT transmit. It listens on
//  channel 6 in promiscuous mode, keeps only 802.11 Beacons carrying an Open
//  Drone ID vendor IE, and prints them over serial in a hex format that
//  Wireshark can import directly.
//
// -----------------------------------------------------------------------------
//  WHY THIS EXISTS
//
//  The serial debug path (Format L) on the TRANSMITTER prints the pack it
//  *intended* to send — read out of RAM, before esp_wifi_80211_tx() is even
//  called. It would report a flawless dump if the frame never left the antenna,
//  if the MAC header were malformed, or if the driver rewrote the source
//  address. Since the whole transmission layer was recently replaced with
//  hand-built frames, the one thing most in need of verification is precisely
//  the thing Format L structurally cannot see.
//
//  This sniffer reads the AIR. What it prints actually propagated.
//
//  It also recovers the source MAC, which the Python observer currently
//  discards (it starts parsing at offset 36 and never reads Addr2). That
//  blindness is not cosmetic: it is why a single-BSSID transmitter design would
//  have looked healthy to our own tooling while a real receiver saw one
//  flickering aircraft.
//
// -----------------------------------------------------------------------------
//  WHY A SECOND ESP32 RATHER THAN A MONITOR-MODE NIC
//
//  esp_wifi_set_promiscuous_rx_cb() hands us wifi_promiscuous_pkt_t, whose
//  .payload begins at the 802.11 Frame Control field — with NO radiotap header.
//  That matters: a monitor-mode pcap prepends a variable-length radiotap header,
//  which would break odid.py's BEACON_TAGGED_START = 36 (and silently
//  mis-decode, which is worse than failing). Sniffing on an ESP32 sidesteps
//  radiotap entirely, needs no Npcap/monitor-mode support on the host, and
//  reuses the promiscuous RX path already proven by SPIKE_Beacon_Inject.
//
//  The RSSI / channel / timestamp that radiotap would have carried are
//  available here in rx_ctrl, and are emitted as '#' comments.
//
// -----------------------------------------------------------------------------
//  OUTPUT FORMAT — verified against text2pcap 4.2.2 + tshark before this
//  firmware was written (4 synthetic frames in -> 4 packets out, MACs, SSIDs,
//  OUI fa:0b:bc type 13 all dissected, timestamps preserved to microseconds).
//
//      # comment lines are ignored by text2pcap (verified)
//      HH:MM:SS.uuuuuu 000000 80 00 00 00 FF FF FF FF FF FF 02 44 52 49 50 00
//                      000010 02 44 52 49 50 00 00 00 00 00 00 00 00 00 00 00
//                      ...
//
//  The timestamp appears ONLY on a packet's first line; continuation lines are
//  padded to the same width (text2pcap ignores text before the offset).
//
//  IMPORT:
//      text2pcap -t "%H:%M:%S.%f" -l 105 capture.txt capture.pcap
//
//    -t "%H:%M:%S.%f"  the %f (fractional seconds) descriptor is REQUIRED.
//                      Older Wireshark docs show "%H:%M:%S." — on 4.2.2 that
//                      silently DROPS the fraction and every frame lands on the
//                      same timestamp. Verified the hard way.
//    -l 105            LINKTYPE_IEEE802_11 = raw 802.11, no radiotap.
//
//  With microsecond timestamps preserved, the capture can verify BOTH the
//  ~10 Hz per-drone beacon repeat and the 111 ms phase stagger between drones.
//
// -----------------------------------------------------------------------------
//  STANDARDS
//    ASTM F3411-22a §5.4.9.2 (BWFB0020) / Table 20 — the vendor IE we filter on:
//        Element ID 221 (0xDD) | Length | OUI FA-0B-BC | Vendor Type 0x0D
//    ASTM F3411-22a §5.4.9.1 (BWFB0010) — channel 6 as the single social channel
//    IEEE 802.11-2016 §9.3.3.3 — Beacon frame (type 0 management, subtype 8)
//
// -----------------------------------------------------------------------------
//  HOW TO RUN
//    1. Folder must be named exactly  DRIP_Sniffer/
//    2. Flash to the SECOND ESP32 (the transmitter keeps running its own build).
//    3. Serial Monitor at 921600 — see the BAUD note below.
//    4. Capture the text to a file, then run the text2pcap command above.
//       (Serial Monitor cannot save to a file; use a logger script, or
//        PuTTY/screen logging, or the Arduino IDE's Serial Monitor copy-paste.)
// =============================================================================

#include <Arduino.h>
#include <string.h>

extern "C" {
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
}

// -----------------------------------------------------------------------------
//  Configuration
// -----------------------------------------------------------------------------

// ASTM F3411-22a §5.4.9.1 (BWFB0010) — must match the transmitter's
// WIFI_CHANNEL_DRIP (beacon_tx_raw.h). This sniffer does NOT hop channels.
#define SNIFFER_CHANNEL     6

// Serial rate. Budget: a 296-byte frame emits ~624 chars (hex + offsets +
// metadata); 3 drones x 10 Hz = 30 frames/s = ~18.7 kB/s.
//   115200 -> 162% of the link  ** WILL DROP FRAMES **
//   460800 ->  41%              OK
//   921600 ->  20%              recommended
// If your USB-serial chip is unreliable at 921600 (CH340 often is above
// ~460800; CP2102 is usually fine), drop to 460800 here AND in the capture
// tool. Do NOT drop to 115200: the sniffer would silently lose frames and any
// rate analysis drawn from the capture would be wrong.
#define SNIFFER_BAUD        921600

// Ring buffer. The promiscuous callback MUST NOT print: it runs in the Wi-Fi
// driver task, and Serial.printf() blocks when the TX FIFO fills, which would
// stall the Wi-Fi stack and drop frames at the radio. So the callback only
// copies and returns; loop() does all the printing.
#define RING_SLOTS          16
#define MAX_FRAME           512   // our own frames are 296 B; headroom for others

// Offset of the first tagged parameter in a Beacon:
//   24 (MAC header) + 12 (timestamp/interval/capability). Same constant as
//   odid.py's BEACON_TAGGED_START — deliberately.
#define BEACON_TAGGED_START 36

// ASTM F3411-22a Table 20
static const uint8_t ODID_OUI[3] = { 0xFA, 0x0B, 0xBC };
#define ODID_VENDOR_TYPE    0x0D

// -----------------------------------------------------------------------------
//  State
// -----------------------------------------------------------------------------
struct Slot {
    uint8_t  buf[MAX_FRAME];
    uint16_t len;
    uint64_t t_us;
    int8_t   rssi;
    uint8_t  ch;
};

static Slot              g_ring[RING_SLOTS];
static volatile uint16_t g_head = 0;      // written by the Wi-Fi task
static volatile uint16_t g_tail = 0;      // written by loop()
static volatile uint32_t g_captured = 0;
static volatile uint32_t g_dropped  = 0;  // ring overflow — serial too slow
static volatile uint32_t g_oversize = 0;  // frame > MAX_FRAME, skipped

// rx_ctrl.timestamp is a uint32 of MICROSECONDS -> it wraps every ~71.6 min.
// Recorded flight 26 alone runs 116.7 min, so a wrap WILL happen in a long
// capture and would make timestamps jump backwards. Extended to 64-bit here.
// Safe in the callback: single producer, frames arrive in order.
static uint32_t g_last_us   = 0;
static uint64_t g_wrap_base = 0;

// -----------------------------------------------------------------------------
//  Does this frame carry an Open Drone ID vendor IE?  (ASTM Table 20)
//
//  NOTE — we filter on the ODID OUI, NOT on our own MACs. Two reasons:
//    1. a real ODID drone nearby would also be captured (useful);
//    2. filtering by our MACs would HIDE the very defect this tool exists to
//       detect — a Remote ID payload arriving from an unexpected transmitter.
// -----------------------------------------------------------------------------
static bool has_odid_ie(const uint8_t *f, uint16_t len) {
    uint16_t pos = BEACON_TAGGED_START;
    while (pos + 2 <= len) {
        uint8_t id     = f[pos];
        uint8_t ie_len = f[pos + 1];
        if (pos + 2 + ie_len > len) return false;          // truncated/malformed
        if (id == 0xDD && ie_len >= 4 &&
            f[pos + 2] == ODID_OUI[0] &&
            f[pos + 3] == ODID_OUI[1] &&
            f[pos + 4] == ODID_OUI[2] &&
            f[pos + 5] == ODID_VENDOR_TYPE) {
            return true;
        }
        pos += 2 + ie_len;
    }
    return false;
}

// -----------------------------------------------------------------------------
//  Promiscuous RX callback — runs in the Wi-Fi driver task. KEEP IT SHORT.
//  No Serial, no malloc, no blocking.
// -----------------------------------------------------------------------------
static void promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *f = p->payload;

    // rx_ctrl.sig_len includes the 4-byte FCS, which the hardware appends and
    // which is not part of the frame we built. Strip it so the captured length
    // matches the transmitter exactly (a 9-message pack => 296 bytes) — that
    // equality is itself a useful check that nothing mangled the frame.
    int len = (int)p->rx_ctrl.sig_len - 4;
    if (len < BEACON_TAGGED_START) return;

    // Beacon only: Frame Control byte 0 = 0x80 (version 0, type 0 mgmt,
    // subtype 8). IEEE 802.11-2016 §9.3.3.3.
    if (f[0] != 0x80) return;

    if (!has_odid_ie(f, (uint16_t)len)) return;

    if (len > MAX_FRAME) { g_oversize++; return; }   // skip, never truncate:
                                                     // a truncated frame would
                                                     // decode as corrupt data
    // 64-bit extend the microsecond clock (see g_wrap_base).
    uint32_t t = p->rx_ctrl.timestamp;
    if (t < g_last_us) g_wrap_base += 0x100000000ULL;
    g_last_us = t;

    uint16_t next = (uint16_t)((g_head + 1) % RING_SLOTS);
    if (next == g_tail) { g_dropped++; return; }     // serial cannot keep up

    Slot *s = &g_ring[g_head];
    memcpy(s->buf, f, (size_t)len);
    s->len  = (uint16_t)len;
    s->t_us = g_wrap_base + t;
    s->rssi = p->rx_ctrl.rssi;
    s->ch   = p->rx_ctrl.channel;

    g_head = next;
    g_captured++;
}

// -----------------------------------------------------------------------------
//  Emit one frame in text2pcap hexdump format.
//
//  "HH:MM:SS.uuuuuu " is exactly 16 characters, so continuation lines are
//  padded with 16 spaces to keep the offsets aligned. text2pcap ignores text
//  before the offset; the timestamp is parsed only where a packet starts.
// -----------------------------------------------------------------------------
static void emit(const Slot *s) {
    uint32_t secs = (uint32_t)(s->t_us / 1000000ULL);
    uint32_t frac = (uint32_t)(s->t_us % 1000000ULL);
    unsigned hh = (secs / 3600) % 24;
    unsigned mm = (secs / 60) % 60;
    unsigned ss = secs % 60;

    // '#' lines are ignored by text2pcap (verified) — metadata for humans and
    // for a future observer parser reading this text directly.
    Serial.printf("#F rssi=%d ch=%u len=%u\n", (int)s->rssi, (unsigned)s->ch,
                  (unsigned)s->len);

    for (uint16_t off = 0; off < s->len; off += 16) {
        if (off == 0) Serial.printf("%02u:%02u:%02u.%06u ", hh, mm, ss,
                                    (unsigned)frac);
        else          Serial.print("                ");     // 16 spaces
        Serial.printf("%06X", (unsigned)off);
        for (uint16_t k = off; k < off + 16 && k < s->len; k++)
            Serial.printf(" %02X", s->buf[k]);
        Serial.println();
    }
}

// -----------------------------------------------------------------------------
void setup() {
    Serial.begin(SNIFFER_BAUD);
    delay(600);

    esp_err_t nvs = nvs_flash_init();
    if (nvs == ESP_ERR_NVS_NO_FREE_PAGES || nvs == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs = nvs_flash_init();
    }
    ESP_ERROR_CHECK(nvs);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    // STA, never connected — same posture as the transmitter. Nothing is
    // associated, nothing beacons, and the radio stays parked on our channel.
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Management frames only: beacons are mgmt subtype 8. Filtering here rather
    // than in the callback keeps the driver from waking us for every data frame
    // on a busy 2.4 GHz band.
    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filt));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&promisc_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_channel(SNIFFER_CHANNEL, WIFI_SECOND_CHAN_NONE));

    // The file documents its own import command — so a capture handed to
    // another engineer is self-describing.
    Serial.println();
    Serial.println("# DRIP-SNIFFER v1 — over-the-air ASTM F3411-22a Broadcast RID capture");
    Serial.printf ("# channel=%d  baud=%d  filter=Beacon + vendor IE OUI FA-0B-BC type 0x0D\n",
                   SNIFFER_CHANNEL, SNIFFER_BAUD);
    Serial.println("# FCS stripped; frame starts at 802.11 Frame Control (no radiotap).");
    Serial.println("# import:  text2pcap -t \"%H:%M:%S.%f\" -l 105 capture.txt capture.pcap");
    Serial.println("# NOTE: the %f is required; \"%H:%M:%S.\" silently drops the fraction.");
    Serial.println("# timestamps are microseconds since THIS board booted, not wall clock.");
    Serial.println("#");
}

// -----------------------------------------------------------------------------
void loop() {
    // Drain the ring. Printing happens only here, never in the callback.
    while (g_tail != g_head) {
        emit(&g_ring[g_tail]);
        g_tail = (uint16_t)((g_tail + 1) % RING_SLOTS);
    }

    // Periodic health line. Emitted only between packets (the ring is drained
    // first), so it can never split a hexdump.
    //
    // g_dropped > 0 means the ring overflowed: the serial link could not keep
    // up and frames were LOST. Any rate/interval analysis from such a capture
    // is unsound — raise the baud or reduce the fleet before trusting it.
    static uint32_t last = 0;
    if (millis() - last >= 10000) {
        last = millis();
        Serial.printf("# stats captured=%u dropped=%u oversize=%u  (dropped>0 => "
                      "capture is INCOMPLETE)\n",
                      (unsigned)g_captured, (unsigned)g_dropped,
                      (unsigned)g_oversize);
    }
}
