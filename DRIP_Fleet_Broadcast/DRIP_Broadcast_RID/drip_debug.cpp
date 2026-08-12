#include "drip_debug.h"
#include "beacon_tx_raw.h"   // beacon_tx_raw_mac() for attribution
#include "det_generator.h"   // det_print()
#include "f3411_messages.h"
#include <Arduino.h>
#include <string.h>

#define DBG_VSIE_ELEM_ID   0xDD
#define DBG_VSIE_OUI_0     0xFA
#define DBG_VSIE_OUI_1     0x0B
#define DBG_VSIE_OUI_2     0xBC
#define DBG_VSIE_TYPE      0x0D

// ---------------------------------------------------------------------------
static void print_hex_block(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) {
            if (i > 0) Serial.println();
            Serial.printf("  0x%02X: ", (unsigned)i);
        }
        Serial.printf("%02X", data[i]);
        if ((i + 1) % 16 != 0 && i + 1 < len) Serial.print(' ');
    }
    Serial.println();
}

static void print_hex_inline(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) Serial.printf("%02X", data[i]);
}

static const char *msg_type_str(uint8_t nibble) {
    switch (nibble) {
        case 0x0: return "Basic ID";
        case 0x1: return "Location";
        case 0x2: return "Auth";
        case 0x3: return "Self ID";
        case 0x4: return "System";
        case 0x5: return "Operator ID";
        case 0xF: return "Message Pack";
        default:  return "Unknown";
    }
}

static const char *sam_type_str(uint8_t sam) {
    switch (sam) {
        case 0x01: return "Link (Broadcast Endorsement)";
        case 0x02: return "Wrapper";
        case 0x03: return "Manifest";
        case 0x04: return "Frame";
        default:   return "Unknown";
    }
}

static const char *cycle_str(uint8_t phase) {
    switch (phase) {
        case 0: return "A — Wrapper";
        case 1: return "B — Link / BE chain";
        case 2: return "C — Manifest";
        default: return "?";
    }
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// ---------------------------------------------------------------------------
// Reassemble the SAM Authentication Data of a multi-page Auth message.
//   page0   : pointer to the 25-byte page-0 message
//   pages   : pointer to the run of pages (page0 == pages[0..24])
//   navail  : number of 25-byte pages available from page0 to end of pack
//   sam_out : destination (caller sized >= length)
// Returns the number of pages consumed (last_page_index + 1), 0 on error.
// Layout decoded per drip_auth_page.cpp:
//   page0[1]=0x50, [2]=LastPageIndex, [3]=Length, [4..7]=Timestamp, [8..24]=17 data
//   pageN[1]=0x5N, [2..24]=23 data
// ---------------------------------------------------------------------------
// R1 FIX (Round-2 remediation): sam_cap was declared uint8_t, so the caller's
// sizeof(sam) == DRIP_DBG_SAM_MAX == 256 truncated to 0 and the guard
// `length > sam_cap` rejected EVERY message (1360/1360 reassembly failures in
// the 2026-06 capture). size_t carries the full value; no other change needed.
static uint8_t reassemble_sam(const uint8_t *page0, uint8_t navail,
                              uint8_t *sam_out, size_t sam_cap,
                              uint8_t *length_out, uint32_t *ts_out,
                              uint8_t *lpi_out) {
    uint8_t lpi    = page0[2];
    uint8_t length = page0[3];
    uint32_t ts    = le32(&page0[4]);
    uint8_t pages  = lpi + 1;

    *lpi_out = lpi; *length_out = length; *ts_out = ts;

    if (length > sam_cap) return 0;
    if (pages > navail)   return 0;     // truncated / inconsistent

    uint8_t off = 0;
    uint8_t n0  = (length < 17) ? length : 17;
    memcpy(&sam_out[off], &page0[8], n0);
    off += n0;

    for (uint8_t p = 1; p < pages && off < length; p++) {
        const uint8_t *pg = page0 + (size_t)p * F3411_MSG_BYTES;
        uint8_t rem  = length - off;
        uint8_t take = (rem < 23) ? rem : 23;
        memcpy(&sam_out[off], &pg[2], take);
        off += take;
    }
    return pages;
}

// Annotate a reassembled SAM payload.
static void annotate_sam(const uint8_t *sam, uint8_t length) {
    uint8_t sam_type = sam[0];
    Serial.printf("         SAM_type=0x%02X  →  %s   (SAM data length=%u)\n",
                  sam_type, sam_type_str(sam_type), length);

    if (sam_type == 0x01 && length >= 137) {
        // DRIP Link = Broadcast Endorsement — RFC 9575 §4.2 Figure 5
        Serial.printf("         VNB=%u  VNA=%u\n", le32(&sam[1]), le32(&sam[5]));
        Serial.print  ("         DET(child) : "); print_hex_inline(&sam[9],  16); Serial.println();
        Serial.print  ("         HI (child) : "); print_hex_inline(&sam[25], 32); Serial.println();
        Serial.print  ("         DET(parent): "); print_hex_inline(&sam[57], 16); Serial.println();
        Serial.print  ("         Sig(parent): "); print_hex_inline(&sam[73], 16);
        Serial.println("...(64B)");
    } else if (sam_type == 0x02) {
        // DRIP Wrapper over EXTENDED TRANSPORT — RFC 9575 §4.3.2 / Figure 7.
        //   0x02 ‖ VNB(4) ‖ VNA(4) ‖ DET(16) ‖ Sig(64) = 89 octets, FIXED size.
        // Evidence is CLEARED on the wire (this is the whole point of Extended
        // Transport: the signed ASTM messages are the pack's own co-located
        // messages, not re-transmitted inside the Wrapper). So wrappedCount is
        // ALWAYS 0 here by design — it is not a decode failure. A receiver
        // reconstructs the signed Evidence from the pack's non-Auth messages
        // (see the observer's odid.reconstruct_wrapper_evidence()).
        Serial.printf("         VNB=%u  VNA=%u\n", le32(&sam[1]), le32(&sam[5]));

        if (length != 89) {
            Serial.printf("         !! unexpected Wrapper length %u (expected 89, "
                          "Extended Transport)\n", length);
        } else {
            Serial.println("         Evidence: (cleared - Extended Transport, "
                           "signed over the co-located pack messages)");
            const uint8_t *det = &sam[9];
            Serial.print  ("         UA DET     : "); print_hex_inline(det, 16); Serial.println();
            Serial.print  ("         Sig (UA)   : "); print_hex_inline(det + 16, 16);
            Serial.println("...(64B)");
        }
    } else if (sam_type == 0x03) {
        // DRIP Manifest — RFC 9575 §4.1 Figure 4 / §4.4 (Round-2 layout, R3):
        //   0x03 ‖ VNB(4) ‖ VNA(4) ‖ Evidence(32) ‖ DET(16) ‖ Sig(64) = 121
        Serial.printf("         VNB=%u  VNA=%u\n", le32(&sam[1]), le32(&sam[5]));
        if (length != 121) {
            Serial.printf("         !! unexpected Manifest length %u (expected 121)\n",
                          length);
        }
        // Evidence = 4 × 8-byte ledger hashes, §4.4.2 order
        Serial.print("         Hash(Previous): "); print_hex_inline(&sam[9],  8); Serial.println();
        Serial.print("         Hash(Current) : "); print_hex_inline(&sam[17], 8); Serial.println();
        Serial.print("         Hash(Link)    : "); print_hex_inline(&sam[25], 8); Serial.println();
        Serial.print("         Hash(Pack)    : "); print_hex_inline(&sam[33], 8); Serial.println();
        Serial.print("         UA DET        : "); print_hex_inline(&sam[41], 16); Serial.println();
        Serial.print("         Sig (UA)      : "); print_hex_inline(&sam[57], 16);
        Serial.println("...(64B)");
    }
}

// ---------------------------------------------------------------------------
// The fleet owns this flag: fleet_init() clears it (boot is QUIET) and
// fleet_build_and_send() sets it per drone to (g_debug_slot == slot). The
// initialiser below only covers the window before fleet_init() runs.
//
// It also gates the per-cycle STATUS lines in drip_auth.cpp and
// drip_manifest.cpp — at 3 drones those were ~15 lines/s and buried every
// typed command. WARN/ERROR lines there are deliberately NOT gated, so a
// quiet console means "every drone is signing", never "no information".
static bool g_dbg_enabled = false;

void drip_debug_set_enabled(bool en) { g_dbg_enabled = en; }
bool drip_debug_enabled()            { return g_dbg_enabled; }

void drip_debug_print_pack(const MessagePack *pack,
                            uint8_t            tx_counter,
                            uint8_t            cycle_phase,
                            uint8_t            slot,
                            const uint8_t     *det) {

    if (!g_dbg_enabled) return;          // see the bandwidth note in drip_debug.h

    uint8_t pack_bytes = message_pack_bytes(pack);

    Serial.println();
    Serial.println(F("================================================="));
    // Format L contract: observer.py / odid.py parse_format_l() keys on THIS
    // line's exact shape ("TX cnt=0x.. (  n) | Cycle X — Name"). It is left
    // untouched; the drone attribution goes on its own line below so existing
    // captures and the existing parser keep working.
    Serial.printf( "  TX cnt=0x%02X (%3u) | Cycle %s\n",
                   tx_counter, tx_counter, cycle_str(cycle_phase));
    Serial.printf( "  drone %u  MAC=%02X:%02X:%02X:%02X:%02X:%02X\n",
                   (unsigned)slot,
                   beacon_tx_raw_mac(slot)[0], beacon_tx_raw_mac(slot)[1],
                   beacon_tx_raw_mac(slot)[2], beacon_tx_raw_mac(slot)[3],
                   beacon_tx_raw_mac(slot)[4], beacon_tx_raw_mac(slot)[5]);
    if (det) det_print("  drone DET = ", det);
    Serial.println(F("================================================="));

    // ---- Full reconstructed VSIE ----
    uint8_t  vsie_body_len = 5 + pack_bytes;
    uint16_t vsie_total    = 2 + vsie_body_len;
    Serial.printf("\n[VSIE] elem_id=0xDD  body_len=%u  total=%u bytes\n",
                  vsie_body_len, vsie_total);
    Serial.printf(  "       OUI=FA-0B-BC  vendor_type=0x0D  counter=0x%02X\n", tx_counter);

    uint8_t vsie[2 + 255];
    vsie[0] = DBG_VSIE_ELEM_ID; vsie[1] = vsie_body_len;
    vsie[2] = DBG_VSIE_OUI_0; vsie[3] = DBG_VSIE_OUI_1; vsie[4] = DBG_VSIE_OUI_2;
    vsie[5] = DBG_VSIE_TYPE; vsie[6] = tx_counter;
    memcpy(&vsie[7], pack->buf, pack_bytes);
    print_hex_block(vsie, vsie_total);

    // ---- Message Pack header ----
    Serial.printf("\n[Pack] %u messages, %u bytes\n", pack->count, pack_bytes);
    Serial.printf(  "       hdr=[%02X %02X %02X]  msg_size=%u  count=%u\n",
                  pack->buf[0], pack->buf[1], pack->buf[2], pack->buf[1], pack->buf[2]);
    print_hex_block(pack->buf, pack_bytes);

    // ---- Individual messages ----
    uint8_t m = 0;
    while (m < pack->count) {
        const uint8_t *msg = pack->buf + MSG_PACK_HDR_BYTES + (size_t)m * F3411_MSG_BYTES;
        uint8_t type_nibble = (msg[0] >> 4) & 0x0F;

        if (type_nibble == 0x2) {
            uint8_t hi  = (msg[1] >> 4) & 0x0F;   // AuthType nibble
            uint8_t low =  msg[1]       & 0x0F;   // Page Number nibble

            if (hi == 0x5 && low == 0x0) {
                // Page 0 of a (possibly multi-page) Auth message — correct framing.
                uint8_t navail = pack->count - m;
                uint8_t sam[DRIP_DBG_SAM_MAX];
                uint8_t length, lpi; uint32_t ts;
                uint8_t pages = reassemble_sam(msg, navail, sam, sizeof(sam),
                                               &length, &ts, &lpi);

                Serial.printf("\n[Msg %02u] Auth Page 0  (AuthType=0x5 SAM, "
                              "LastPageIdx=%u, %u page(s))\n"
                              "         Length=%u  Timestamp=%u\n",
                              m, lpi, lpi + 1, length, ts);

                if (pages == 0) {
                    Serial.println("         !! could not reassemble (truncated or "
                                   "Length > buffer) — dumping raw pages");
                } else {
                    annotate_sam(sam, length);
                }

                // Dump every page of this Auth message.
                uint8_t span = (pages == 0) ? 1 : pages;
                if (span > navail) span = navail;
                for (uint8_t k = 0; k < span; k++) {
                    Serial.printf("         -- page %u (byte1=0x%02X) --\n",
                                  k, msg[(size_t)k * F3411_MSG_BYTES + 1]);
                    print_hex_block(msg + (size_t)k * F3411_MSG_BYTES, F3411_MSG_BYTES);
                }
                m += span;
                continue;
            } else if (hi == 0x5) {
                Serial.printf("\n[Msg %02u] Auth continuation page %u (orphaned in dump)\n",
                              m, low);
                print_hex_block(msg, F3411_MSG_BYTES);
            } else {
                Serial.printf("\n[Msg %02u] Auth page with AuthType nibble 0x%X "
                              "(expected 0x5) — legacy/None framing?\n", m, hi);
                print_hex_block(msg, F3411_MSG_BYTES);
            }
        } else {
            Serial.printf("\n[Msg %02u] %s  (type=0x%X  ver=0x%X)\n",
                          m, msg_type_str(type_nibble), type_nibble, msg[0] & 0x0F);
            print_hex_block(msg, F3411_MSG_BYTES);
        }
        m++;
    }

    Serial.println(F("================================================="));
}
