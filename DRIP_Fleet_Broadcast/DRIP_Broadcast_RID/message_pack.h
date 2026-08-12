#pragma once
#include <stdint.h>
#include "f3411_messages.h"

// ---------------------------------------------------------------------------
// ASTM F3411-22a §5.4.9 — Message Pack
//
// Bundles up to MSG_PACK_MAX_MSGS individual 25-byte messages into a single
// payload for WiFi Beacon VSIE transmission.
//
// 802.11 IE body limit = 255 bytes.
// VSIE body = OUI(3) + Type(1) + Counter(1) + pack_bytes → max pack = 250 B.
// Pack = header(3) + N×25 → max N = floor(247/25) = 9 messages.
//
// Wire format: [0xF2][0x19][N] [msg0] [msg1] ... [msgN-1]
//              type+ver  size  count   25 bytes each
// ---------------------------------------------------------------------------

#define MSG_PACK_MAX_MSGS    9        // 802.11 IE 255-byte body limit
#define MSG_PACK_HDR_BYTES   3        // type_ver + single_msg_size + count
#define MSG_PACK_MAX_BYTES  (MSG_PACK_HDR_BYTES + MSG_PACK_MAX_MSGS * F3411_MSG_BYTES)

struct MessagePack {
    uint8_t buf[MSG_PACK_MAX_BYTES];
    uint8_t count;
};

void    message_pack_init  (MessagePack *pack);
bool    message_pack_add   (MessagePack *pack, const uint8_t msg[F3411_MSG_BYTES]);
uint8_t message_pack_bytes (const MessagePack *pack);
