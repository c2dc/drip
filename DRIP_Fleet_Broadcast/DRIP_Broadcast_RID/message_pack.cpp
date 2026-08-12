#include "message_pack.h"
#include <string.h>
#include <Arduino.h>

void message_pack_init(MessagePack *pack) {
    memset(pack->buf, 0, sizeof(pack->buf));
    pack->count = 0;

    // Write the fixed 3-byte header
    pack->buf[0] = (F3411_TYPE_MSG_PACK << 4) | F3411_PROTO_VER;  // 0xF2
    pack->buf[1] = F3411_MSG_BYTES;   // 0x19 = 25 — single message size
    pack->buf[2] = 0;                 // count, updated by message_pack_add
}

bool message_pack_add(MessagePack *pack, const uint8_t msg[F3411_MSG_BYTES]) {
    if (pack->count >= MSG_PACK_MAX_MSGS) {
        Serial.println("[Pack] Message Pack full (max 10)");
        return false;
    }
    uint8_t *dest = pack->buf + MSG_PACK_HDR_BYTES + pack->count * F3411_MSG_BYTES;
    memcpy(dest, msg, F3411_MSG_BYTES);
    pack->count++;
    pack->buf[2] = pack->count;   // keep count byte in sync
    return true;
}

uint8_t message_pack_bytes(const MessagePack *pack) {
    return MSG_PACK_HDR_BYTES + pack->count * F3411_MSG_BYTES;
}
