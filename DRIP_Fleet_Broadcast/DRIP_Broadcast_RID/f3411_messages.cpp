#include "f3411_messages.h"
#include "drip_time.h"   // drip_timestamp() - populates F3411System.timestamp
#include <string.h>
#include <math.h>

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

// Altitude: (alt_m + 1000.0) / 0.5, range −1000 → +31767.5 m, 0xFFFF = unknown
uint16_t f3411_encode_altitude(float alt_m) {
    if (alt_m < -1000.0f || alt_m > 31767.0f) return 0xFFFF;
    return (uint16_t)((alt_m + 1000.0f) / 0.5f + 0.5f);
}

// Track direction split:
//   Direction segment bit (in status_flags) = 0 for 0–179°, 1 for 180–359°
//   Stored angle = heading within that 180° segment
static void encode_direction(float hdg, uint8_t *segment, uint8_t *stored) {
    if (hdg < 0.0f)   hdg += 360.0f;
    if (hdg >= 360.0f) hdg -= 360.0f;
    if (hdg < 180.0f) {
        *segment = 0;
        *stored  = (uint8_t)hdg;
    } else {
        *segment = 1;
        *stored  = (uint8_t)(hdg - 180.0f);
    }
}

// Speed encoding:
//   speed_mult = 0 → speed_byte × 0.25 m/s  (0 – 63.75 m/s)
//   speed_mult = 1 → speed_byte × 0.75 m/s  (for higher speeds)
static void encode_hspeed(float speed_mps, uint8_t *speed_byte, uint8_t *multiplier) {
    if (speed_mps < 0.0f) speed_mps = 0.0f;
    if (speed_mps <= 63.75f) {
        *multiplier  = 0;
        *speed_byte  = (uint8_t)(speed_mps / 0.25f + 0.5f);
    } else {
        *multiplier  = 1;
        float clamped = (speed_mps > 254.25f) ? 254.25f : speed_mps;
        *speed_byte   = (uint8_t)(clamped / 0.75f + 0.5f);
    }
}

// ---------------------------------------------------------------------------
// Basic ID
// ---------------------------------------------------------------------------

F3411BasicID f3411_build_basic_id(const uint8_t session_id[SESSION_ID_BYTES]) {
    return f3411_build_basic_id_ua(session_id, 5);  // default: multirotor = 2
}

F3411BasicID f3411_build_basic_id_ua(const uint8_t session_id[SESSION_ID_BYTES],
                                      uint8_t ua_type) {
    F3411BasicID msg = {};
    msg.type_ver   = (F3411_TYPE_BASIC_ID << 4) | F3411_PROTO_VER;
    // ID Type 4 = Specific Session ID (DRIP DET)  — ASTM F3411-22a Table 1
    msg.id_ua_type = (0x4 << 4) | (ua_type & 0x0F);
    memcpy(msg.uas_id, session_id, SESSION_ID_BYTES);
    return msg;
}

// ---------------------------------------------------------------------------
// Location / Vector
// ---------------------------------------------------------------------------

F3411Location f3411_build_location(const DronePosition &pos) {
    F3411Location msg = {};
    msg.type_ver = (F3411_TYPE_LOCATION << 4) | F3411_PROTO_VER;

    uint8_t dir_segment, dir_stored;
    encode_direction(pos.heading_deg, &dir_segment, &dir_stored);

    uint8_t spd_byte, spd_mult;
    encode_hspeed(pos.speed_mps, &spd_byte, &spd_mult);

    // Byte 1 bit layout (MSB→LSB):
    //   bits 7-4 : Operational Status
    //   bit  3   : reserved
    //   bit  2   : Height Type (0 = above takeoff)
    //   bit  1   : Direction Segment
    //   bit  0   : Speed Multiplier
    msg.status_flags = ((uint8_t)(F3411_STATUS_AIRBORNE) << 4) |
                       (dir_segment << 1) |
                       (spd_mult    << 0);

    msg.latitude     = (int32_t)(pos.lat * 1e7);
    msg.longitude    = (int32_t)(pos.lon * 1e7);

    msg.alt_pressure = 0xFFFF;                         // not available in simulation
    msg.alt_geodetic = f3411_encode_altitude(pos.alt_m);
    msg.height       = f3411_encode_altitude(pos.alt_m); // height ≈ geodetic alt for simulation

    // Accuracy codes: 0x0 = unknown/unset — update with real sensor accuracy
    msg.horiz_vert_acc = 0x00;
    msg.baro_speed_acc = 0x00;
    msg.ts_accuracy    = 0x00;

    // Timestamp: 0.1 s units since the start of the current or previous UTC hour
    msg.timestamp = (uint16_t)((pos.unix_time_s % 3600UL) * 10UL);

    msg.speed      = spd_byte;
    msg.speed_vert = (int8_t)(pos.vspeed_mps / 0.5f);
    msg.direction  = dir_stored;

    return msg;
}

// ---------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------

F3411System f3411_build_system(double op_lat, double op_lon, float op_alt_m) {
    F3411System msg = {};
    msg.type_ver = (F3411_TYPE_SYSTEM << 4) | F3411_PROTO_VER;

    // flags: operator location type 1 (Takeoff/live GNSS), classification type 0 (undeclared)
    msg.flags          = (0x1 << 6) | (F3411_UA_CLASS_UNDECLARED << 3);

    msg.op_latitude    = (int32_t)(op_lat * 1e7);
    msg.op_longitude   = (int32_t)(op_lon * 1e7);

    msg.area_count     = 1;       // single UA
    msg.area_radius    = 0;       // 0 = unset
    msg.area_ceiling   = f3411_encode_altitude(op_alt_m + 120.0f); // max flight alt
    msg.area_floor     = f3411_encode_altitude(0.0f);
    msg.ua_classification = 0x00;
    msg.op_alt_geodetic   = f3411_encode_altitude(op_alt_m);

    // ASTM Table 11 offset 20: 32-bit DRIP-epoch Unix timestamp, "time of
    // applicability" of this message - i.e. now. Was previously left at zero
    // (folded into the struct's old reserved[5]); see f3411_messages.h.
    msg.timestamp = drip_timestamp();

    return msg;
}
