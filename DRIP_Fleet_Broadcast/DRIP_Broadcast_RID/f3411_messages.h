#pragma once
#include <stdint.h>
#include "det_generator.h"

// ---------------------------------------------------------------------------
// ASTM F3411-22a  — Message definitions
//
// Every message is exactly F3411_MSG_BYTES (25) bytes.
// Byte 0 of all messages = (MessageType << 4) | ProtocolVersion
// Protocol version for F3411-22a = 0x2.
// ---------------------------------------------------------------------------

#define F3411_MSG_BYTES     25

// Message type values (stored in high nibble of byte 0)
#define F3411_TYPE_BASIC_ID  0x0
#define F3411_TYPE_LOCATION  0x1
#define F3411_TYPE_AUTH      0x2
#define F3411_TYPE_SYSTEM    0x4
#define F3411_TYPE_MSG_PACK  0xF

#define F3411_PROTO_VER      0x2

// UA Classification Type (byte 1 bits 5-3 of System message)
#define F3411_UA_CLASS_UNDECLARED  0x0

// Operational Status (bits 7-4 of Location message byte 1)
#define F3411_STATUS_AIRBORNE   0x2

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Auth message framing — RFC 9575 §3.2.3
//
// ALL DRIP authentication formats use ASTM Auth Type 0x5 (SAM).
// The first byte of the Authentication Data payload is the SAM Type,
// which distinguishes Link / Wrapper / Manifest / Frame.
// Using distinct Auth Type values per format (e.g. 0x6 for Wrapper) is WRONG.
// ---------------------------------------------------------------------------
#define F3411_AUTH_TYPE_SAM     0x5   // Specific Authentication Method — all DRIP

// SAM Type byte — first octet of Authentication Data — RFC 9575 §3.2.3 Table 1
#define DRIP_SAM_TYPE_LINK      0x01
#define DRIP_SAM_TYPE_WRAPPER   0x02
#define DRIP_SAM_TYPE_MANIFEST  0x03
#define DRIP_SAM_TYPE_FRAME     0x04

// ---------------------------------------------------------------------------
// DRIP timestamp helpers — RFC 9575 §3.2.4.3
//
// "Timestamps are a Unix-style timestamp with an epoch of 2019-01-01 00:00:00 UTC."
// DRIP_EPOCH_UNIX_S converts between Unix epoch (1970) and DRIP epoch (2019).
//
// SIM_DRIP_TIME_BASE is an approximate "now" in the DRIP epoch for simulation.
// Update it before each test session:
//   SIM_DRIP_TIME_BASE = <current Unix time> - DRIP_EPOCH_UNIX_S
// Example for May 2025:  1748000000 - 1546300800 = 201699200
// ---------------------------------------------------------------------------
#define DRIP_EPOCH_UNIX_S    1546300800UL
#define SIM_DRIP_TIME_BASE   201699200UL   // ≈ May 2025 — UPDATE before testing
#define DRIP_VNA_OFFSET_S    120UL         // RFC 9575 §3.2.4.3 recommended offset

// drip_timestamp() is declared in drip_time.h (requires Arduino.h)
// Do NOT place millis() calls in this header — it is included by pure C++ units.

// ---------------------------------------------------------------------------
// Packed message structs
// All multi-byte integer fields are little-endian (ASTM F3411-22a convention).
// ---------------------------------------------------------------------------

// Basic ID Message — ASTM F3411-22a Table 3
struct __attribute__((packed)) F3411BasicID {
    uint8_t  type_ver;      // (TYPE_BASIC_ID << 4) | PROTO_VER = 0x02
    uint8_t  id_ua_type;    // high nibble = ID Type (4 = Session ID), low nibble = UA type
    uint8_t  uas_id[20];    // Session ID bytes
    uint8_t  reserved[3];
};
static_assert(sizeof(F3411BasicID) == 25, "");

// Location/Vector Message — ASTM F3411-22a Table 4
struct __attribute__((packed)) F3411Location {
    uint8_t  type_ver;          // 0x12
    uint8_t  status_flags;      // see encoder for bit layout
    uint8_t  direction;         // track direction 0–359°
    uint8_t  speed;             // horizontal speed (× 0.25 m/s, or × 0.75 m/s with multiplier)
    int8_t   speed_vert;        // vertical speed × 0.5 m/s
    int32_t  latitude;          // degrees × 1e7, little-endian
    int32_t  longitude;         // degrees × 1e7, little-endian
    uint16_t alt_pressure;      // (alt_m + 1000) / 0.5, 0xFFFF = unknown
    uint16_t alt_geodetic;      // same encoding
    uint16_t height;            // height above takeoff, same encoding
    uint8_t  horiz_vert_acc;    // horiz accuracy (high nibble) | vert accuracy (low nibble)
    uint8_t  baro_speed_acc;    // baro accuracy (high nibble) | speed accuracy (low nibble)
    uint16_t timestamp;         // 0.1s units since previous hour boundary
    uint8_t  ts_accuracy;       // timestamp accuracy (high nibble), low nibble reserved
    uint8_t  reserved;
};
static_assert(sizeof(F3411Location) == 25, "");

// System Message — ASTM F3411-22a Table 11
struct __attribute__((packed)) F3411System {
    uint8_t  type_ver;          // 0x42
    uint8_t  flags;             // operator loc type (7-6) | class type (5-3) | reserved (2-0)
    int32_t  op_latitude;       // operator location, degrees × 1e7
    int32_t  op_longitude;
    uint16_t area_count;        // number of UAs in operational volume
    uint8_t  area_radius;       // operational area radius in 10m steps (0 = unset)
    uint16_t area_ceiling;      // altitude encoding (same as F3411Location)
    uint16_t area_floor;        // altitude encoding
    uint8_t  ua_classification; // UA category (type-specific per flags.class_type)
    uint16_t op_alt_geodetic;   // operator altitude, same encoding
    // Table 11 offset 20, length 4: "Time of applicability of Location Message
    // expressed as a 32-bit Unix Timestamp (UTC) in seconds since... 2019-01-01"
    // i.e. the same DRIP-epoch second count drip_timestamp() returns. Populated
    // in f3411_build_system() — previously this was folded into `reserved[5]`
    // and always left at zero, which is non-conformant (ASTM mandates this
    // field; only the trailing 1 byte at offset 24 is truly reserved) and, per
    // RFC 9434 §9.5 (citing §3.3 and §6), undermines DRIP's own freshness and
    // multilateration-consistency use of broadcast timestamps.
    uint32_t timestamp;
    uint8_t  reserved;          // Table 11 offset 24, length 1: genuinely reserved
};
static_assert(sizeof(F3411System) == 25, "");

// ---------------------------------------------------------------------------
// Drone position passed in by flight_sim — used by the encoders
// ---------------------------------------------------------------------------
struct DronePosition {
    double  lat;           // degrees
    double  lon;           // degrees
    float   alt_m;         // metres above takeoff (geodetic)
    float   speed_mps;     // horizontal speed m/s
    float   vspeed_mps;    // vertical speed m/s
    float   heading_deg;   // track direction 0–359°
    uint32_t unix_time_s;  // approximate Unix epoch (millis/1000 for simulation)
};

// ---------------------------------------------------------------------------
// Encoder functions
// ---------------------------------------------------------------------------

F3411BasicID f3411_build_basic_id(const uint8_t session_id[SESSION_ID_BYTES]);

// ua_type: 0 = undeclared, 1 = aeroplane, 2 = multirotor, ...
F3411BasicID f3411_build_basic_id_ua(const uint8_t session_id[SESSION_ID_BYTES], uint8_t ua_type);

F3411Location f3411_build_location(const DronePosition &pos);

// op_lat/op_lon = operator position (usually launch point)
F3411System f3411_build_system(double op_lat, double op_lon, float op_alt_m);

// Utility: encode altitude per F3411 (alt_m → uint16)
uint16_t f3411_encode_altitude(float alt_m);
