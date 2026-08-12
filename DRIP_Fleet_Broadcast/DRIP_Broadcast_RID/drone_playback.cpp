#include "drone_playback.h"
#include "drone_data.h"
#include <Arduino.h>
#include <math.h>
#include <string.h>

// ---------------------------------------------------------------------------
// If two consecutive recorded points share the same (or an out-of-order)
// timestamp, there is no real interval to pace against. Advance immediately
// using this floor instead of stalling forever. This is common in the source
// data: several rows can carry the same integer-second timestamp.
// ---------------------------------------------------------------------------
#define PLAYBACK_MIN_DT_S   PLAYBACK_CYCLE_S

// Read one point from flash (the tables live in PROGMEM, not RAM).
// `ts_unix` receives the RECORDED timestamp (test-only; see drone_playback.h).
static bool read_point(uint16_t flight, uint16_t i,
                       double *lat, double *lon, float *alt_m, uint32_t *ts_unix) {
    if (flight >= DRONE_FLIGHT_COUNT || i >= DRONE_FLIGHTS[flight].n) return false;
    const DronePoint *p = &DRONE_FLIGHTS[flight].pts[i];
    int32_t lat_e7 = (int32_t)pgm_read_dword(&p->lat_e7);
    int32_t lon_e7 = (int32_t)pgm_read_dword(&p->lon_e7);
    int16_t alt_dm = (int16_t)pgm_read_word(&p->alt_dm);
    *lat   = lat_e7 / 1e7;
    *lon   = lon_e7 / 1e7;
    *alt_m = alt_dm / 10.0f;
    if (ts_unix) *ts_unix = (uint32_t)pgm_read_dword(&p->ts_unix);
    return true;
}

// ---------------------------------------------------------------------------
//  Flight table queries (the table is shared by every drone)
// ---------------------------------------------------------------------------
bool     drone_playback_available() { return DRONE_FLIGHT_COUNT > 0; }
uint16_t drone_playback_count()     { return DRONE_FLIGHT_COUNT; }

const char *drone_playback_name(uint16_t flight) {
    return (flight < DRONE_FLIGHT_COUNT) ? DRONE_FLIGHTS[flight].flight_id : nullptr;
}

uint16_t drone_playback_points(uint16_t flight) {
    return (flight < DRONE_FLIGHT_COUNT) ? DRONE_FLIGHTS[flight].n : 0;
}

float drone_playback_duration_s(uint16_t flight) {
    if (flight >= DRONE_FLIGHT_COUNT || DRONE_FLIGHTS[flight].n < 2) return 0.0f;
    double dlat, dlon; float dalt;
    uint32_t ts0 = 0, ts1 = 0;
    read_point(flight, 0, &dlat, &dlon, &dalt, &ts0);
    read_point(flight, DRONE_FLIGHTS[flight].n - 1, &dlat, &dlon, &dalt, &ts1);
    return (float)(ts1 - ts0);
}

void drone_playback_list() {
    Serial.println("[Playback] Available flights:");
    for (uint16_t i = 0; i < DRONE_FLIGHT_COUNT; i++) {
        // Real playback duration = last recorded timestamp - first recorded
        // timestamp (paced by real time, not by point count x 0.333 s).
        Serial.printf("  %2u : %-24s %5u pts  (~%.1f min real time)\n",
                      i, DRONE_FLIGHTS[i].flight_id, DRONE_FLIGHTS[i].n,
                      drone_playback_duration_s(i) / 60.0f);
    }
}

// ---------------------------------------------------------------------------
//  Per-drone cursor
// ---------------------------------------------------------------------------
void drone_playback_reset(PlaybackState *st) {
    st->idx             = 0;
    st->finished        = false;
    st->stopped_by_user = false;
    st->started         = false;   // next call re-emits point 0 fresh
    st->hold_elapsed_s  = 0;
    st->last_call_ms    = 0;       // next call measures from a clean start
    st->cur_speed = st->cur_vspeed = st->cur_heading = 0;
}

bool drone_playback_init(PlaybackState *st, uint16_t flight) {
    memset(st, 0, sizeof(*st));
    if (DRONE_FLIGHT_COUNT == 0) {
        Serial.println("[Playback] ERROR: drone_data.h contains no flights.");
        return false;
    }
    if (flight >= DRONE_FLIGHT_COUNT) return false;
    st->flight = flight;
    drone_playback_reset(st);
    st->ready = true;
    return true;
}

bool drone_playback_select(PlaybackState *st, uint16_t index) {
    if (index >= DRONE_FLIGHT_COUNT) return false;
    st->flight = index;
    st->ready  = true;
    drone_playback_reset(st);
    return true;
}

bool drone_playback_finished(const PlaybackState *st) { return st->finished; }

void drone_playback_stop(PlaybackState *st, uint8_t slot) {
    if (st->finished) return;                  // already halted
    st->finished        = true;
    st->stopped_by_user = true;
    Serial.printf("[Playback] drone %u STOPPED by command at point %u/%u of "
                  "flight %u (%s) — no Remote ID on the air for this drone.\n",
                  (unsigned)slot, st->idx, drone_playback_points(st->flight),
                  st->flight, drone_playback_name(st->flight));
}

void drone_playback_get_launch(const PlaybackState *st,
                               double *lat, double *lon, float *alt_m) {
    if (!st->ready || !read_point(st->flight, 0, lat, lon, alt_m, nullptr)) {
        *lat = 0; *lon = 0; *alt_m = 0;
    }
}

// ---------------------------------------------------------------------------
// Great-circle-free distance between two points, accurate over the metre-scale
// hops between consecutive recorded samples (equirectangular approximation).
// ---------------------------------------------------------------------------
static double point_distance_m(double lat1, double lon1, double lat2, double lon2) {
    const double M_PER_DEG_LAT = 111320.0;
    double mean_lat_rad = radians((lat1 + lat2) * 0.5);
    double dy = (lat2 - lat1) * M_PER_DEG_LAT;                      // north (m)
    double dx = (lon2 - lon1) * M_PER_DEG_LAT * cos(mean_lat_rad);  // east  (m)
    return sqrt(dx * dx + dy * dy);
}

// ---------------------------------------------------------------------------
// Advance one point; derive speed / heading / vertical speed from the delta.
// At the end of the track, hold on the last point with zero velocity.
// ---------------------------------------------------------------------------
DronePosition drone_playback_next(PlaybackState *st, uint32_t live_unix_time_s,
                                  uint8_t slot) {
    DronePosition pos;
    pos.lat = 0; pos.lon = 0; pos.alt_m = 0;
    pos.speed_mps = 0; pos.vspeed_mps = 0; pos.heading_deg = 0;
    pos.unix_time_s = live_unix_time_s;
    if (!st->ready) return pos;

    const uint16_t n = drone_playback_points(st->flight);
    uint16_t i = st->finished ? (uint16_t)(n - 1) : st->idx;   // hold on the last point

    double lat, lon; float alt_m; uint32_t ts_rec = 0;
    if (!read_point(st->flight, i, &lat, &lon, &alt_m, &ts_rec)) return pos;

    // ---- Real-timestamp pacing ------------------------------------------------
    // Advance to the next recorded point only once real transmission time has
    // caught up to the REAL recorded interval between points, instead of one
    // point per fixed 0.333 s cycle. Speed/heading/vspeed are computed from the
    // actual recorded delta-t, so they reflect true average velocity over that
    // segment rather than being inflated by assuming a constant 0.333 s gap.
    //
    // BUG FIX (retained): hold_elapsed_s used to be incremented by the ASSUMED
    // cycle duration (PLAYBACK_CYCLE_S) every call, regardless of how long the
    // cycle actually took — Ed25519 signing, the Wi-Fi update and verbose serial
    // output were unaccounted for, so the pacing clock drifted (~2.06x measured:
    // a 700 s flight took ~1440 s). Fix: measure ACTUAL elapsed time via
    // millis() and add THAT instead.
    //
    // MULTI-DRONE NOTE: last_call_ms is per drone, and each drone is served once
    // per fleet round, so this measures THIS drone's real cycle period — which is
    // what the pacing needs. It self-corrects if the round period changes with
    // fleet size (a 3-drone round is ~3x a 1-drone round per drone).
    uint32_t now_ms = millis();
    float real_elapsed_s = (st->last_call_ms == 0) ? PLAYBACK_CYCLE_S
                                                   : (now_ms - st->last_call_ms) / 1000.0f;
    st->last_call_ms = now_ms;

    if (!st->started) {
        st->started = true;                  // first emission: no prior point yet
        st->hold_elapsed_s = 0;
        st->cur_speed = st->cur_vspeed = st->cur_heading = 0;
    } else if (!st->finished) {
        st->hold_elapsed_s += real_elapsed_s;   // MEASURED, not assumed
        if (st->idx + 1 < n) {
            double next_lat, next_lon; float next_alt; uint32_t next_ts;
            if (read_point(st->flight, st->idx + 1, &next_lat, &next_lon, &next_alt, &next_ts)) {
                double dt = (double)next_ts - (double)ts_rec;
                if (dt <= 0) dt = PLAYBACK_MIN_DT_S;   // duplicate/out-of-order guard
                if (st->hold_elapsed_s >= dt) {
                    double d = point_distance_m(lat, lon, next_lat, next_lon);
                    st->cur_speed   = (float)(d / dt);
                    st->cur_vspeed  = (next_alt - alt_m) / dt;
                    st->cur_heading = 0;
                    if (d > 0.01) {
                        double hdg = degrees(atan2(
                            (next_lon - lon) * 111320.0 * cos(radians((lat + next_lat) * 0.5)),
                            (next_lat - lat) * 111320.0));
                        if (hdg < 0) hdg += 360.0;
                        st->cur_heading = (float)hdg;
                    }
                    st->idx++;
                    st->hold_elapsed_s -= dt;          // carry the remainder forward
                    // re-read the point we just advanced to, so this cycle emits it
                    read_point(st->flight, st->idx, &lat, &lon, &alt_m, &ts_rec);
                }
            }
        }
    }

    pos.lat = lat; pos.lon = lon; pos.alt_m = alt_m;
    pos.speed_mps   = st->cur_speed;
    pos.vspeed_mps  = st->cur_vspeed;
    pos.heading_deg = st->cur_heading;

#if DRONE_REPLAY_RECORDED_TIME
    // *** TEST-ONLY (see drone_playback.h) ***
    // Replay the dataset's RECORDED timestamp instead of the live clock. This
    // reaches ONLY the ASTM Location message timestamp (f3411_messages.cpp:
    // `(unix_time_s % 3600) * 10`, i.e. tenths of a second within the UTC hour).
    // DRIP VNB/VNA come from drip_timestamp() and stay on the live clock, so the
    // Wrapper / Link / Manifest signatures remain RFC 9575 §3.2.4.3 conformant.
    pos.unix_time_s = ts_rec;
#else
    pos.unix_time_s = live_unix_time_s;   // RFC-conformant: broadcast time is now
#endif
    // When finished, velocity stays zero (aircraft reported as stationary).
    if (st->finished) { pos.speed_mps = 0; pos.vspeed_mps = 0; pos.heading_deg = 0; }

    // The track is complete once we have EMITTED the last index (n-1): there is
    // no next recorded timestamp left to pace against. Fires once, on the cycle
    // that first reaches/holds the final point.
    if (!st->finished && n > 0 && st->idx >= n - 1) {
        st->finished = true;
        // The fleet checks drone_playback_finished() and stops transmitting for
        // this drone. Kept to ONE line: with several drones a multi-line banner
        // per completion would flood the console (and the serial link is a real
        // timing budget at 3 drones — see drone_fleet.cpp).
        Serial.printf("[Playback] drone %u FLIGHT COMPLETE: %u (%s), %u point(s) "
                      "transmitted — this drone is now off the air.\n",
                      (unsigned)slot, st->flight,
                      drone_playback_name(st->flight), n);
    }
    return pos;
}
