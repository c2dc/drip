#pragma once
#include <stdint.h>
#include "f3411_messages.h"      // DronePosition

// ---------------------------------------------------------------------------
// Real-drone track playback.
//
// Replays recorded flight tracks (compiled into drone_data.h) instead of the
// synthetic square route in flight_sim.
//
// Behaviour (per project decisions):
//   * PACING: each recorded point is held on the wire for its REAL recorded
//     duration (the delta between its timestamp and the next point's), not for
//     one fixed 0.333 s cycle. The transmitter still broadcasts at 3 Hz (DRIP
//     cadence is unaffected) — it simply repeats the SAME position across
//     multiple cycles until real time catches up to the recorded interval.
//     Speed / heading / vertical speed are computed from that real interval
//     (distance / real_seconds), so they reflect true average velocity instead
//     of being inflated by assuming a constant 0.333 s gap. The velocity value
//     is held constant for the whole hold (it represents the motion that
//     carried the drone INTO the point currently being held).
//   * CONSEQUENCE — playback duration is not bounded by the point cap. Total
//     playback time equals the real recorded flight duration (last timestamp -
//     first timestamp), regardless of how many points were kept.
//   * Duplicate/out-of-order recorded timestamps (delta <= 0) advance
//     immediately instead of stalling (PLAYBACK_MIN_DT_S floor).
//   * End of track: playback HOLDS on the final point (it does not wrap to the
//     start). Wrapping would teleport the drone back to takeoff mid-broadcast,
//     which an observer cross-checking position would rightly treat as bogus.
//     Re-select the flight (or 'reset') to play it again.
//   * Timestamp source: controlled by DRONE_REPLAY_RECORDED_TIME below.
//
// ---------------------------------------------------------------------------
// MULTI-DRONE CHANGE (this revision)
//
// Every piece of playback state used to be a file-scope global, which hard-coded
// "there is exactly one drone". The bench fleet runs up to 3 virtual UAs, each
// walking its OWN track at its OWN pace, so all of that state now lives in a
// caller-owned PlaybackState and every function takes a pointer to one.
// Nothing about the pacing algorithm changed — only where its variables live.
//
//   drone_playback_init()      -> drone_playback_init(PlaybackState*, flight)
//   drone_playback_next(t)     -> drone_playback_next(PlaybackState*, t)
//   ...and so on for select/reset/stop/finished/get_launch.
//
//   drone_playback_cmd()  -> MOVED to drone_fleet.cpp. Serial commands are now
//                            a fleet concern (they must say WHICH drone), and a
//                            module that owns one track cannot own the console.
//   drone_playback_det()  -> REMOVED. Identity is per SLOT, not per flight
//                            (det_generator.h IDENTITY_TABLE), so that two
//                            drones can fly the SAME track under DIFFERENT
//                            DETs. DroneFlight.det in drone_data.h stays unused.
// ---------------------------------------------------------------------------

// ===========================================================================
//  *** TEST-ONLY SWITCH — NOT RFC-CONFORMANT WHEN ENABLED ***
//
//  DRONE_REPLAY_RECORDED_TIME
//      1 = the ASTM Location message carries the RECORDED timestamp from the
//          dataset (e.g. 2025-11-09T20:27:29Z), replayed verbatim.
//      0 = the Location message carries the LIVE clock (RFC-conformant).
//
//  WHY THIS IS NOT CONFORMANT
//      ASTM F3411-22a Table 6 defines the Location timestamp as tenths of a
//      second within the CURRENT or previous UTC hour. Replaying a timestamp
//      from a past date makes that field describe a time that is not now, so a
//      receiver cross-checking the broadcast against the real world (RFC 9575
//      §9.1 / §6.3) can no longer use it for freshness.
//
//  SCOPE — what this switch does NOT touch
//      DRIP authentication timestamps (VNB/VNA in the Wrapper, Link and
//      Manifest) come from drip_timestamp(), NOT from this module. They remain
//      on the LIVE clock and stay RFC 9575 §3.2.4.3 conformant. Only the ASTM
//      Location message timestamp field is affected.
//
//  ENABLED ONLY to replay this specific historical dataset on the bench.
//  Set to 0 (or delete the block) before any live/flight use.
// ===========================================================================
#define DRONE_REPLAY_RECORDED_TIME  1

// Nominal seconds between a drone's transmission cycles (3 Hz -> ~0.333 s).
// Used only as a bootstrap/floor value for pacing; real elapsed time is
// MEASURED with millis() (see the bug-fix note in drone_playback.cpp).
#define PLAYBACK_CYCLE_S   0.3333f

// ---------------------------------------------------------------------------
// One virtual drone's independent playback cursor.
// Zero-initialise then call drone_playback_init().
// ---------------------------------------------------------------------------
struct PlaybackState {
    bool     ready;             // false until init() succeeded
    uint16_t flight;            // selected flight index into DRONE_FLIGHTS[]
    uint16_t idx;               // point CURRENTLY broadcast (already "arrived")
    bool     finished;          // track ended (or stopped) -> holding
    bool     stopped_by_user;   // halted via command, not end-of-track
    bool     started;           // false until the first point has been emitted

    // Real-timestamp pacing state.
    float    hold_elapsed_s;    // TX seconds accumulated while holding idx
    uint32_t last_call_ms;      // millis() at the previous call, for MEASURED pacing

    // Velocity that carried the drone INTO idx (from idx-1 to idx), held
    // constant while broadcast waits for real time to reach the next point.
    float    cur_speed;
    float    cur_vspeed;
    float    cur_heading;
};

// ---- flight table queries (global — the table is shared, the cursors are not) ----

// True if drone_data.h contains at least one flight.
bool        drone_playback_available();
// Number of flights compiled in.
uint16_t    drone_playback_count();
// Flight's ID string / point count (nullptr / 0 if out of range).
const char *drone_playback_name(uint16_t flight);
uint16_t    drone_playback_points(uint16_t flight);
// Real recorded duration of a flight, in seconds.
float       drone_playback_duration_s(uint16_t flight);
// Print the flight table to Serial.
void        drone_playback_list();

// ---- per-drone cursor ----

// Initialise `st` and select `flight`. Returns false if there are no flights or
// the index is out of range.
bool drone_playback_init(PlaybackState *st, uint16_t flight);

// Select a flight by index [0, count) and restart it at point 0.
bool drone_playback_select(PlaybackState *st, uint16_t index);

// Restart the current flight at point 0.
void drone_playback_reset(PlaybackState *st);

// Halt this drone on demand (equivalent to reaching end-of-track): the fleet
// checks drone_playback_finished() and stops transmitting for this drone.
// Resume by selecting a flight (or 'reset'). No-op if already halted.
// `slot` is used only for logging.
void drone_playback_stop(PlaybackState *st, uint8_t slot);

// True once this drone's flight has reached its last point (playback holding).
bool drone_playback_finished(const PlaybackState *st);

// Advance this drone's track (call once per ITS transmission cycle) and return
// the position, with speed/heading/vspeed derived from the previous point.
// Once the track ends, keeps returning the final point with zero velocity.
//
// `live_unix_time_s` is used for DronePosition.unix_time_s ONLY when
// DRONE_REPLAY_RECORDED_TIME == 0. When it is 1 (test mode) the argument is
// ignored and the point's RECORDED timestamp is returned instead.
// `slot` is used only for logging the end-of-track notice.
DronePosition drone_playback_next(PlaybackState *st, uint32_t live_unix_time_s,
                                  uint8_t slot);

// Operator / launch location for the System message: first point of the track.
void drone_playback_get_launch(const PlaybackState *st,
                               double *lat, double *lon, float *alt_m);
