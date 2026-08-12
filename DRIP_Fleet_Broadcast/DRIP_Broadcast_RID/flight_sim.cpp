#include "flight_sim.h"
#include <math.h>

// Square route: each leg ~100 m at SIM_SPEED_MPS
// lat/lon offsets chosen so each side ≈ 100 m (at ~23° S lat)
static const struct { double lat, lon; } ROUTE[SIM_WAYPOINT_COUNT] = {
    { SIM_BASE_LAT,          SIM_BASE_LON          },   // 0 — takeoff
    { SIM_BASE_LAT + 0.0009, SIM_BASE_LON          },   // 1 — ~100 m north
    { SIM_BASE_LAT + 0.0009, SIM_BASE_LON + 0.0010 },   // 2 — ~100 m east
    { SIM_BASE_LAT,          SIM_BASE_LON + 0.0010 },   // 3 — ~100 m south
    { SIM_BASE_LAT,          SIM_BASE_LON          },   // 4 — return home
};

// Leg durations in milliseconds (distance / speed, approx.)
// Each leg ≈ 100 m → time = 100 / SIM_SPEED_MPS seconds
static const uint32_t LEG_MS[SIM_WAYPOINT_COUNT - 1] = {
    (uint32_t)(100.0f / SIM_SPEED_MPS * 1000.0f),
    (uint32_t)(100.0f / SIM_SPEED_MPS * 1000.0f),
    (uint32_t)(100.0f / SIM_SPEED_MPS * 1000.0f),
    (uint32_t)(141.0f / SIM_SPEED_MPS * 1000.0f),   // diagonal leg is longer
};

static uint32_t total_route_ms() {
    uint32_t t = 0;
    for (int i = 0; i < SIM_WAYPOINT_COUNT - 1; i++) t += LEG_MS[i];
    return t;
}

// Bearing from (lat1,lon1) to (lat2,lon2) in degrees (0 = north, CW)
static float bearing_deg(double lat1, double lon1, double lat2, double lon2) {
    double dlon = (lon2 - lon1) * M_PI / 180.0;
    lat1 *= M_PI / 180.0; lat2 *= M_PI / 180.0;
    double y = sin(dlon) * cos(lat2);
    double x = cos(lat1) * sin(lat2) - sin(lat1) * cos(lat2) * cos(dlon);
    double b = atan2(y, x) * 180.0 / M_PI;
    return (float)fmod(b + 360.0, 360.0);
}

DronePosition flight_sim_get_position(uint32_t now_ms) {
    uint32_t cycle_ms = now_ms % total_route_ms();

    // Find which leg we are on
    int leg = 0;
    uint32_t elapsed = cycle_ms;
    for (int i = 0; i < SIM_WAYPOINT_COUNT - 1; i++) {
        if (elapsed < LEG_MS[i]) { leg = i; break; }
        elapsed -= LEG_MS[i];
        leg = i + 1;
    }
    if (leg >= SIM_WAYPOINT_COUNT - 1) leg = SIM_WAYPOINT_COUNT - 2;

    // Interpolate position along current leg
    float t = (LEG_MS[leg] > 0) ? (float)elapsed / (float)LEG_MS[leg] : 0.0f;
    if (t > 1.0f) t = 1.0f;

    double lat = ROUTE[leg].lat + t * (ROUTE[leg + 1].lat - ROUTE[leg].lat);
    double lon = ROUTE[leg].lon + t * (ROUTE[leg + 1].lon - ROUTE[leg].lon);
    float  hdg = bearing_deg(ROUTE[leg].lat, ROUTE[leg].lon,
                              ROUTE[leg + 1].lat, ROUTE[leg + 1].lon);

    DronePosition pos = {};
    pos.lat         = lat;
    pos.lon         = lon;
    pos.alt_m       = SIM_BASE_ALT_M;
    pos.speed_mps   = SIM_SPEED_MPS;
    pos.vspeed_mps  = 0.0f;
    pos.heading_deg = hdg;
    pos.unix_time_s = now_ms / 1000UL;   // not real UTC — sufficient for testing
    return pos;
}

void flight_sim_get_launch(double *lat, double *lon, float *alt_m) {
    *lat   = ROUTE[0].lat;
    *lon   = ROUTE[0].lon;
    *alt_m = 0.0f;           // operator is at ground level
}
