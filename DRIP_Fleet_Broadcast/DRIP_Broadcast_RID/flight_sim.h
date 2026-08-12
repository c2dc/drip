#pragma once
#include "f3411_messages.h"

// ---------------------------------------------------------------------------
// Simulated flight: square route at constant altitude
// Modify SIM_BASE_* to relocate the test flight area.
// ---------------------------------------------------------------------------

#define SIM_BASE_LAT      -23.2094    // degrees
#define SIM_BASE_LON      -45.8694    // degrees
#define SIM_BASE_ALT_M     100.0f     // metres above takeoff
#define SIM_SPEED_MPS        5.0f     // horizontal speed m/s

// Number of waypoints in ROUTE[]
#define SIM_WAYPOINT_COUNT   5

// Returns interpolated drone position for the given millis() value.
// Loops continuously through the hardcoded square route.
DronePosition flight_sim_get_position(uint32_t now_ms);

// Returns the launch-point coordinates (operator position for System message).
void flight_sim_get_launch(double *lat, double *lon, float *alt_m);
