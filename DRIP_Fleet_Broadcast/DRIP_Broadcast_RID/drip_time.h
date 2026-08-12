#pragma once
#include <Arduino.h>          // required for millis()
#include "f3411_messages.h"   // for DRIP_EPOCH / SIM_DRIP_TIME_BASE constants

// Returns current time in the DRIP epoch (seconds since 2019-01-01 00:00:00 UTC).
// RFC 9575 §3.2.4.3: all authentication timestamps use this epoch.
//
// SIM_DRIP_TIME_BASE approximates the current wall-clock offset; update it
// in f3411_messages.h before each test session:
//   SIM_DRIP_TIME_BASE = <current Unix time> - DRIP_EPOCH_UNIX_S
inline uint32_t drip_timestamp() {
    return SIM_DRIP_TIME_BASE + (uint32_t)(millis() / 1000UL);
}
