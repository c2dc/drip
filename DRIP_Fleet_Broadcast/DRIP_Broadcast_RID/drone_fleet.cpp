#include "drone_fleet.h"
#include "drip_config.h"
#include "beacon_tx_raw.h"
#include "f3411_messages.h"
#include "message_pack.h"
#include "drip_time.h"
#include "drip_auth.h"
#include "drip_link.h"
#include "drip_manifest.h"
#include "drip_registration.h"
#include "drip_debug.h"
#include <Arduino.h>
#include <string.h>
#include <stdlib.h>

// ---------------------------------------------------------------------------
// Fleet state
// ---------------------------------------------------------------------------
static VirtualDrone g_fleet[FLEET_MAX];
static uint8_t      g_n     = 1;   // drones currently in the fleet
static uint8_t      g_focus = 0;   // slot the legacy commands act on

// Which slot's pack gets hex-dumped. -1 = none.
// See the bandwidth note in drip_debug.h: at 115200 baud a single drone's dump
// already eats ~90% of the link, so only ONE drone can ever be dumped.
static int8_t       g_debug_slot = -1;

// DRIP epoch -> Unix epoch offset (2019-01-01T00:00:00Z), as the .ino used.
#define DRIP_EPOCH_UNIX_OFFSET   1546300800u

// ---------------------------------------------------------------------------
// Provision one slot: identity, track, manifest chain, counters, phase.
// ---------------------------------------------------------------------------
static bool fleet_provision(uint8_t slot, uint16_t flight) {
    VirtualDrone *d = &g_fleet[slot];
    memset(d, 0, sizeof(*d));

    // Identity is bound to the SLOT, not the flight — that is what lets two
    // drones fly the same recorded track under different DETs.
    if (!det_load_identity(slot, d->id)) {
        Serial.printf("[Fleet] slot %u: no identity in the table\n", (unsigned)slot);
        return false;
    }
    if (!drone_playback_init(&d->track, flight)) {
        Serial.printf("[Fleet] slot %u: cannot select flight %u\n",
                      (unsigned)slot, flight);
        return false;
    }
    // Each UA owns its Prev/Curr Manifest hash chain (RFC 9575 §4.4.2). Seeded
    // from the hardware RNG, so two drones never share a chain.
    drip_manifest_init(&d->manifest);

    d->msg_counter = 0;
    d->cycle       = slot;    // PHASE STAGGER: drone i starts at phase i
    d->active      = true;
    d->off_air     = false;
    return true;
}

// Re-sign the BE chain for the current fleet. RFC 9575 §6.4.2: every UA needs
// its own BE:HDA,UA, so this must run whenever the fleet's membership changes.
static bool g_reg_first = true;   // first chain signing prints in full

static void fleet_reg_refresh() {
#ifdef DRIP_TEST_BE
    DETIdentity ids[FLEET_MAX];
    for (uint8_t i = 0; i < g_n; i++) ids[i] = g_fleet[i].id;
    // Full detail on the FIRST signing (the "this chain is fake" warning and
    // the anchor DETs must always be on the record at boot), and whenever the
    // operator has asked for debug. Every later re-sign — one per `fleet` /
    // `fleet set` — collapses to a single line so it does not bury the
    // command that triggered it.
    drip_reg_init_fleet(ids, g_n, g_reg_first || g_debug_slot >= 0);
    g_reg_first = false;
#endif
}

// Spread the drones' pack rebuilds evenly across the 333 ms period so that at
// most one Ed25519 signature is in flight at any instant.
static void fleet_restagger(uint32_t now) {
    uint32_t step = (g_n > 0) ? (FLEET_PACK_PERIOD_MS / g_n) : FLEET_PACK_PERIOD_MS;
    for (uint8_t i = 0; i < g_n; i++) {
        g_fleet[i].next_pack_ms   = now + (uint32_t)i * step;
        g_fleet[i].next_beacon_ms = now + (uint32_t)i * step;
    }
}

// ---------------------------------------------------------------------------
static void fleet_list() {
    Serial.println("[Fleet] slot  MAC                DET                               flight  phase  point");
    for (uint8_t s = 0; s < g_n; s++) {
        VirtualDrone *d = &g_fleet[s];
        if (!d->active) continue;
        const uint8_t *m = beacon_tx_raw_mac(s);
        Serial.printf("   %s%u   %02X:%02X:%02X:%02X:%02X:%02X  ",
                      (s == g_focus) ? ">" : " ", (unsigned)s,
                      m[0], m[1], m[2], m[3], m[4], m[5]);
        for (int i = 0; i < DET_BYTES; i++) Serial.printf("%02X", d->id.det[i]);
        Serial.printf("  %5u   %c    %5u/%u%s\n",
                      d->track.flight,
                      "ABC"[d->cycle % 3],
                      d->track.idx, drone_playback_points(d->track.flight),
                      d->off_air ? "  [off air]" : "");
    }
    Serial.printf("[Fleet] %u drone(s); focus=slot %u; pack dump=%s\n",
                  (unsigned)g_n, (unsigned)g_focus,
                  (g_debug_slot < 0) ? "off" : "on");
    if (g_debug_slot >= 0) Serial.printf("[Fleet] dumping slot %d\n", (int)g_debug_slot);
}

// ---------------------------------------------------------------------------
// Resize / re-assign the fleet.
//   same == true  -> every drone replays `same_flight`
//   same == false -> drone i replays flight i (wrapped to the table size)
// ---------------------------------------------------------------------------
static void fleet_set_size(uint8_t n, bool same, uint16_t same_flight) {
    if (n < 1 || n > FLEET_MAX) {
        Serial.printf("[Fleet] n must be 1..%u (FLEET_MAX in drone_fleet.h)\n",
                      (unsigned)FLEET_MAX);
        return;
    }
    if (!drone_playback_available()) {
        Serial.println("[Fleet] no flights compiled in (drone_data.h) — cannot start");
        return;
    }
    const uint16_t nflights = drone_playback_count();
    if (same && same_flight >= nflights) {
        Serial.printf("[Fleet] flight %u out of range (0..%u)\n",
                      same_flight, nflights - 1);
        return;
    }

    // Take the drones being removed off the air BEFORE forgetting them.
    for (uint8_t i = n; i < FLEET_MAX; i++) {
        if (g_fleet[i].active) beacon_tx_raw_stop(i);
        g_fleet[i].active = false;
    }
    for (uint8_t i = 0; i < n; i++) {
        uint16_t f = same ? same_flight : (uint16_t)(i % nflights);
        fleet_provision(i, f);
    }

    g_n = n;
    if (g_focus >= g_n) g_focus = 0;

    // With more than one drone the serial link cannot carry the hex dumps
    // (drip_debug.h bandwidth note) — turning it off is the difference between
    // a working scheduler and one that blocks in Serial.print().
    if (g_n > 1 && g_debug_slot >= 0) {
        g_debug_slot = -1;
        Serial.println("[Fleet] pack dump AUTO-DISABLED: at 115200 baud one drone's "
                       "dump already uses ~90% of the link, so >1 drone would stall "
                       "the scheduler. Use 'debug <slot>' to dump exactly one.");
    }

    fleet_reg_refresh();
    fleet_restagger(millis());
    fleet_list();
}

// ---------------------------------------------------------------------------
// Build and transmit ONE drone's pack. This is the original .ino A/B/C cycle,
// unchanged in substance — only the singletons became per-drone fields.
// ---------------------------------------------------------------------------
static void fleet_build_and_send(uint8_t slot, VirtualDrone *d) {
    const uint8_t phase = (uint8_t)(d->cycle % 3);

    // Gate the hex dump to at most one drone (see drip_debug.h).
    drip_debug_set_enabled(g_debug_slot == (int8_t)slot);

    // Position: recorded track. While DRONE_REPLAY_RECORDED_TIME == 1 the
    // argument is ignored and the point's RECORDED timestamp is used; DRIP
    // VNB/VNA still come from drip_timestamp() and stay RFC 9575 §3.2.4.3
    // conformant.
    DronePosition pos = drone_playback_next(&d->track,
                                            drip_timestamp() + DRIP_EPOCH_UNIX_OFFSET,
                                            slot);

    uint8_t session_id[SESSION_ID_BYTES];
    det_to_session_id(d->id.det, session_id);          // THIS drone's DET

    F3411BasicID  basic_id = f3411_build_basic_id(session_id);
    F3411Location location = f3411_build_location(pos);

    double op_lat, op_lon; float op_alt;
    drone_playback_get_launch(&d->track, &op_lat, &op_lon, &op_alt);
    F3411System system_msg = f3411_build_system(op_lat, op_lon, op_alt);

    // Common to all cycles: Basic ID + Location. System is added per-cycle
    // (A and C only — Cycle B has no room; see the CYCLE-B NOTE in the .ino).
    MessagePack pack;
    message_pack_init(&pack);
    message_pack_add(&pack, (const uint8_t *)&basic_id);
    message_pack_add(&pack, (const uint8_t *)&location);

    switch (phase) {

        // ---- Cycle A: DRIP Wrapper (RFC 9575 §4.3) ----
        case 0: {
            message_pack_add(&pack, (const uint8_t *)&system_msg);

            uint8_t wrapper[DRIP_WRAPPER_MAX_PAGES][F3411_MSG_BYTES];
            uint8_t wrapper_pages = 0;
            // Signs with THIS drone's key and carries THIS drone's DET.
            drip_wrapper_build(d->id, &pack, wrapper, &wrapper_pages);
            for (uint8_t i = 0; i < wrapper_pages; i++)
                message_pack_add(&pack, wrapper[i]);

            drip_manifest_update_pack(&d->manifest, pack.buf,
                                      message_pack_bytes(&pack));
            break;
        }

        // ---- Cycle B: DRIP Link / Broadcast Endorsement (RFC 9575 §4.2) ----
        case 1: {
#ifdef DRIP_TEST_BE
            // This slot's own rotation cursor over its own chain.
            const BroadcastEndorsement *be = drip_reg_next_link(slot);
            uint8_t link[DRIP_LINK_MAX_PAGES][F3411_MSG_BYTES];
            uint8_t link_pages = drip_link_build_be(be, link, DRIP_LINK_MAX_PAGES);
            for (uint8_t i = 0; i < link_pages; i++)
                message_pack_add(&pack, link[i]);   // 7 pages -> 2 + 7 = 9 msgs

            // The Manifest references BE:HDA,UA specifically (RFC §4.4.2), so
            // hash THIS drone's leaf regardless of which link went out.
            uint8_t hu_sam[DRIP_LINK_SAM_BYTES];
            uint8_t hu_len = drip_reg_hda_ua_sam(slot, hu_sam);
            drip_manifest_update_link(&d->manifest, hu_sam, hu_len);
#else
            Serial.println("[Link] No Broadcast Endorsement provisioned. "
                           "Define DRIP_TEST_BE (test) or load BE records (production).");
#endif
            break;
        }

        // ---- Cycle C: DRIP Manifest (RFC 9575 §4.4) ----
        case 2: {
            message_pack_add(&pack, (const uint8_t *)&system_msg);

            uint8_t manifest[DRIP_MANIFEST_MAX_PAGES][F3411_MSG_BYTES];
            uint8_t manifest_pages = 0;
            drip_manifest_build(&d->manifest, d->id, manifest, &manifest_pages);
            for (uint8_t i = 0; i < manifest_pages; i++)
                message_pack_add(&pack, manifest[i]);
            break;
        }
    }

    const uint8_t tx_counter = d->msg_counter++;   // per-UA (ASTM §5.4.4.2)
    beacon_tx_raw_send(slot, &pack, tx_counter);
    drip_debug_print_pack(&pack, tx_counter, phase, slot, d->id.det);

    d->cycle++;
}

// ---------------------------------------------------------------------------
void fleet_init() {
    memset(g_fleet, 0, sizeof(g_fleet));
    g_n = 1; g_focus = 0;
    // Boot CLEAN: the console is for flying the drones. Per-cycle status from
    // the Wrapper/Manifest and the pack hex dump stay silent until asked for.
    // Signing WARN/ERROR lines are never gated, so a quiet console means
    // "everything is signing", not "no information".
    g_debug_slot = -1;

    if (!drone_playback_available()) {
        Serial.println("[Fleet] ERROR: drone_data.h contains no flights — nothing to fly.");
        Serial.println("[Fleet] (The old flight_sim fallback was dropped for the fleet: it is");
        Serial.println("[Fleet]  a stateless global route, so N drones would all sit on the");
        Serial.println("[Fleet]  same synthetic point — a degenerate multi-drone test.)");
        return;
    }

    fleet_provision(0, 0);
    fleet_reg_refresh();

    drip_debug_set_enabled(false);
    fleet_restagger(millis());

    Serial.println();
    drone_playback_list();
    fleet_list();
    Serial.println("[Fleet] console is QUIET by default — 'debug on' shows this drone's");
    Serial.println("        per-cycle Wrapper/Manifest detail + pack hex dump.");
    Serial.println("[Fleet] commands: fleet <1..3> | fleet <n> same <flight> |");
    Serial.println("                  fleet set <slot> <flight> | fleet list |");
    Serial.println("                  focus <slot> | debug off|on|<slot> |");
    Serial.println("                  list | info | next | reset | stop | <number>");
}

// ---------------------------------------------------------------------------
void fleet_tick(uint32_t now_ms) {
    for (uint8_t s = 0; s < g_n; s++) {
        VirtualDrone *d = &g_fleet[s];
        if (!d->active) continue;

        // End of track (or 'stop'): this drone leaves the air. Nothing is built
        // or signed, its Manifest chain does not advance, its counter freezes.
        // Selecting a flight for it resumes transmission.
        if (drone_playback_finished(&d->track)) {
            if (!d->off_air) { beacon_tx_raw_stop(s); d->off_air = true; }
            continue;
        }
        d->off_air = false;

        // Signed comparison handles millis() wraparound (~49.7 days) correctly.
        if ((int32_t)(now_ms - d->next_pack_ms) >= 0) {
            fleet_build_and_send(s, d);
            // Re-arm from NOW rather than += period: if a cycle overruns we do
            // not want a burst of catch-up sends.
            d->next_pack_ms   = now_ms + FLEET_PACK_PERIOD_MS;
            d->next_beacon_ms = now_ms + FLEET_BEACON_PERIOD_MS;
        } else if ((int32_t)(now_ms - d->next_beacon_ms) >= 0) {
            // Same pack, same Message Counter — ASTM §5.4.4.2 (BUR0050) permits
            // repeating unchanged data. Only the 802.11 sequence advances.
            beacon_tx_raw_repeat(s);
            d->next_beacon_ms = now_ms + FLEET_BEACON_PERIOD_MS;
        }
    }
}

// ---------------------------------------------------------------------------
// Serial commands
// ---------------------------------------------------------------------------
static bool parse_u16(const char *s, uint16_t *out) {
    char *end;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || v < 0 || v > 65535) return false;
    *out = (uint16_t)v;
    return true;
}

void fleet_cmd() {
    if (!Serial.available()) return;

    char buf[48];
    size_t n = Serial.readBytesUntil('\n', buf, sizeof(buf) - 1);
    buf[n] = '\0';
    while (n && (buf[n - 1] == '\r' || buf[n - 1] == ' ')) buf[--n] = '\0';
    if (n == 0) return;

    // ---- tokenise ----
    char *tok[4] = {nullptr, nullptr, nullptr, nullptr};
    uint8_t ntok = 0;
    for (char *p = strtok(buf, " "); p && ntok < 4; p = strtok(nullptr, " "))
        tok[ntok++] = p;
    if (ntok == 0) return;

    VirtualDrone *f = &g_fleet[g_focus];

    // ---- fleet ... ----
    if (strcasecmp(tok[0], "fleet") == 0) {
        if (ntok == 1 || strcasecmp(tok[1], "list") == 0) { fleet_list(); return; }

        if (strcasecmp(tok[1], "set") == 0) {
            uint16_t slot, flight;
            if (ntok < 4 || !parse_u16(tok[2], &slot) || !parse_u16(tok[3], &flight)) {
                Serial.println("[Fleet] usage: fleet set <slot> <flight>");
                return;
            }
            if (slot >= g_n) {
                Serial.printf("[Fleet] slot %u not in the fleet (have 0..%u)\n",
                              slot, (unsigned)(g_n - 1));
                return;
            }
            if (!fleet_provision((uint8_t)slot, flight)) return;
            fleet_reg_refresh();          // that slot's leaf BE must be re-issued
            fleet_restagger(millis());
            Serial.printf("[Fleet] slot %u -> flight %u (%s)\n",
                          slot, flight, drone_playback_name(flight));
            fleet_list();
            return;
        }

        uint16_t cnt;
        if (!parse_u16(tok[1], &cnt)) {
            Serial.println("[Fleet] usage: fleet <1..3> | fleet <n> same <flight> | "
                           "fleet set <slot> <flight> | fleet list");
            return;
        }
        if (ntok >= 4 && strcasecmp(tok[2], "same") == 0) {
            uint16_t fl;
            if (!parse_u16(tok[3], &fl)) { Serial.println("[Fleet] bad flight index"); return; }
            fleet_set_size((uint8_t)cnt, true, fl);
        } else {
            fleet_set_size((uint8_t)cnt, false, 0);
        }
        return;
    }

    // ---- focus <slot> ----
    if (strcasecmp(tok[0], "focus") == 0) {
        uint16_t slot;
        if (ntok < 2 || !parse_u16(tok[1], &slot) || slot >= g_n) {
            Serial.printf("[Fleet] usage: focus <0..%u>\n", (unsigned)(g_n - 1));
            return;
        }
        g_focus = (uint8_t)slot;
        Serial.printf("[Fleet] focus = slot %u — list/info/next/reset/stop/<number> "
                      "now act on it\n", (unsigned)g_focus);
        return;
    }

    // ---- debug off|on|<slot> ----
    if (strcasecmp(tok[0], "debug") == 0) {
        if (ntok < 2) { Serial.println("[Fleet] usage: debug off|on|<slot>"); return; }
        if (strcasecmp(tok[1], "off") == 0) {
            g_debug_slot = -1;
            Serial.println("[Fleet] pack dump off");
        } else if (strcasecmp(tok[1], "on") == 0) {
            g_debug_slot = (int8_t)g_focus;
            Serial.printf("[Fleet] pack dump -> slot %u (focused)\n", (unsigned)g_focus);
        } else {
            uint16_t slot;
            if (!parse_u16(tok[1], &slot) || slot >= g_n) {
                Serial.printf("[Fleet] usage: debug off|on|<0..%u>\n", (unsigned)(g_n - 1));
                return;
            }
            g_debug_slot = (int8_t)slot;
            Serial.printf("[Fleet] pack dump -> slot %u ONLY (one drone is all the "
                          "115200 link can carry)\n", slot);
        }
        return;
    }

    // ---- legacy single-drone commands: act on the FOCUSED slot ----
    if (strcasecmp(tok[0], "list") == 0) { drone_playback_list(); fleet_list(); return; }

    if (strcasecmp(tok[0], "info") == 0) {
        Serial.printf("[Playback] drone %u: flight %u (%s), point %u/%u%s\n",
                      (unsigned)g_focus, f->track.flight,
                      drone_playback_name(f->track.flight),
                      f->track.idx, drone_playback_points(f->track.flight),
                      f->track.finished
                        ? (f->track.stopped_by_user ? "  [stopped by command]"
                                                    : "  [finished — holding]")
                        : "");
        return;
    }

    if (strcasecmp(tok[0], "stop") == 0) { drone_playback_stop(&f->track, g_focus); return; }

    if (strcasecmp(tok[0], "reset") == 0) {
        drone_playback_reset(&f->track);
        f->off_air = false;
        Serial.printf("[Playback] drone %u restarted at point 0\n", (unsigned)g_focus);
        return;
    }

    if (strcasecmp(tok[0], "next") == 0) {
        DronePosition p = drone_playback_next(&f->track, 0, g_focus);
        Serial.printf("[Playback] drone %u -> lat=%.7f lon=%.7f alt=%.1f m "
                      "spd=%.1f hdg=%.0f ts=%lu\n",
                      (unsigned)g_focus, p.lat, p.lon, p.alt_m,
                      p.speed_mps, p.heading_deg, (unsigned long)p.unix_time_s);
        return;
    }

    // ---- <number> : select a flight for the focused slot ----
    uint16_t v;
    if (parse_u16(tok[0], &v)) {
        if (!drone_playback_select(&f->track, v)) {
            Serial.printf("[Playback] invalid index %u (0..%u)\n",
                          v, drone_playback_count() - 1);
            return;
        }
        f->off_air = false;
        Serial.printf("[Playback] drone %u selected flight %u: %s (%u points, ~%.1f min)\n",
                      (unsigned)g_focus, v, drone_playback_name(v),
                      drone_playback_points(v), drone_playback_duration_s(v) / 60.0f);
        return;
    }

    Serial.printf("[Fleet] unknown command '%s'\n", tok[0]);
    Serial.println("        fleet <1..3> | fleet <n> same <flight> | fleet set <slot> <flight> |");
    Serial.println("        fleet list | focus <slot> | debug off|on|<slot> |");
    Serial.println("        list | info | next | reset | stop | <number>");
}
