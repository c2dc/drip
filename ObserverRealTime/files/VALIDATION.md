# Live path vs batch observer - reference capture CaptureWithDNS4.txt

Batch:  python3 observer.py CaptureWithDNS4.txt --keyring new.keyring
Live :  python3 replay_test.py CaptureWithDNS4.txt new.keyring
        (replay driven by the capture's own t_us timeline, grace=4s warmup=4s)

## Framing - EXACT agreement with odid.parse_format_a()
frames intact        7352   ==   7352
frames damaged          3   ==      3
frame bytes identical           True
frame metadata identical        True
damaged list identical          True

## Findings
identity                              batch                          live
d952:5618:fbc9:c3cf   E-KEY-01 x4667 E-MAN-02 x2 E-MAN-04 x3   ==  same
8412:4323:5d3c:a050   E-MAN-02 x2 E-MAN-04 x3                  ==  same
a57e:87ab:5388:cbb8   E-MAN-02 x2 E-MAN-04 x3                  ==  same
(unattributed)        W-CAP-01 x3                              ==  same

## Track points - match flight_tracks.extract_tracks()
3117 / 1375 / 2860   ==   3117 / 1375 / 2860

## The ONE intentional difference
E-LINK-04 x1 per drone appears LIVE ONLY.
observer.run() passes now=None to verify_link_chain(), which SKIPS the
RFC 9575 3.2.4.3 validity-window check. The live view passes real time, so an
endorsement outside VNB..VNA is flagged. That is correct for a live view and
expected when replaying an old capture, whose endorsements have since expired.

## Drone drop behaviour (verified, not assumed)
a57e last transmitted at t+687.6s, 8412 at t+1430.2s, d952 at t+1558.4s.
Two drones therefore age out of "currently detecting" before the capture ends -
the 90 s drop rule working as specified, on real data.

## End-to-end test (live_observer.py against a file being appended in real time)
GET /              serves live_map.html                    OK
GET /state.json    valid JSON snapshot                     OK
GET /nope          404                                     OK
3 drones live, trail capped at 500 points each             OK
E-MAN-02 ABSENT - the 4 s warm-up suppressed exactly the
  frame[0]/frame[1]/frame[2] artefacts that batch reports  OK (intended)

## Ctrl+C shutdown (run_live.py)
SIGINT to the process group (what a console Ctrl+C does):
  launcher   receives KeyboardInterrupt
  launcher   WAITS rather than exiting
  child      runs its OWN KeyboardInterrupt handler to completion
  child      exits rc=0, cleanup confirmed written
So arduino_logger.py flushes its trailing partial line and closes the serial
port cleanly before the launcher lets go. Verified, not assumed.

## Files changed in the existing project
observer.py              UNCHANGED  (byte-identical report re-verified)
odid.py                  UNCHANGED
errors.py                UNCHANGED  (colour work deferred, as agreed)
arduino_logger.py        UNCHANGED
make_map.py              UNCHANGED  (re-run, still produces 3 tracks)
det.py / ed25519*.py     UNCHANGED
identity_resolve.py      UNCHANGED
flight_tracks.py         +23 lines, PURELY ADDITIVE (two public wrappers)

===============================================================================
 SECOND ROUND - test clock override, E-LINK-04 units, crash tolerance
===============================================================================

## observer.py - E-LINK-04 units fix (ONE change, verify_link_chain)
decode_link_sam() returns vnb/vna as RAW DRIP-epoch seconds; --now is
documented as UNIX. Comparing them directly placed `now` in the year 2075, so
E-LINK-04 fired on every endorsement whenever a reference time was given.
Hidden until now because --now defaults to None, which skips the check.

  default run (no --now)   output BYTE-IDENTICAL to the original baseline  PASS
  --now inside the window  UA endorsements now PASS                        PASS
  --now outside the window endorsements correctly flagged                  PASS

Real windows in CaptureWithDNS4.txt: vnb=201702421 vna=201788821 (86400 s),
i.e. unix 1748003221 .. 1748089621 (2025-05-23/24) - which is what
SIM_DRIP_TIME_BASE in f3411_messages.h pins the transmitter to.

## Test clock override
real clock            -> E-LINK-04 present                                 PASS
override inside window-> E-LINK-04 CLEARED                                 PASS
override cleared      -> E-LINK-04 returns                                 PASS
POST /set-time announces on the terminal, both set and clear               PASS
snapshot always carries "time_override" (null when off)                    PASS
staleness/last-seen stay on the REAL clock even when the override is set

## Memory leak fixed (internal flight_tracks copy was never trimmed)
  before:  frames=13859  tracks_pts=13859  drone_pts=1500   RSS 134 MB
  after :  frames= 7352  tracks_pts= 1500  drone_pts=1500   RSS  83 MB
Both copies now honour --trail.

## Crash tolerance
Per-event ingest and tick() are now individually guarded. An exception is
counted in frames_skipped, printed with a full traceback, and the session
CONTINUES. Previously any non-KeyboardInterrupt exception unwound past the
loop, ran the finally block, shut the HTTP server down and killed the process -
which is what produced "Failed to fetch" on the page with no explanation.
The skipped count is shown on the page and in the terminal status line.

## Files changed in the existing project (cumulative)
observer.py        MODIFIED - E-LINK-04 units only; default output identical
flight_tracks.py   MODIFIED - two additive public wrappers, no behaviour change
odid.py, errors.py, arduino_logger.py, make_map.py, det.py, ed25519*.py,
identity_resolve.py, identity_lookup.py, all firmware      UNCHANGED
