#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - live_observer.py
#  Real-time view of a Format A (DRIP_Sniffer) capture that is still being
#  written. Decodes and validates every frame as it arrives and publishes the
#  result on a local web page.
#
#  TWO WAYS TO RUN
#  ---------------
#    1. Attach to a capture already in progress (this file):
#           python3 live_observer.py capture.txt
#       The serial port is NOT touched. Use this when arduino_logger.py is
#       already running in another window.
#
#    2. Start the capture and the view together:
#           python3 run_live.py --port COM4
#
#  WHERE IT RESUMES
#  ----------------
#  By default it starts at the END of the file and shows what happens from now
#  on. Re-reading a long capture from the top to rebuild state would take
#  ~166 s of cSHAKE128 hashing for one hour of prior flight (measured), during
#  which the map would be blank. Instead the first `--warmup` seconds suppress
#  E-MAN-02 / E-MAN-03, whose only failure mode at start-up is referring to
#  packs captured before we attached. Use --from-start to replay the whole file.
#
#  WHAT THIS IS NOT
#  ----------------
#  It is a monitoring tool. Because it must judge each message with only what
#  has arrived so far, it can disagree with a batch observer.py run over the
#  finished capture. The batch run is the authoritative conformance result.
#  See live_state.py for the full statement of that difference.
# =============================================================================

import argparse
import os
import sys
import time
import traceback
import webbrowser

import observer
import live_feed
import live_state
import live_server


def build_keyring(args):
    """Assemble the keyring exactly as observer.py's main() does, so the live
       view and the batch report are verifying against the same identities."""
    keys = observer.Keyring() if args.no_builtin_keys \
        else observer.default_keyring(args.anchor)

    if args.pubkey:
        try:
            keys.set_wildcard(bytes.fromhex(args.pubkey.replace(" ", "")))
        except ValueError as e:
            print(f"ERROR: --pubkey is not valid hex: {e}")
            return None

    if args.keyring:
        try:
            with open(args.keyring, encoding="utf-8") as fh:
                for ln, line in enumerate(fh, 1):
                    t = line.split("#", 1)[0].split()
                    if not t:
                        continue
                    if len(t) != 2:
                        print(f"ERROR: {args.keyring}:{ln}: expected "
                              f"'DET_HEX PUBKEY_HEX'")
                        return None
                    d_hex, p_hex = t
                    if len(d_hex) != 32 or len(p_hex) != 64:
                        print(f"ERROR: {args.keyring}:{ln}: DET must be 32 hex "
                              f"chars and pubkey 64; got "
                              f"{len(d_hex)}/{len(p_hex)}")
                        return None
                    keys.add(bytes.fromhex(d_hex), bytes.fromhex(p_hex))
        except OSError as e:
            print(f"ERROR: cannot read --keyring: {e}")
            return None
    return keys


def add_arguments(ap):
    """Shared with run_live.py so both front ends take the same options."""
    ap.add_argument("--keyring", metavar="FILE",
                    help="file of 'DET_HEX PUBKEY_HEX' pairs, same format as "
                         "observer.py --keyring")
    ap.add_argument("--pubkey", metavar="HEX",
                    help="wildcard Ed25519 public key for any DET with no "
                         "keyring entry")
    ap.add_argument("--no-builtin-keys", action="store_true",
                    help="do not preload identities from the trust anchor file")
    ap.add_argument("--anchor", default="hierarchy.json",
                    help="trusted-identities file (default: hierarchy.json)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="address to serve on (default: 127.0.0.1). The "
                         "snapshot carries aircraft positions and identities, "
                         "so it is loopback-only unless you change this.")
    ap.add_argument("--web-port", type=int, default=8080,
                    help="web page port (default: 8080)")
    ap.add_argument("--stale", type=float, default=10.0,
                    help="seconds of silence before a drone is marked stale "
                         "(default: 10)")
    ap.add_argument("--drop", type=float, default=90.0,
                    help="seconds of silence before a drone leaves the map "
                         "(default: 90)")
    ap.add_argument("--grace", type=float, default=4.0,
                    help="seconds a Manifest waits before E-MAN-02/E-MAN-03 "
                         "are decided (default: 4)")
    ap.add_argument("--warmup", type=float, default=4.0,
                    help="seconds after start during which E-MAN-02/E-MAN-03 "
                         "are suppressed (default: 4)")
    ap.add_argument("--trail", type=int, default=500,
                    help="max track points kept per drone in the live view; 0 "
                         "= unlimited (default: 500). The full track is always "
                         "still in the capture file for make_map.py.")
    ap.add_argument("--max-age", type=float, default=None,
                    help="freshness window in seconds for E-FRESH-01 "
                         "(default: off, same as observer.py)")
    ap.add_argument("--now", type=float, default=None, metavar="UNIX",
                    help="TEST ONLY. Reference Unix time for time-based checks "
                         "(E-LINK-04, E-FRESH-01) instead of the real clock. "
                         "For a bench whose transmitter has no RTC/GNSS/NTP. "
                         "It does NOT fix the aircraft, and any run using it is "
                         "a bench exercise, not evidence. Can also be set from "
                         "the web page while running.")
    ap.add_argument("--from-start", action="store_true",
                    help="read the capture from the beginning instead of "
                         "resuming at the end")
    ap.add_argument("--no-browser", action="store_true",
                    help="do not open a web browser automatically")
    return ap


def run(path, args):
    """The live loop. Returns an exit code. Shared with run_live.py."""
    keys = build_keyring(args)
    if keys is None:
        return 2

    print(f"Ed25519 backend: {observer.ed25519_backend.backend_name()}")
    print(f"  self-test: {observer.ed25519_backend.selftest_note()}")
    print(f"Keyring: {len(keys)} DET-bound key(s)")
    if len(keys) == 0:
        print("  NOTE: no keys - no signature will be verified (E-KEY-01).")

    if not live_feed.wait_for_file(path, timeout=30.0):
        print(f"ERROR: capture file never appeared: {path}")
        return 2

    state = live_state.LiveState(
        keys=keys, stale_s=args.stale, drop_s=args.drop, grace_s=args.grace,
        warmup_s=args.warmup, trail=(args.trail or 0), max_age=args.max_age)
    if args.now is not None:
        state.set_time_override(args.now)
        print("\n*** TEST-ONLY TIME OVERRIDE ACTIVE ***")
        print(f"    time-based checks use "
              f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(args.now))}, "
              f"not the real clock.")
        print("    This does not correct the aircraft. This run is a bench "
              "exercise, not evidence.")

    feed = live_feed.LiveFeed(path, start_at_end=not args.from_start)

    try:
        httpd = live_server.serve(state, host=args.host, port=args.web_port)
    except OSError as e:
        print(f"ERROR: cannot serve on {args.host}:{args.web_port}: {e}")
        return 2

    url = f"http://{args.host}:{args.web_port}/"
    print(f"\nReading : {path}"
          f"  ({'from the start' if args.from_start else 'resuming at the end'})")
    print(f"Live map: {url}")
    print(f"stale {args.stale:g}s / drop {args.drop:g}s / grace {args.grace:g}s "
          f"/ warm-up {args.warmup:g}s")
    print("The batch observer.py run over the finished capture remains the "
          "authoritative report.")
    print("Ctrl+C to stop.\n")

    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    t_status = time.time()
    try:
        while True:
            events = feed.poll()
            # No EOF in a live stream, so the newest frame is closed by an idle
            # gap instead. 2 s is comfortably longer than the measured ~210 ms
            # inter-frame spacing.
            events += feed.flush_idle(idle_s=2.0)

            for kind, a, b in events:
                # ONE BAD FRAME MUST NEVER END THE SESSION.
                # Before this guard the loop caught only KeyboardInterrupt, so
                # any other exception unwound past the loop, hit the finally
                # block, shut the HTTP server down and killed the process - the
                # browser then showed "Failed to fetch" with no explanation on
                # the page. Log it, count it, carry on.
                try:
                    if kind == "frame":
                        state.ingest_frame(a, b)
                    elif kind == "damaged":
                        state.ingest_damaged(a, b)
                    elif kind == "stats":
                        state.ingest_stats(a)
                except Exception:
                    state.frames_skipped += 1
                    print(f"\n[skipped {kind} #{state.frames_ok + 1}] "
                          f"unhandled error - continuing:")
                    traceback.print_exc()

            try:
                state.tick()
            except Exception:
                print("\n[tick error] continuing:")
                traceback.print_exc()

            now = time.time()
            if now - t_status >= 1.0:
                t_status = now
                snap_n = len([d for d in state.drones.values()
                              if d.status(now, args.stale, args.drop) != "dropped"])
                sn = state.sniffer_stats
                drop_txt = ""
                if sn.get("dropped"):
                    drop_txt = f" | SNIFFER DROPPED {sn['dropped']}"
                if state.frames_skipped:
                    drop_txt += f" | SKIPPED {state.frames_skipped}"
                if state.time_override is not None:
                    drop_txt += " | TEST CLOCK"
                sys.stdout.write(
                    f"\r  {state.frames_ok:8,d} frames | "
                    f"{state.frames_damaged:4d} damaged | "
                    f"{snap_n} drone(s) live{drop_txt}   ")
                sys.stdout.flush()

            time.sleep(0.05)
    except KeyboardInterrupt:
        print("\nStopped by user (Ctrl+C).")
    finally:
        try:
            httpd.shutdown()
        except Exception:
            pass
        feed.close()

    print(f"Totals: {state.frames_ok:,} frames, {state.frames_damaged} damaged, "
          f"{len(state.drones)} identity/identities seen.")
    print(f"For the authoritative report:  python3 observer.py {path}"
          + (f" --keyring {args.keyring}" if args.keyring else ""))
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Real-time DRIP observer for a Format A capture that is "
                    "still being written. Does not touch the serial port.")
    ap.add_argument("file", help="capture file being written by "
                                 "arduino_logger.py (Format A)")
    add_arguments(ap)
    args = ap.parse_args()

    if not os.path.exists(args.file):
        print(f"Waiting for {args.file} to appear...")
    return run(args.file, args)


if __name__ == "__main__":
    sys.exit(main())
