#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - run_live.py
#  ONE command that starts the serial capture and the real-time map together.
#
#      python3 run_live.py --port COM4
#
#  Ctrl+C stops BOTH. See "SHUTDOWN" below for why that works.
#
# -----------------------------------------------------------------------------
#  CAPTURE FILENAME
#  With no -o, the capture is written to  capture_YYYY-MM-DD_HHMM.txt  so each
#  session is kept as its own evidence file. With -o NAME it uses NAME, exactly
#  as arduino_logger.py does today.
#
#  This matters: arduino_logger.py opens its output with mode "w", which
#  TRUNCATES. Run it twice with the same name and the previous flight is gone.
#  Timestamping by default means a capture cannot be destroyed by starting the
#  next one.
#
#  arduino_logger.py ITSELF IS NOT MODIFIED. The timestamped name is computed
#  here and passed to it with -o, so running that script directly behaves
#  exactly as it always has (default: data_log.txt).
#
# -----------------------------------------------------------------------------
#  SHUTDOWN - WHY Ctrl+C REACHES BOTH PROCESSES
#  The logger is started WITHOUT a new process group, deliberately. A console
#  Ctrl+C is delivered by the OS to every process in the console's group, so the
#  logger receives it directly and runs its OWN KeyboardInterrupt handler: it
#  writes out the trailing partial line, flushes, and closes the serial port
#  cleanly. This launcher then WAITS for it rather than exiting immediately,
#  because exiting first could kill the child mid-write and truncate the
#  capture. Only if the logger has not exited within a grace period is it
#  terminated.
#
#  Creating a new process group here would have been the wrong choice: it would
#  isolate the child from the console's Ctrl+C, and the launcher would then have
#  to synthesise a signal that behaves differently on Windows and POSIX.
#
# -----------------------------------------------------------------------------
#  BAUD
#  Defaults to 921600, the rate DRIP_Sniffer.ino is built for. Its own header
#  states 115200 is only 162% of the link budget and WILL drop frames, so the
#  transmitter's Format L default is not a safe default here.
# =============================================================================

import argparse
import os
import subprocess
import sys
import time

import live_observer

HERE = os.path.dirname(os.path.abspath(__file__))
LOGGER = os.path.join(HERE, "arduino_logger.py")

SHUTDOWN_GRACE_S = 10.0


def default_capture_name():
    return time.strftime("capture_%Y-%m-%d_%H%M.txt")


def main():
    ap = argparse.ArgumentParser(
        description="Start the DRIP_Sniffer serial capture and the real-time "
                    "map together. Ctrl+C stops both.")
    ap.add_argument("--port", default="COM4",
                    help="serial port of the SNIFFER ESP32 (default: COM4)")
    ap.add_argument("--baud", type=int, default=921600,
                    help="serial rate (default: 921600, what DRIP_Sniffer.ino "
                         "is built for)")
    ap.add_argument("-o", "--output", default=None,
                    help="capture filename. Default: capture_YYYY-MM-DD_HHMM.txt")
    live_observer.add_arguments(ap)
    args = ap.parse_args()

    out = args.output or default_capture_name()
    if args.output is None:
        print(f"No -o given, so this capture is being kept as: {out}")
    if os.path.exists(out):
        # arduino_logger.py opens with "w". Say so before it happens.
        print(f"WARNING: {out} already exists and will be OVERWRITTEN.")

    if not os.path.exists(LOGGER):
        print(f"ERROR: cannot find {LOGGER}")
        return 2

    cmd = [sys.executable, LOGGER, "--port", args.port,
           "--baud", str(args.baud), "-o", out]
    print(f"Starting capture: {' '.join(cmd)}")

    try:
        # No new process group, on purpose - see SHUTDOWN in the header.
        child = subprocess.Popen(cmd, cwd=HERE)
    except OSError as e:
        print(f"ERROR: could not start the capture: {e}")
        return 2

    # Give the logger a moment to open the port and fail loudly if it cannot.
    time.sleep(1.5)
    if child.poll() is not None:
        print(f"ERROR: the capture exited immediately (code {child.returncode}). "
              f"Check --port and that no Serial Monitor is holding it open.")
        return 2

    rc = 0
    try:
        rc = live_observer.run(out, args)
    except KeyboardInterrupt:
        # live_observer.run() normally absorbs this itself; this is the
        # belt-and-braces path.
        print("\nStopped by user (Ctrl+C).")
    finally:
        rc = _stop_child(child) or rc

    print(f"\nCapture saved: {out}")
    print(f"Authoritative report:  python3 observer.py {out}"
          + (f" --keyring {args.keyring}" if args.keyring else ""))
    print(f"Post-flight map     :  python3 make_map.py {out}")
    return rc


def _stop_child(child):
    """Wait for the logger to shut itself down cleanly; force it only if it
       will not. The child already received the console's Ctrl+C."""
    if child.poll() is not None:
        return 0
    print("Waiting for the capture to close the serial port cleanly...")
    deadline = time.time() + SHUTDOWN_GRACE_S
    while time.time() < deadline:
        if child.poll() is not None:
            return 0
        time.sleep(0.2)

    print("Capture did not exit in time - terminating it.")
    try:
        child.terminate()
        child.wait(timeout=5)
    except Exception:
        try:
            child.kill()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
