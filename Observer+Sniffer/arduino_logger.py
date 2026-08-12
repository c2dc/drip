"""
arduino_logger.py - capture an ESP32 serial stream to a file without resetting
the board.

Used for BOTH:
  * Format L - the transmitter's own debug log (~30 lines/s at 115200)
  * Format A - the DRIP_Sniffer's air capture (~720 lines/s at 921600)

-----------------------------------------------------------------------------
 THROUGHPUT (rewritten - this is why)
-----------------------------------------------------------------------------
The original read loop was written for Format L at 115200 (~11.5 kB/s, ~30
lines/s) and did three things per line:

    raw = ser.readline()     # pyserial scans ONE BYTE AT A TIME for '\n'
    print(line)              # a Windows console render per line
    f.flush()                # a disk sync per line

At 115200 that is fine. Pointed at the sniffer at 921600 with 3 drones
(~39 kB/s, ~720 lines/s) it is not: the reader stalls, the OS serial buffer
(4 kB by default on Windows = about 0.1 s of data at this rate) overflows, and
the driver SILENTLY DISCARDS BYTES.

MEASURED on a real 19.4 MB / 18,462-frame capture taken with the old loop:
    46 malformed lines out of 339,059  (0.0136%)
    22 frames spliced together mid-stream
    e.g.  '0000C0 E6 3C1 E0 ...'   <- three hex chars
          '0070 08 72 ...'         <- 4-char offset, should be 6
The firmware prints %02X and %06X and can emit neither. Those are not corrupted
bytes, they are MISSING bytes. The ESP32 side was innocent: dropped=0 on all 54
of the sniffer's own stats lines.

Cost: 18 damaged frames out of 18,462 - 0.1% data loss, but they produced ALL
66 findings in that run, reported as "Wrong protocol version" and "Manifest
chain broken". A USB glitch reading as a DRIP conformance failure is far worse
than the lost bytes themselves.

Fixed by:
  1. reading in CHUNKS (ser.in_waiting) and splitting lines in memory
  2. NOT echoing every line to the console (--echo restores it)
  3. flushing about once a second instead of once a line
  4. asking Windows for a 1 MB RX buffer instead of 4 kB
"""

import serial
import time
import sys
import argparse

# -- Settings ----------------------------------------------
PORT        = "COM4"
BAUD_RATE   = 115200
OUTPUT_FILE = "data_log.txt"
# ----------------------------------------------------------

STATUS_EVERY_S = 1.0


def main():
    ap = argparse.ArgumentParser(
        description="Capture an ESP32 serial log (Format L or DRIP_Sniffer "
                    "Format A) without resetting the board")
    ap.add_argument("--port", default=PORT)
    ap.add_argument("--baud", type=int, default=BAUD_RATE,
                    help="115200 for the transmitter's debug log; 921600 for "
                         "the DRIP_Sniffer (460800 if the USB chip is flaky)")
    ap.add_argument("-o", "--output", default=OUTPUT_FILE)
    ap.add_argument("--select", type=int, metavar="N",
                    help="send flight index N over serial right after connecting "
                         "(equivalent to typing N in the Serial Monitor)")
    ap.add_argument("--cmd", default=None,
                    help="send an arbitrary playback command instead of --select "
                         "(e.g. 'reset', 'stop', 'list')")
    ap.add_argument("--echo", action="store_true",
                    help="print every line to the console (the old behaviour). "
                         "At sniffer rates this can stall the reader and cause "
                         "the OS to DROP SERIAL BYTES - use only at 115200.")
    args = ap.parse_args()

    print(f"Connecting to {args.port} at {args.baud} baud...")

    # ---------------------------------------------------------------------
    # BUG FIX: opening a serial port normally toggles the DTR/RTS control
    # lines, which on virtually every ESP32 board are wired straight to the
    # EN (reset) and GPIO0 pins -> the board reboots every time this script
    # starts. That reboot is why the log always begins at flight 0: whatever
    # flight was selected over the Serial Monitor is lost on reconnect.
    #
    # Fix: build the Serial object WITHOUT opening it, set dtr/rts to False
    # first, THEN open(). Setting dsrdtr=False/rtscts=False in the
    # constructor does NOT work (confirmed against pyserial's own open()
    # behaviour) - the control lines must be deasserted before open().
    # ---------------------------------------------------------------------
    try:
        ser = serial.Serial()
        ser.port = args.port
        ser.baudrate = args.baud
        ser.timeout = 1
        ser.dtr = False   # do NOT toggle EN
        ser.rts = False   # do NOT toggle GPIO0
        ser.open()
    except serial.SerialException as e:
        print(f"[ERROR] Could not open port: {e}")
        sys.exit(1)

    # Windows only: the default driver RX buffer is 4 kB, about 0.1 s of data at
    # sniffer rates. Anything that stalls this loop past that loses bytes with
    # no error raised anywhere. Harmless no-op on other platforms.
    try:
        ser.set_buffer_size(rx_size=1 << 20, tx_size=4096)
        print("RX buffer set to 1 MB.")
    except Exception:
        pass   # not Windows, or unsupported - the chunked read still helps

    print("Connected without resetting the board - the currently running "
          "flight keeps playing.")
    if args.echo and args.baud > 115200:
        print("[WARN] --echo at this baud may stall the reader and cause the OS "
              "to drop bytes. The capture may be silently corrupted.")

    if args.select is not None or args.cmd:
        cmd = args.cmd if args.cmd is not None else str(args.select)
        time.sleep(0.3)                    # let any in-flight serial settle
        ser.write((cmd + "\n").encode("utf-8"))
        print(f"Sent command: '{cmd}'")

    print(f"Capturing to {args.output} - press Ctrl+C to stop.\n")

    buf = bytearray()
    n_lines = n_bytes = 0
    t_start = t_status = time.time()
    last_bytes = 0

    with open(args.output, "w", encoding="utf-8", errors="replace",
              newline="\n") as f:
        try:
            while True:
                try:
                    # Read everything already buffered in ONE call. Falling back
                    # to a blocking 1-byte read keeps the loop responsive when
                    # the stream is idle (and honours ser.timeout).
                    waiting = ser.in_waiting
                    chunk = ser.read(waiting) if waiting else ser.read(1)
                except serial.SerialException as e:
                    print(f"\n[ERROR] Serial connection lost: {e}")
                    break

                if chunk:
                    buf += chunk
                    n_bytes += len(chunk)
                    # Split whole lines out of the buffer. A partial trailing
                    # line stays put until the rest of it arrives - which is
                    # what stops a frame being cut in half by a read boundary.
                    while True:
                        nl = buf.find(b"\n")
                        if nl < 0:
                            break
                        raw = bytes(buf[:nl])
                        del buf[:nl + 1]
                        line = raw.decode("utf-8", errors="replace").rstrip("\r")
                        if line:
                            f.write(line + "\n")
                            n_lines += 1
                            if args.echo:
                                print(line)

                now = time.time()
                if now - t_status >= STATUS_EVERY_S:
                    f.flush()
                    rate = (n_bytes - last_bytes) / (now - t_status)
                    last_bytes, t_status = n_bytes, now
                    if not args.echo:
                        # '\r' keeps this to ONE self-updating line, so the
                        # console can never become the bottleneck.
                        pct = 100.0 * rate / (args.baud / 10.0)
                        sys.stdout.write(
                            f"\r  {n_bytes/1e6:7.2f} MB | {n_lines:9,d} lines | "
                            f"{rate/1000:6.1f} kB/s ({pct:4.1f}% of link) | "
                            f"{now-t_start:6.0f}s ")
                        sys.stdout.flush()

        except KeyboardInterrupt:
            print("\nStopped by user (Ctrl+C).")

        # Whatever is left is a partial line: the capture was stopped mid-frame.
        # Written out as-is; the parser rejects it on the length check.
        if buf:
            f.write(buf.decode("utf-8", errors="replace"))

    print(f"\nWrote {n_lines:,} lines ({n_bytes/1e6:.2f} MB) to {args.output}")
    if ser.is_open:
        ser.close()
        print("Serial port closed cleanly.")


if __name__ == "__main__":
    main()
