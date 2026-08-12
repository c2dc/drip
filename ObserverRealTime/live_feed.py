#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - live_feed.py
#  Incremental (streaming) reader for Format A - the DRIP_Sniffer air capture.
#
#  WHY THIS EXISTS
#  ---------------
#  odid.parse_format_a() takes the WHOLE capture as one string and returns every
#  frame at once. That is right for a finished file and useless for a file that
#  is still being written: it would re-parse the entire capture on every call.
#
#  This module tails a growing file and yields frames as they complete. It does
#  NOT re-implement the parsing: it imports odid's own compiled regexes so the
#  live path and the batch path can never disagree about what a valid row is.
#
#  FRAMING IS IDENTICAL TO odid.parse_format_a() -- ON PURPOSE
#  -----------------------------------------------------------
#  A frame is closed when the NEXT frame's offset-0 row appears. That is exactly
#  odid's rule, and it is used here deliberately.
#
#  An earlier version of this file closed a frame as soon as it had accumulated
#  the byte count declared on the '#F' line, to save one frame of latency. It
#  was REMOVED after being tested against the reference capture: on damaged
#  frames the two schemes resynchronise differently, and live_feed produced
#  7,353 intact / 1 damaged where odid produced 7,352 intact / 3 damaged, with
#  the frame stream diverging from index 209 onward. The saving was not worth
#  it either - at the measured 4.7 frames/s one frame of latency is ~210 ms,
#  invisible behind a 1 Hz page refresh. Exact agreement with the batch parser
#  is worth far more than 210 ms.
#
#  The one thing the offset-0 rule cannot do is close the LAST frame, since no
#  frame follows it. odid handles that at EOF; a live stream has no EOF, so
#  flush_idle() closes a frame that has been open with no new rows for a while.
#
#  THE LENGTH CHECK
#  ----------------
#  Same contract as odid.parse_format_a(strict_len=True): if the byte count does
#  not match the sniffer's declared len, the frame was damaged in the CAPTURE
#  PIPELINE (serial byte loss), not on the air. It is reported as W-CAP-01 and
#  never decoded. Confirmed present in real data: the reference capture
#  CaptureWithDNS4.txt contains 3 such frames out of 7,355.
#
#  SNIFFER SELF-REPORT
#  -------------------
#  The firmware also emits, every 10 s:
#      # stats captured=%u dropped=%u oversize=%u
#  `dropped` counts frames the ESP32's 16-slot ring lost because serial could
#  not keep up - i.e. frames that never left the board. That is a DIFFERENT
#  failure from W-CAP-01 (host-side loss) and it is parsed here so the live view
#  can show it. A drone can vanish from the map because the sniffer dropped it
#  rather than because it stopped transmitting, and those two must not be
#  confused.
# =============================================================================

import os
import re
import time

import odid

# ---------------------------------------------------------------------------
#  Reuse odid's OWN row/meta regexes.
#
#  Deliberate: if this module defined its own copies they could drift from the
#  batch parser, and a live/batch disagreement about row syntax would be almost
#  impossible to spot. Importing the private names means that if odid.py ever
#  renames them we fail LOUDLY at import, instead of silently diverging.
# ---------------------------------------------------------------------------
try:
    from odid import _FMT_A_ROW, _FMT_A_META
except ImportError as e:                                  # pragma: no cover
    raise ImportError(
        "live_feed.py needs odid._FMT_A_ROW and odid._FMT_A_META (the Format A "
        "row/meta regexes). odid.py appears to have changed. Fix the import "
        "rather than copying the patterns here - two copies WILL drift."
    ) from e

# '# stats captured=N dropped=N oversize=N'  (DRIP_Sniffer.ino loop())
_FMT_A_STATS = re.compile(
    r'^#\s*stats\s+captured=(\d+)\s+dropped=(\d+)\s+oversize=(\d+)')


class LiveFeed:
    """Tail a growing Format A capture file and emit completed frames.

    Events returned by poll(), in arrival order:
        ("frame",   meta, frame_bytes)   intact frame
        ("damaged", meta, got_len)       byte count != declared len  -> W-CAP-01
        ("stats",   stats_dict, None)    the sniffer's own counters

    `meta` carries rssi / ch / len from the '#F' line and t_us from the row
    timestamp, exactly as odid.parse_format_a() would populate it.

    NOTE ON TIME: meta["t_us"] is microseconds since the SNIFFER BOARD booted
    (DRIP_Sniffer.ino says so in its own banner), NOT wall clock, and its source
    counter wraps every ~71.6 min. It is therefore NEVER used for staleness.
    Staleness uses the host clock at the moment the frame was read - see
    live_state.py.
    """

    def __init__(self, path, start_at_end=True):
        """start_at_end=True  -> resume at EOF (Option C: attach to a capture
                                 already in progress without replaying it).
           start_at_end=False -> read the file from the beginning.
        """
        self.path = path
        self.start_at_end = start_at_end

        self._fh = None
        self._pos = 0
        self._inode = None
        self._buf = ""            # partial trailing LINE not yet terminated

        # frame under construction
        self._cur = bytearray()
        self._meta = {}
        self._pending_meta = {}   # from a '#F' line, applied at the next offset 0
        self._have = False
        self._last_row_at = None

        # counters for the UI
        self.frames_ok = 0
        self.frames_damaged = 0
        self.bytes_read = 0
        self.sniffer_stats = {}   # last '# stats' line seen
        self.opened = False

    # -- file plumbing -----------------------------------------------------
    def _open(self):
        """Open (or re-open) the capture. Returns True once open.

        Tolerates the file not existing yet: run_live.py starts the logger and
        the observer together, and there is a short window before the logger has
        created its output file.
        """
        try:
            st = os.stat(self.path)
        except OSError:
            return False

        if self._fh is not None and self._inode == (st.st_dev, st.st_ino):
            return True

        # First open, or the file was replaced (a new capture started).
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._reset_frame()
            self._pending_meta = {}      # a new file: nothing is pending

        self._fh = open(self.path, "r", encoding="utf-8", errors="replace",
                        newline="")
        self._inode = (st.st_dev, st.st_ino)
        self._pos = st.st_size if self.start_at_end else 0
        self._fh.seek(self._pos)
        self._buf = ""
        self.opened = True
        return True

    def _reset_frame(self):
        """Clear the frame under construction.

        DELIBERATELY does NOT clear _pending_meta. A frame is closed by the
        arrival of the NEXT frame's offset-0 row, and that frame's '#F' line has
        already been read by then - so _pending_meta holds metadata belonging to
        the frame about to start, not the one being closed. Wiping it here left
        every frame after the first without its declared `len`, which silently
        disabled the damage check entirely (0 damaged instead of 3 on the
        reference capture).
        """
        self._cur = bytearray()
        self._meta = {}
        self._have = False
        self._last_row_at = None

    # -- the main entry point ----------------------------------------------
    def poll(self):
        """Read whatever has been appended and return a list of events."""
        events = []
        if not self._open():
            return events

        try:
            st = os.stat(self.path)
        except OSError:
            return events

        # File shrank -> it was truncated or rotated. arduino_logger.py opens
        # its output with mode "w", so a NEW capture session truncates the file.
        # Restart from the top rather than reading garbage from a stale offset.
        if st.st_size < self._pos:
            self._pos = 0
            self._fh.seek(0)
            self._buf = ""
            self._reset_frame()
            self._pending_meta = {}      # truncated/rotated: nothing is pending

        chunk = self._fh.read()
        if not chunk:
            return events
        self._pos = self._fh.tell()
        self.bytes_read += len(chunk)

        data = self._buf + chunk
        # Keep the last partial line for the next poll. Without this, a read
        # boundary would cut a hexdump row in half and the row would be dropped
        # by the regex - silent data loss that looks like a sparse capture.
        nl = data.rfind("\n")
        if nl < 0:
            self._buf = data
            return events
        self._buf = data[nl + 1:]
        complete = data[:nl]

        for line in complete.split("\n"):
            self._feed_line(line, events)
        return events

    # -- line handling (mirrors odid.parse_format_a) ------------------------
    def _feed_line(self, line, events):
        s = line.strip()
        if not s:
            return

        if s.startswith("#"):
            m = _FMT_A_META.match(s)
            if m:
                self._pending_meta = {"rssi": int(m.group(1)),
                                      "ch":   int(m.group(2)),
                                      "len":  int(m.group(3))}
                return
            m = _FMT_A_STATS.match(s)
            if m:
                self.sniffer_stats = {"captured": int(m.group(1)),
                                      "dropped":  int(m.group(2)),
                                      "oversize": int(m.group(3))}
                events.append(("stats", dict(self.sniffer_stats), None))
            return

        m = _FMT_A_ROW.match(line)
        if not m:
            return

        off = int(m.group(5), 16)
        row = bytes.fromhex(re.sub(r"\s+", "", m.group(6)))

        if off == 0:
            # THE close rule, identical to odid.parse_format_a(): a new frame
            # starting is what ends the previous one.
            if self._have:
                self._close(events)
            self._cur = bytearray()
            self._meta = dict(self._pending_meta)
            self._pending_meta = {}
            self._have = True
            if m.group(1) is not None:
                frac = (m.group(4) + "000000")[:6]      # normalise to microseconds
                self._meta["t_us"] = ((int(m.group(1)) * 3600 +
                                       int(m.group(2)) * 60 +
                                       int(m.group(3))) * 1_000_000 + int(frac))

        if not self._have:
            return                      # rows before the first offset-0 row

        self._cur += row
        self._last_row_at = time.time()

    def flush_idle(self, idle_s=2.0):
        """Close a frame that has been open with no new rows for `idle_s`.

        The offset-0 rule needs a FOLLOWING frame to close the current one.
        odid.parse_format_a() gets that for free at EOF; a live stream never
        reaches EOF, so without this the most recent frame would sit unclosed
        whenever transmission pauses (or stops for good). Returns events.
        """
        events = []
        if self._have and self._last_row_at is not None:
            if time.time() - self._last_row_at >= idle_s:
                self._close(events)
        return events

    def _close(self, events):
        """Accept a completed frame, or bin it if the byte count is wrong."""
        declared = self._meta.get("len")
        got = len(self._cur)
        if declared is not None and declared != got:
            self.frames_damaged += 1
            events.append(("damaged", dict(self._meta), got))
        else:
            self.frames_ok += 1
            events.append(("frame", dict(self._meta), bytes(self._cur)))
        self._reset_frame()

    def close(self):
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None


def wait_for_file(path, timeout=30.0, interval=0.2):
    """Block until `path` exists. Used by run_live.py, which starts the logger
       and the observer together - the file appears a moment later."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(interval)
    return os.path.exists(path)
