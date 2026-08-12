#!/usr/bin/env python3
"""Replay a finished capture into a growing file to exercise the live path.

TEST HARNESS - not part of the deliverable.

The simulated clock is driven by the capture's OWN timeline (the sniffer's
t_us), not by wall time. Without that, replaying 26 minutes of flight in 23
seconds of wall time would give the 4 s grace period the effect of a ~4.5
minute grace period, and the test would prove nothing about real operation.
"""
import sys, os, time, tempfile

import live_feed, live_state, observer


class SimClock:
    def __init__(self):
        self.t = time.time()
    def __call__(self):
        return self.t


def main():
    src = sys.argv[1]
    keyring = sys.argv[2] if len(sys.argv) > 2 else None

    keys = observer.default_keyring("hierarchy.json")
    if keyring:
        for line in open(keyring, encoding="utf-8"):
            t = line.split("#", 1)[0].split()
            if len(t) == 2:
                keys.add(bytes.fromhex(t[0]), bytes.fromhex(t[1]))
    print(f"keyring: {len(keys)} DET-bound key(s)")

    clock = SimClock()
    tmp = tempfile.mktemp(suffix=".txt")
    open(tmp, "w").close()
    feed = live_feed.LiveFeed(tmp, start_at_end=False)
    st = live_state.LiveState(keys=keys, grace_s=4.0, warmup_s=4.0,
                              trail=0, clock=clock)
    t0 = clock.t
    us0 = [None]
    last_tick = [t0]

    def drain():
        for kind, a, b in feed.poll():
            if kind == "frame":
                tus = a.get("t_us")
                if tus is not None:
                    if us0[0] is None:
                        us0[0] = tus
                    clock.t = t0 + (tus - us0[0]) / 1e6
                st.ingest_frame(a, b, now=clock.t)
            elif kind == "damaged":
                st.ingest_damaged(a, b, now=clock.t)
            elif kind == "stats":
                st.ingest_stats(a)
            if clock.t - last_tick[0] >= 1.0:
                st.tick(now=clock.t)
                last_tick[0] = clock.t

    wall = time.perf_counter()
    with open(src, encoding="utf-8", errors="replace") as fh, \
         open(tmp, "a", encoding="utf-8") as out:
        buf = []
        for line in fh:
            buf.append(line)
            if len(buf) >= 4000:
                out.write("".join(buf)); out.flush(); buf = []
                drain()
        if buf:
            out.write("".join(buf)); out.flush(); drain()
    for kind, a, b in feed.flush_idle(idle_s=0):
        if kind == "frame":
            st.ingest_frame(a, b, now=clock.t)
        elif kind == "damaged":
            st.ingest_damaged(a, b, now=clock.t)
    # Advance just past the grace window - NOT past drop_s, or every drone
    # would age out of the snapshot and the comparison would show nothing.
    clock.t += st.grace_s + 1
    st.tick(now=clock.t)
    os.unlink(tmp)

    snap = st.snapshot()
    # The snapshot deliberately omits dropped drones ("currently detecting").
    # For the batch comparison we want everything ever seen.
    print("\nALL drones ever seen (batch-comparable):")
    for k, d in st.drones.items():
        print(f"  {k}  frames={d.frames} pts={len(d.points)}")
        for eid in d._finding_order:
            print(f"      {eid} x{d.findings[eid]['count']}")
        for lf in st._link_findings_for(k):
            print(f"      {lf['id']} x{lf['count']}   [current chain verdict]")
    print(f"  (unattributed)")
    for eid in st.unattributed._finding_order:
        print(f"      {eid} x{st.unattributed.findings[eid]['count']}")
    for lf in st._link_findings_for(None):
        print(f"      {lf['id']} x{lf['count']}   [current chain verdict]")
    print(f"\nreplayed {clock.t - t0:.0f}s of capture in {time.perf_counter()-wall:.1f}s wall")
    print(f"frames_ok={st.frames_ok} damaged={st.frames_damaged} "
          f"sniffer={st.sniffer_stats}")
    print(f"\ndrones: {len(snap['drones'])}")
    for d in snap["drones"]:
        print(f"  {d['label']}  macs={d['macs']} frames={d['frames']} "
              f"pts={len(d['points'])} key={'YES' if d['key_known'] else 'NO'}")
        for f in d["findings"]:
            print(f"      {f['id']} x{f['count']}")
    if snap["unattributed"]:
        print(f"  {snap['unattributed']['label']}")
        for f in snap["unattributed"]["findings"]:
            print(f"      {f['id']} x{f['count']}")


if __name__ == "__main__":
    main()
