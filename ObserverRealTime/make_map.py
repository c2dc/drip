#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - make_map.py
#  Generates a single self-contained HTML file that plots each drone's path
#  (grouped by DET) on a Leaflet/OpenStreetMap map, from the same capture
#  files the observer reads (Format L serial log, Format W Wireshark export,
#  or Format B hand-authored vectors).
#
#  Usage:
#     python3 make_map.py <capture.txt> [-o map.html]
#     then open map.html in any browser (double-click it). No server needed.
#     Requires internet access ONLY to load the Leaflet library and the map
#     tile images (both fetched from public CDNs by the browser at view time).
#
#  What's plotted per drone:
#     - a coloured polyline through every decoded Location point, in
#       transmission order
#     - a green marker at the first point, a red marker at the last
#     - a popup on each marker showing the approximate time (see NOTE below)
#
#  NOTE ON TIME: ASTM System (Table 11) carries no timestamp in this firmware;
#  the time shown is the VNB of the nearest DRIP auth message (Wrapper/Link/
#  Manifest) in the same pack - see flight_tracks.py for the full rationale.
#  It may be absent ("unknown") for packs with no auth message.
# =============================================================================

import sys
import json
import argparse
from datetime import datetime, timezone

import flight_tracks

# Distinct, colour-blind-friendlier palette; cycles if there are more drones.
PALETTE = [
    "#e6194b", "#3cb44b", "#4363d8", "#f58231", "#911eb4",
    "#46f0f0", "#f032e6", "#bcf60c", "#fabebe", "#008080",
    "#e6beff", "#9a6324", "#800000", "#aaffc3", "#808000",
    "#ffd8b1", "#000075", "#808080", "#ffe119", "#000000",
]

DRIP_EPOCH_UNIX_S = 1546300800   # RFC 9374/9575: 2019-01-01 00:00:00 UTC


def vnb_to_iso(vnb_drip_epoch_s):
    if vnb_drip_epoch_s is None:
        return None
    try:
        return datetime.fromtimestamp(
            vnb_drip_epoch_s + DRIP_EPOCH_UNIX_S, tz=timezone.utc
        ).isoformat()
    except Exception:
        return None


def build_html(tracks, title="DRIP flight tracks"):
    drones = []
    for i, (key, t) in enumerate(tracks.items()):
        pts = [p for p in t["points"] if p["lat"] is not None and p["lon"] is not None]
        if not pts:
            continue
        color = PALETTE[i % len(PALETTE)]
        drones.append({
            "label": t["label"],
            "color": color,
            "points": [
                {
                    "lat": p["lat"], "lon": p["lon"], "alt_m": p["alt_m"],
                    "speed_mps": p["speed_mps"], "heading_deg": p["heading_deg"],
                    "time": vnb_to_iso(p["vnb"]),
                    "where": p["where"],
                }
                for p in pts
            ],
        })

    if not drones:
        print("No Location points with valid coordinates found - nothing to map.")
        sys.exit(1)

    all_lats = [p["lat"] for d in drones for p in d["points"]]
    all_lons = [p["lon"] for d in drones for p in d["points"]]
    center = [sum(all_lats) / len(all_lats), sum(all_lons) / len(all_lons)]

    data_json = json.dumps(drones)

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
  html, body {{ height: 100%; margin: 0; font-family: sans-serif; }}
  #map {{ height: 100%; }}
  #legend {{
    position: absolute; top: 10px; right: 10px; z-index: 1000;
    background: white; padding: 8px 12px; border-radius: 6px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.4); max-height: 80vh; overflow-y: auto;
    font-size: 13px;
  }}
  #legend h4 {{ margin: 0 0 6px 0; }}
  .legend-item {{ display: flex; align-items: center; margin: 3px 0; cursor: pointer; }}
  .legend-swatch {{ width: 14px; height: 14px; margin-right: 6px; border-radius: 3px; flex-shrink: 0; }}
  .legend-item.disabled {{ opacity: 0.35; }}
</style>
</head>
<body>
<div id="map"></div>
<div id="legend"><h4>Drones ({len(drones)})</h4><div id="legend-list"></div></div>
<script>
const drones = {data_json};

const map = L.map('map').setView([{center[0]}, {center[1]}], 15);
L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
    maxZoom: 19,
    attribution: '&copy; OpenStreetMap contributors'
}}).addTo(map);

const bounds = [];
const legendList = document.getElementById('legend-list');
const layers = [];

drones.forEach((d, idx) => {{
    const latlngs = d.points.map(p => [p.lat, p.lon]);
    latlngs.forEach(ll => bounds.push(ll));

    const line = L.polyline(latlngs, {{color: d.color, weight: 3, opacity: 0.85}}).addTo(map);

    const first = d.points[0], last = d.points[d.points.length - 1];
    const startMarker = L.circleMarker([first.lat, first.lon], {{
        radius: 7, color: '#2ecc40', fillColor: '#2ecc40', fillOpacity: 0.9
    }}).addTo(map).bindPopup(
        '<b>' + d.label + '</b><br>START<br>' +
        'lat=' + first.lat.toFixed(7) + ' lon=' + first.lon.toFixed(7) +
        (first.alt_m != null ? '<br>alt=' + first.alt_m.toFixed(1) + ' m' : '') +
        (first.time ? '<br>time=' + first.time : '<br>time=unknown')
    );
    const endMarker = L.circleMarker([last.lat, last.lon], {{
        radius: 7, color: '#ff4136', fillColor: '#ff4136', fillOpacity: 0.9
    }}).addTo(map).bindPopup(
        '<b>' + d.label + '</b><br>LAST<br>' +
        'lat=' + last.lat.toFixed(7) + ' lon=' + last.lon.toFixed(7) +
        (last.alt_m != null ? '<br>alt=' + last.alt_m.toFixed(1) + ' m' : '') +
        (last.speed_mps != null ? '<br>speed=' + last.speed_mps.toFixed(1) + ' m/s' : '') +
        (last.time ? '<br>time=' + last.time : '<br>time=unknown') +
        '<br>points=' + d.points.length
    );

    const group = L.layerGroup([line, startMarker, endMarker]);
    layers.push(group);

    const item = document.createElement('div');
    item.className = 'legend-item';
    item.innerHTML = '<span class="legend-swatch" style="background:' + d.color + '"></span>' +
                      d.label + ' (' + d.points.length + ' pts)';
    let visible = true;
    item.onclick = () => {{
        visible = !visible;
        if (visible) {{ group.addTo(map); item.classList.remove('disabled'); }}
        else {{ map.removeLayer(group); item.classList.add('disabled'); }}
    }};
    legendList.appendChild(item);
}});

if (bounds.length) map.fitBounds(bounds, {{padding: [30, 30]}});
</script>
</body>
</html>
"""
    return html


def main():
    ap = argparse.ArgumentParser(description="Generate a Leaflet map from a DRIP capture")
    ap.add_argument("file", help="capture file (Format L, W, or B)")
    ap.add_argument("-o", "--output", default="map.html")
    ap.add_argument("--title", default="DRIP flight tracks")
    args = ap.parse_args()

    with open(args.file, encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    tracks = flight_tracks.extract_tracks(text)
    print(f"Found {len(tracks)} drone(s):")
    for line in flight_tracks.track_summary(tracks):
        print(f"  {line}")

    html = build_html(tracks, title=args.title)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"\nwrote {args.output} - open it in a browser (double-click) to view the map.")


if __name__ == "__main__":
    main()
