# PROJECT_MAP.md — where everything lives

DRIP Broadcast RID PoC — ESP32 transmitter (bench emulator) + Python observer.

---

## 0. How to use this map

**This is a POINTER document, not a source of values.**

Every project constant already has exactly one file that owns it. If this map
restated those values, it would become a second (or, for the hierarchy, a
*fourth*) copy that drifts silently. So each entry below gives:

| column | meaning |
|---|---|
| **What** | the thing you are looking for |
| **Edit here** | the ONE file that owns it — change it there and nowhere else |
| **Also appears in** | read-only mirrors that must be kept in step (and how) |

Values are quoted here **only** where they are already published in two or more
places anyway (the DETs, the RAA/HDA numbers, the channel). Private seeds and
public keys are **never** copied into this file — go to the owning table.

Section 11 lists every known duplication and the tool that catches drift.

---

## 1. Identity & keys

### 1.1 The UA identity slots (the drones' DETs and signing keys)

| What | Edit here | Also appears in |
|---|---|---|
| Per-slot Ed25519 seed + public key (HI) + expected DET | **`det_generator.cpp` → `IDENTITY_TABLE[]`** | `bench.keyring` (DET + pubkey only), `observer.py` → `BUILTIN_KEYS`, boot printout |
| How many slots exist | `det_generator.h` → `DET_IDENTITY_SLOTS` (= 3) | `beacon_tx_raw.cpp` `SLOT_MAC[]` is sized by it |
| How many drones the fleet will run | `drone_fleet.h` → `FLEET_MAX` (= 3, agreed scope cap) | — |

The three test DETs (published in four places already, so safe to repeat here):

| slot | DET | MAC | note |
|---|---|---|---|
| 0 | `2001:0030:FA07:D005:31E0:1AED:4E7E:CF5C` | `02:44:52:49:50:00` | **the original single-drone PoC identity** — `fleet 1` puts exactly this on the air |
| 1 | `2001:0030:FA07:D005:F3B6:6F58:E30E:AD97` | `02:44:52:49:50:01` | |
| 2 | `2001:0030:FA07:D005:5584:4FA7:8F0D:14D7` | `02:44:52:49:50:02` | |

All three share **RAA = 1000 / HDA = 2000 / Suite = 5** (RFC 9374 §3.2 Table 2,
EdDSA/cSHAKE128). Only the key-derived ORCHID hash (low 64 bits) differs — that
is the whole point of RFC 9374 §3.5.2.

> ⚠️ **TEST VALUES.** Every private seed is published in source. No IANA
> registration stands behind any of them (RFC 9374 §3.3).

**How the values are reproduced** (they are derived, not invented): the recipe
lives in the comment block at the top of `det_generator.cpp` and is repeated in
`bench.keyring`. Slot 0 is a legacy seed recorded verbatim; slots 1..N are
`shake128(b"DRIP PoC UA slot <i>", 32)`.

### 1.2 Adding a 4th drone — the three-file checklist

Miss any one of these and you get a mismatch that looks like a firmware fault:

1. `det_generator.cpp` → append a row to `IDENTITY_TABLE[]`
2. `det_generator.h` → raise `DET_IDENTITY_SLOTS`
3. `drone_fleet.h` → raise `FLEET_MAX` *(read the airtime / Ed25519 budget note
   there first)*
4. `beacon_tx_raw.cpp` → add a MAC to `SLOT_MAC[]`
5. then add the DET + pubkey to `bench.keyring` **or** `observer.py`
   `BUILTIN_KEYS` so the observer can verify it

### 1.3 The keys the OBSERVER already knows

The observer maps **DET → public key** (never one global key: RFC 9374 §3.5.2
binds a DET to exactly one key, so a fleet needs a keyring).

| Source | File / flag | Precedence |
|---|---|---|
| Compiled-in bench identities (slots 0–2) | `observer.py` → `BUILTIN_KEYS` | lowest |
| Keyring file (a 4th drone, another hierarchy, someone else's capture) | `bench.keyring`, via `--keyring FILE` | **overrides built-ins for the same DET** |
| Wildcard, for one unknown drone | `--pubkey HEX` | used only for a DET with no entry |
| Drop the built-ins entirely | `--no-builtin-keys` | file/`--pubkey` become the whole keyring |
| Show the resulting keyring and exit | `--list-keys` | — |

`bench.keyring` format: `<DET_HEX 32 chars>  <PUBKEY_HEX 64 chars>`, `#`
comments, malformed line = hard reject with file:line. **Public keys only** —
the observer never wants a seed; it only verifies.

For the standard 1–3 drone bench fleet you do **not** need `bench.keyring`; the
built-ins already cover it.

---

## 2. The DRIP hierarchy (Apex / RAA / HDA)

> **Read `drip_hierarchy.h`'s header comment before touching any of this.** It
> is the single source of truth and it explains *why* the numbers must nest.

| What | Edit here | Mirrored in |
|---|---|---|
| RAA/HDA numbers of every entity; test parent **private seeds** | **`drip_hierarchy.h`** (firmware) | — |
| The same numbers + parent **public keys + DETs** | **`hierarchy.json`** (observer, PUBLIC ONLY) | — |
| Trust-anchor fallback if `hierarchy.json` is missing | `observer.py` → `APEX_HI` / `APEX_DET` | superseded at startup by `hierarchy.json` |
| Anchor file path | `observer.py --anchor FILE` (default `hierarchy.json`) | — |
| Aliases `HHIT_TEST_RAA` / `HHIT_TEST_HDA` | `det_generator.h` — **aliases only**, do not edit | resolve to `DRIP_UA_RAA/HDA` |

Current test hierarchy:

| entity | RAA / HDA | DET | zone |
|---|---|---|---|
| Apex | 0 / 0 | `2001:30:0:5:881e:c792:8833:e0fb` | owns `2001:30::/28` |
| RAA | 1000 / 0 | `2001:30:fa00:5:32fd:cbfe:b2f4:3c02` | `2001:30:fa00::/44` |
| HDA | 1000 / 2000 | `2001:30:fa07:d005:8462:788f:47c8:b813` | `2001:30:fa07:d000::/56` |
| UA 0–2 | 1000 / 2000 | see §1.1 | inside the HDA /56 ✔ |

**THE RULE (RFC 9886 §6):** a child's DET must fall inside its parent's zone,
and that is decided *entirely* by the RAA/HDA numbers — the keys only affect the
trailing 64-bit hash. So the RAA and HDA must carry the **UAs' own numbers**.
The signature walk (RFC 9575 §6.4.2) never checks zones, so a non-nesting
hierarchy passes every self-test and is still undelegable. That happened here
once; the compile-time `#error` guards in `drip_hierarchy.h` exist because of it.

**After changing EITHER `drip_hierarchy.h` OR `hierarchy.json`:**

```bash
python3 check_hierarchy.py --header drip_hierarchy.h --json hierarchy.json
```

It re-derives every DET from scratch, proves the zones nest, and proves the two
files still agree. It is the only thing standing between an edit and a silent
mismatch that surfaces as `E-LINK-*` in the observer.

---

## 3. Radio / RF settings

### 3.1 The channel — TWO constants that must agree

| What | Edit here | Value |
|---|---|---|
| Transmitter channel | `beacon_tx_raw.h` → `WIFI_CHANNEL_DRIP` | 6 |
| Sniffer channel | `DRIP_Sniffer.ino` → `SNIFFER_CHANNEL` | 6 |

> ⚠️ **These are independent `#define`s in two separate sketches.** Nothing links
> them. Change one and the sniffer goes deaf with no error message. The sniffer
> does **not** channel-hop. Basis: ASTM F3411-22a §5.4.9.1 (BWFB0010) permits a
> single "social" channel.

### 3.2 Transmitter frame parameters — all in `beacon_tx_raw.h` / `.cpp`

| What | Where | Value |
|---|---|---|
| Per-slot source MAC (= per-drone BSSID) | `beacon_tx_raw.cpp` → `SLOT_MAC[]` | `02:44:52:49:50:0<slot>` (locally administered) |
| Vendor IE OUI / type | `beacon_tx_raw.cpp`, `odid.py` (`ODID_OUI`/`ODID_VTYPE`), `DRIP_Sniffer.ino` | `FA-0B-BC` / `0x0D` (ASTM Table 20) |
| SSID prefix | `beacon_tx_raw.cpp` (`ssid_prefix`) | `DRIP-RID-<slot>` — not an ASTM field; exists only so the frame is well-formed |
| Beacon Interval | `beacon_tx_raw.cpp` (fixed params) | 100 TU |
| Capability | `beacon_tx_raw.cpp` | `0x0421` (open ESS) |
| Max frame | `beacon_tx_raw.h` → `BEACON_RAW_MAX_FRAME` | 320 (real frames ≈ 296 B) |
| Tagged-params offset | `beacon_tx_raw.cpp`, `DRIP_Sniffer.ino` `BEACON_TAGGED_START`, `odid.py` `BEACON_TAGGED_START` | 36 |

Transmit path: **STA + promiscuous**, `esp_wifi_80211_tx()`, `en_sys_seq = false`,
hand-built beacons. **Not** SoftAP + `esp_wifi_set_vendor_ie` — that path was
deleted (an AP has one BSSID, so it physically cannot represent 3 UAs). Sequence
numbers are synthesised per slot because `en_sys_seq = false` means the driver
will not fill them.

### 3.3 Serial rates

| Device / tool | Where | Value |
|---|---|---|
| Transmitter | `DRIP_Broadcast_RID.ino` → `Serial.begin()` | 115200 |
| Sniffer | `DRIP_Sniffer.ino` → `SNIFFER_BAUD` | 921600 (460800 OK; **115200 will silently drop frames**) |
| Capture tool defaults | `arduino_logger.py` → `PORT`, `BAUD_RATE` | `COM4`, 115200 — override with `--port` / `--baud` |
| Sniffer ring buffer | `DRIP_Sniffer.ino` → `RING_SLOTS`, `MAX_FRAME` | 16, 512 |

---

## 4. Timing

| What | Edit here | Value |
|---|---|---|
| DRIP epoch (2019-01-01 UTC) | `f3411_messages.h` → `DRIP_EPOCH_UNIX_S` | `1546300800` — spec-fixed, RFC 9575 §3.2.4.3 |
| **Simulated "now"** | `f3411_messages.h` → **`SIM_DRIP_TIME_BASE`** | `201699200` |
| VNA offset (UA-signed evidence window) | `f3411_messages.h` → `DRIP_VNA_OFFSET_S` | 120 s |
| BE validity window | `drip_registration.h` → `DRIP_BE_VALIDITY_S` | 86400 s (24 h) |
| Pack rebuild rate, per drone | `drone_fleet.h` → `FLEET_PACK_PERIOD_MS` | 3 Hz A/B/C rotation |
| Beacon repeat rate, per drone | `drone_fleet.h` → `FLEET_BEACON_PERIOD_MS` | ~10 Hz, unchanged Message Counter (ASTM §5.4.4.2 BUR0050) |
| Playback nominal cycle | `drone_playback.h` → `PLAYBACK_CYCLE_S` | 0.3333 s (bootstrap/floor only; real pacing is measured with `millis()`) |
| Where "now" is read | `drip_time.h` → `drip_timestamp()` | `SIM_DRIP_TIME_BASE + millis()/1000` |

> ⚠️ **`SIM_DRIP_TIME_BASE` is stale.** It is documented as "≈ May 2025 — UPDATE
> before testing". It has not been updated. Every VNB/VNA the firmware emits is
> therefore roughly a year in the past, which will trip `E-FRESH-01` if you run
> the observer with `--now` / `--max-age`. Recompute before the next session:
> `SIM_DRIP_TIME_BASE = <current Unix time> − 1546300800`.
> *(Reported, not changed — no code was touched to produce this map.)*

---

## 5. Fleet commands (transmitter serial console, 115200)

Parsed in **`drone_fleet.cpp` → `fleet_cmd()`**. Case-insensitive.

| Command | Effect |
|---|---|
| `fleet <1..3>` | run N drones, flights auto-assigned 0..N-1 |
| `fleet <n> same <flight>` | N drones, all replaying the same flight |
| `fleet set <slot> <flight>` | assign one slot's flight |
| `fleet list` | slot \| MAC \| DET \| flight \| phase \| point |
| `focus <slot>` | the legacy commands below now act on this slot (default 0) |
| `debug off` | pack hex dump off |
| `debug on` | dump the **focused** slot |
| `debug <slot>` | dump that slot only |

Legacy single-drone commands — they act on the **focused** slot:

| Command | Effect |
|---|---|
| `list` | flight table + fleet table |
| `info` | focused drone's flight, point N/M, finished/stopped state |
| `next` | step one point, print lat/lon/alt/spd/hdg/ts |
| `reset` | restart the focused drone's flight at point 0 (also clears off-air) |
| `stop` | halt the focused drone (beacons cease — a landed drone) |
| `<number>` | select that flight index for the focused slot |

> **Why `debug` is one-drone-only:** one dump is ~3–4 kB of text. At 115200 the
> link carries ~11.5 kB/s, so a single drone at 3 Hz already eats ~90% of it.
> Three would block `Serial.print()`, the fleet scheduler would miss its
> deadlines, and the timing model would collapse. With >1 drone it defaults off.
> See `drip_debug.h`.

---

## 6. Flight data

| What | Where |
|---|---|
| The flight catalogue | **`drone_data.h` → `DRONE_FLIGHTS[]`**, `DRONE_FLIGHT_COUNT` = 27 |
| Point struct | `drone_data.h` → `DronePoint { lat_e7, lon_e7, alt_dm, ts_unix }`, in `PROGMEM` |
| Playback engine / cursor | `drone_playback.h` / `.cpp` → `PlaybackState` (one per drone) |
| Generator | auto-generated by `csv_to_drone_data.py` — **do not edit by hand** (not in this tree) |
| Per-flight cap | 1080 points (~6 min at 3 Hz) — note in the file header; flights 25/26 exceed it (appended at full resolution) |

| idx | flight_id | points | idx | flight_id | points |
|---|---|---|---|---|---|
| 0 | `0M63J2T001H037` | 270 | 14 | `F6Z9C23AB003BTNG` | 408 |
| 1 | `0M6CG9QR0A0FD6` | 843 | 15 | `F6Z9C23AR003DHVF` | 93 |
| 2 | `1ZNBK5900C00A8` | 1032 | 16 | `F6Z9C24B60035ER9` | 916 |
| 3 | `3NZCHCP0043PS1` | 330 | 17 | `F8PJC246L0004BAG` | 285 |
| 4 | `4GCCK6QR0B0QRZ` | 595 | 18 | `F986C254E0020E5T` | 732 |
| 5 | `5FSCK320115HYT` | 513 | 19 | `F9DEC258M029H723` | 264 |
| 6 | `F4XF82391006Q24L` | 135 | 20 | `F9DEC259A029P8S8` | 209 |
| 7 | `F5BKB246700F00DV` | 177 | 21 | `KCG0021GGR` | 237 |
| 8 | `F5FJC248L00D6GD3` | 765 | 22 | `MissionAlpha` | 1019 |
| 9 | `F5FJC248M00DXTG9` | 378 | 23 | `encrypted` | 194 |
| 10 | `F67QC234U01429M1` | 180 | 24 | `F6Z9A24AAML33B85-1108` | 329 |
| 11 | `F6Z9A23BHML35V6J` | 1062 | 25 | `F6Z9A24AAML33B85-1109a` | 1465 |
| 12 | `F6Z9A24AAML33B85` | 1074 | 26 | `F6Z9A24AAML33B85-1109b` | 2700 |
| 13 | `F6Z9C23A7003A3HF` | 117 | | | |

**Dead / unused in this tree — do not be misled:**

- `DroneFlight.det` (`drone_data.h`) — always `nullptr`, **unused**. Identity is
  per **slot** (`IDENTITY_TABLE`), not per flight, so that two drones can fly the
  same track under different DETs.
- `flight_sim.h` / `flight_sim.cpp` — the synthetic square route
  (`SIM_BASE_LAT` −23.2094, `SIM_BASE_LON` −45.8694, 100 m, 5 m/s). **Present but
  never called.** It is a stateless global route, so every drone would sit on the
  identical point. Left in the tree only as reference.

Playback behaviour worth knowing: each point is held for its **real recorded
duration**, so total playback time = the real flight duration regardless of point
count; end-of-track **holds** on the final point (it does not wrap — wrapping
would teleport the drone back to takeoff mid-broadcast).

---

## 7. Build switches & dependencies

| Switch | Where | State | Meaning |
|---|---|---|---|
| `DRIP_TEST_BE` | **`drip_config.h`** | **ON** | Fabricate a self-consistent FAKE Apex→RAA→HDA→UA Broadcast Endorsement chain (`drip_registration.*`). ⚠️ **Comment out for any production / flight image.** |
| `DRONE_REPLAY_RECORDED_TIME` | `drone_playback.h` | **1** | ⚠️ **NOT RFC-conformant.** The ASTM Location timestamp replays the dataset's recorded time. Set to 0 for live use. Does **not** affect DRIP VNB/VNA (those come from `drip_timestamp()` and stay conformant). |
| `USE_ARDUINO_CRYPTO_LIB` | `det_generator.cpp` | ON, **required** | Ed25519 Path A. The PSA path was removed — PSA holds one imported key, the fleet needs 3. |

> **Why `drip_config.h` exists:** in the Arduino build model each `.cpp` is a
> separate translation unit, so a `#define` in the `.ino` does **not** reach
> `drip_registration.cpp`. Build flags go in the shared header, never the sketch.

**Library dependency:** Arduino **"Crypto"** (Rhys Weatherley) — *Sketch → Include
Library → Manage Libraries*. Verified on ESP32 core 3.3.8. No `ieee80211_raw_frame_sanity_check`
linker hack is needed (it does not even link on 3.3.8, and is not required).

**Python optional imports** (`observer.py` degrades gracefully if absent): `det`,
`ed25519`, `ed25519_backend`.

---

## 8. Message & DRIP format constants

| What | Edit here | Value |
|---|---|---|
| Message size | `f3411_messages.h` → `F3411_MSG_BYTES` | 25 |
| Protocol version | `f3411_messages.h` → `F3411_PROTO_VER` / `odid.py` `PROTO_VERSION` | `0x2` |
| Message types | `f3411_messages.h` (`F3411_TYPE_*`) / `odid.py` `MSG_TYPES` | Basic ID `0x0`, Location `0x1`, Auth `0x2`, System `0x4`, Pack `0xF` |
| **ASTM Auth Type** | `f3411_messages.h` → `F3411_AUTH_TYPE_SAM` | **`0x5` (SAM) for ALL DRIP formats.** Using a distinct Auth Type per format is *wrong* (RFC 9575 §3.2.3) |
| SAM Type (1st octet of Auth Data) | `f3411_messages.h` → `DRIP_SAM_TYPE_*` / `odid.py` `SAM_TYPES` | Link `0x01`, Wrapper `0x02`, Manifest `0x03`, Frame `0x04` (RFC 9575 Table 1) |
| DET prefix | `det.py` → `DET_PREFIX` / `odid.py` `DET_PREFIX` | `2001:30::/28` (RFC 9374 Table 1) |
| ORCHID Context ID | `det.py` → `CONTEXT_ID` | `00B5A69C795DF5D5F0087F56843F2C40` — spec-fixed |
| Suite ID | `det_generator.h` → `HHIT_OGA_ID` / `det.py` `SUITE_EDDSA_CSHAKE128` | 5 = EdDSA/cSHAKE128 |
| Session ID width | `det_generator.h` → `SESSION_ID_BYTES` | 20 (`0x01` SSI Type + 16 DET + 3 pad) |
| Pack limits | `message_pack.h` → `MSG_PACK_MAX_MSGS` | 9 msgs (802.11 IE 255-byte body limit) |

Auth page framing — **one owner**: `drip_auth_page.h/.cpp` → `drip_auth_scatter()`.
Link, Wrapper and Manifest all call it, so the wire framing is identical.
Page 0 carries 17 octets (LPI is its own octet, Length, LE timestamp); pages N>0
carry 23 and **every** page header carries AuthType `0x5`.

| Format | SAM bytes | Pages | Owner |
|---|---|---|---|
| Link (Broadcast Endorsement) | 137 | 7 | `drip_link.h` → `DRIP_LINK_SAM_BYTES`, `DRIP_LINK_MAX_PAGES` |
| Wrapper (Extended Transport) | 89 (Evidence cleared) | 5 | `drip_auth.h` → `DRIP_WRAPPER_MAX_PAGES` |
| Manifest | 121 | 6 | `drip_manifest.h` → `MANIFEST_PAYLOAD_BYTES`, `DRIP_MANIFEST_MAX_PAGES` |

Transmission cycle, per drone, 3 Hz (see `DRIP_Broadcast_RID.ino` header):

- **Cycle A** — Basic ID, Location, System, 5 Wrapper pages (8 msgs)
- **Cycle B** — Basic ID, Location, 7 Link pages (9 msgs) — **System omitted**: 10 msgs would not fit in a 9-message pack. Documented design decision, reversible.
- **Cycle C** — Basic ID, Location, System, 6 Manifest pages (9 msgs)

Drones are phase-staggered by `i × (333 ms / N)` so at most one Ed25519 signature
is ever in flight.

---

## 9. Observer tooling (Python)

| File | Role | Key flags / symbols |
|---|---|---|
| **`observer.py`** | Decode a capture, apply the error catalogue, print the report | `file`, `--pubkey HEX`, `--keyring FILE`, `--no-builtin-keys`, `--list-keys`, `--anchor FILE` (default `hierarchy.json`), `--pure-python`, `--now UNIX`, `--max-age SEC`, `--verbose` |
| `odid.py` | Pure decoding layer — ASTM messages, DRIP framing, all input parsers. No validation, no I/O | `parse_format_w/b/a`, `diagnose_format`, `parse_mac_header` |
| `errors.py` | The error catalogue — every entry cites its ASTM/RFC clause | `ERROR_CATALOG`, `Finding` |
| `det.py` | DET computation + binding check (RFC 9374). Also contains the pure-Python cSHAKE128/Keccak | `compute_det`, `verify_det_binding`, `parse_det`, `TEST_RAA=1000`, `TEST_HDA=2000`, `base32_appendix_c` |
| `ed25519.py` | **Normative** RFC 8032 reference implementation (pure Python, ~200 ms/verify) | `derive_pubkey`, `verify` |
| `ed25519_backend.py` | Backend selection + memoisation. Only uses a faster impl after proving it agrees with `ed25519.py` on RFC 8032 §7.1 TEST 1 (valid **and** tampered) | `verify`, `backend_name`, `force_pure_python`, `self_test` |
| `check_hierarchy.py` | **Prove the hierarchy is coherent and delegable.** Run after any hierarchy edit | `--header`, `--json`, `--ua-keys` |
| `make_vectors.py` | Reference encoder: builds valid + deliberately-broken vectors; self-tests the observer | `--write FILE`, `--selftest` |
| `flight_tracks.py` | Extract per-drone position tracks from a capture | `extract_tracks`, `track_summary` |
| `make_map.py` | Self-contained Leaflet/OSM HTML map of each drone's path | `file`, `-o/--output`, `--title` |
| `arduino_logger.py` | Capture an ESP32 serial stream to file without resetting the board | `--port`, `--baud`, `-o`, `--select N`, `--cmd`, `--echo` |

### 9.1 Capture formats

| Format | What it is | Produced by |
|---|---|---|
| **A** | Sniffer air capture (frames + offsets + metadata) | `DRIP_Sniffer.ino` → `arduino_logger.py --baud 921600` |
| **L** | Transmitter's own debug log | `debug on` → `arduino_logger.py` (115200) |
| **W** | Wireshark bytes-only export | Wireshark |
| **B** | Flat hex / hand-authored vectors | `make_vectors.py --write` |

`odid.diagnose_format()` identifies which one you handed it.

### 9.2 Error-code families in `errors.py`

- **`E-*` = conformance failures**, each tied to a specific ASTM/RFC clause:
  `E-FMT-*` (structure), `E-PACK-*`, `E-AUTH-*` (paging), `E-SAM-01`,
  `E-DET-01/02`, `E-KEY-01`, `E-SIG-01`, `E-FRESH-01`, `E-LINK-01..04` (chain of
  trust), `E-MAN-01..05` (manifest ledger), `E-SEM-01`.
- **`W-*` = warnings, NOT violations.** A `W-` code means "unexpected for *this
  bench emulator*", never "violates a standard". The prefix is kept distinct so
  the two can never be conflated in a report handed to a certification reader.
  - `W-CAP-01` — frame damaged in the **capture pipeline** (serial byte loss),
    not on the air. The 802.11 FCS is checked in hardware before the sniffer ever
    sees the frame, so RF corruption cannot reach here. Says nothing about the drone.
  - `W-MAC-02` — same DET from multiple MACs. **Permitted** by ASTM §5.4.5.6
    NOTE 2 (Specific Session ID MAY use random MACs); flagged only because this
    emulator uses a fixed MAC per slot.

---

## 10. Firmware file index

| File | Owns |
|---|---|
| `DRIP_Broadcast_RID.ino` | setup/loop only — `fleet_cmd(); fleet_tick(millis())`. All A/B/C logic lives in `drone_fleet.cpp` |
| `drip_config.h` | build switches (`DRIP_TEST_BE`) |
| `drip_hierarchy.h` | **the hierarchy: RAA/HDA numbers + test parent seeds** |
| `det_generator.h/.cpp` | **`IDENTITY_TABLE`**, `det_compute`, `det_sign_with`, `det_to_session_id` |
| `cshake128.h/.cpp` | cSHAKE128 (NIST SP 800-185) — used only for HHIT/DET ORCHID |
| `f3411_messages.h/.cpp` | ASTM message structs + encoders, epoch/timestamp constants |
| `message_pack.h/.cpp` | ASTM §5.4.9 Message Pack assembly |
| `drip_auth_page.h/.cpp` | **shared Auth page framing** (`drip_auth_scatter`) |
| `drip_auth.h/.cpp` | Wrapper (RFC 9575 §4.3.2) |
| `drip_link.h/.cpp` | Link / Broadcast Endorsement serialisation (§4.2) |
| `drip_manifest.h/.cpp` | Manifest + its hash ledger (§4.4) |
| `drip_registration.h/.cpp` | **`DRIP_TEST_BE` only** — fabricates the fake BE chain. This is the file that gets replaced when a real hierarchy arrives |
| `drip_time.h` | `drip_timestamp()` |
| `drip_debug.h/.cpp` | gated Serial pack dump + Auth reassembly |
| `beacon_tx_raw.h/.cpp` | raw 802.11 injection, `SLOT_MAC`, per-slot frame cache |
| `drone_fleet.h/.cpp` | `VirtualDrone`, the scheduler, **all serial commands** |
| `drone_playback.h/.cpp` | `PlaybackState`, real-timestamp pacing |
| `drone_data.h` | 27 recorded flights (auto-generated) |
| `flight_sim.h/.cpp` | synthetic square route — **uncalled** |
| `DRIP_Sniffer.ino` | separate sketch: promiscuous capture → Format A |

---

## 11. Known duplications and what guards them

| Value | Copies | Guard |
|---|---|---|
| RAA/HDA numbers | `drip_hierarchy.h`, `hierarchy.json` | `check_hierarchy.py` + compile-time `#error` in the header |
| Apex/RAA/HDA keys & DETs | `drip_hierarchy.h` (seeds), `hierarchy.json` (pub+DET), `observer.py` `APEX_HI`/`APEX_DET` (fallback) | `check_hierarchy.py`; `observer.py` prefers `hierarchy.json` at startup |
| UA seeds / pubkeys / DETs | `det_generator.cpp` `IDENTITY_TABLE`, `bench.keyring`, `observer.py` `BUILTIN_KEYS` | firmware self-checks the derivation at boot; the reproduction snippet in `det_generator.cpp` regenerates all three |
| Wi-Fi channel | `beacon_tx_raw.h`, `DRIP_Sniffer.ino` | **none — manual** ⚠️ |
| `BEACON_TAGGED_START` = 36 | `beacon_tx_raw.cpp`, `DRIP_Sniffer.ino`, `odid.py` | none — manual (but it is a fixed 802.11 constant) |
| ODID OUI / vendor type | `beacon_tx_raw.cpp`, `DRIP_Sniffer.ino`, `odid.py` | none — manual (fixed by ASTM Table 20) |
| DRIP epoch `1546300800` | `f3411_messages.h`, `odid.py`, `make_map.py` | none — manual (spec-fixed, will not change) |
| Slot count | `det_generator.h` `DET_IDENTITY_SLOTS`, `drone_fleet.h` `FLEET_MAX`, `SLOT_MAC[]` | `SLOT_MAC` is sized by `DET_IDENTITY_SLOTS`; `FLEET_MAX` is **not** checked against it ⚠️ |
| Serial baud | `DRIP_Sniffer.ino` `SNIFFER_BAUD` vs `arduino_logger.py --baud` | none — manual ⚠️ |

---

## 12. Open items visible from this map

Recorded here, **not acted on** — no existing file was modified to produce this document.

1. **`SIM_DRIP_TIME_BASE` is ~14 months stale** (§4). Every emitted VNB/VNA is in
   the past. Trips `E-FRESH-01` under `--now`/`--max-age`.
2. **`DRONE_REPLAY_RECORDED_TIME = 1`** (§7) — the ASTM Location timestamp is
   knowingly non-conformant on this build.
3. **`DRIP_TEST_BE` is ON** (§7) — the trust chain is fabricated and forgeable by
   anyone reading this repository. Correct for the bench; must go for flight.
4. **No IANA registration** stands behind RAA 1000 / HDA 2000 or any DET here
   (RFC 9374 §3.3).
5. **`FLEET_MAX` and `DET_IDENTITY_SLOTS` are independent** — nothing errors if
   they disagree.
6. **Channel and baud are duplicated across two sketches** with no guard (§11).



Full command reference
python3 observer.py [FILE] [options]
Main modes:
CommandWhat it doesobserver.py capture.txtDecode + validate a capture file (Format L/A/W/B auto-detected), verify every DET against the trust file, print findingsobserver.py --resolve <DET>Resolve ONE DET offline against hierarchy.json: decode fields, check nesting + allow-list, verify binding if a key is on file. No networkobserver.py --dns-lookup <DET>Look up ONE DET in DNS (PTR→TXT), verify binding, offer to save. Needs network + dnspythonobserver.py --list-keysPrint the loaded keyring (all identities from hierarchy.json)
Options:
FlagEffect--dns-fallbackDuring file decode, auto-look-up untrusted DETs once each and offer to add them (the feature you just specified)--dns-server IPDNS server for lookups (default 141.227.148.117)--anchor FILETrusted-identities file (default hierarchy.json)--keyring FILEExtra DET→pubkey pairs (overrides file entries)--pubkey HEXWildcard key for any unlisted DET--no-builtin-keysDon't load the trust file; only --keyring/--pubkey supply keys--now UNIX / --max-age SECFreshness check for VNB/VNA timestamps--pure-pythonForce the slow reference Ed25519 (cross-check)--verbosePrint every decoded item
python3 check_hierarchy.py --header drip_hierarchy.h --json hierarchy.json
Validates the chain matching the firmware header (picks the right chain from the both-chains file), re-derives every DET, checks firmware↔observer agreement, and validates RAA/HDA numbers against the corrected RFC 9886 §6.2.1 rule.