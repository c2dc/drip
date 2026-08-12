# DRIP PoC — Command Reference

Built from the current project files (dated Jul 19 11:32). Where a default or
flag is shown, it was read from the actual source, not memory.

Current identity settings baked into the firmware right now:
- **UA RAA = 255, UA HDA = 14340** (`drip_hierarchy.h`)
- **DET method = raw 32-byte key** (RFC 9374 reference / `det-gen.py` compatible)
- Slot 0 = the externally-provided keypair, DET `2001:30:3ff8:405:d952:5618:fbc9:c3cf`

---

## 1. Broadcast side (ESP-32 transmitter)

### 1.1 Build & flash
Open `DRIP_Broadcast_RID.ino` in the Arduino IDE, select the ESP32 board, and
flash. The transmitter's Serial Monitor runs at **115200 baud**
(`Serial.begin(115200)`), and Wi-Fi comes up in STA + promiscuous mode on
**channel 6** (`WIFI_CHANNEL_DRIP = 6`, `beacon_tx_raw.h`).

At boot the firmware self-checks every identity slot: it derives the public key
from each seed, recomputes the DET, and refuses to run if either doesn't match
the recorded value. Watch the boot log to confirm the DETs.

### 1.2 Fleet serial commands (type into the Serial Monitor)
Parsed in `drone_fleet.cpp`. Commands are **case-insensitive**. `FLEET_MAX`
bounds the fleet size; `g_focus` defaults to **slot 0**.

| Command | What it does |
|---|---|
| `fleet <1..3>` | Set how many drones are flying (1 to FLEET_MAX). |
| `fleet <n> same <flight>` | Fly `n` drones, all on the same flight index. |
| `fleet set <slot> <flight>` | Assign a flight to one slot. Re-provisions that slot, re-issues its leaf endorsement (`fleet_reg_refresh`), and re-staggers timing (`fleet_restagger`). |
| `fleet list` (or bare `fleet`) | List the current fleet and each slot's flight. |
| `focus <slot>` | Make the legacy single-drone commands (`list/info/next/reset/stop/<number>`) act on this slot. Default focus = slot 0. |
| `debug off` | Turn off the per-cycle pack hex dump. |
| `debug on` | Dump packs for the focused slot. |
| `debug <slot>` | Dump packs for a specific slot. |
| `list` | List playback flights, then the fleet. |
| `info` | Show the focused slot's flight and playback position. |
| `next` | Advance the focused slot's playback one point. |
| `reset` | Restart the focused slot's flight at point 0. |
| `stop` | Stop the focused slot's playback. |
| `<number>` | Select flight index `<number>` for the focused slot. |

### 1.3 Change which flight a drone flies
Two ways:
- **All drones, one flight:** `fleet <n> same <flight>`
- **One slot:** `focus <slot>` then type the flight `<number>`, **or** in one
  step `fleet set <slot> <flight>`.

### 1.4 Change the transmitted identity
Identities are compiled in (`static const IDENTITY_TABLE` in
`det_generator.cpp`), so this needs an **edit + reflash** — there is no runtime
command to inject a new key. To swap or add an identity:
1. Generate the keypair + DET (see §3).
2. Edit the slot row (seed / pubkey / DET) in `det_generator.cpp`.
3. If adding a slot: also bump `DET_IDENTITY_SLOTS` (`det_generator.h`),
   `FLEET_MAX` (`drone_fleet.h`), and add a MAC in `beacon_tx_raw.cpp`.
4. Reflash.

---

## 2. Observer side (`observer.py`)

All arguments below are read verbatim from the current `observer.py`.

```
python3 observer.py [FILE] [options]
```

### 2.1 Main modes
| Command | What it does |
|---|---|
| `observer.py capture.txt` | Decode + validate a capture file and print findings. |
| `observer.py --resolve <DET>` | Resolve ONE DET **offline** against the trust file: decode fields, check zone nesting + allow-list, verify the DET↔key binding if a key is on file. No network (Step 1). |
| `observer.py --dns-lookup <DET>` | Look up ONE DET in DNS (PTR→TXT), verify the binding, offer to save it. **Needs network + dnspython** (Step 2). |
| `observer.py --list-keys` | Print the keyring (loaded from the trust file) and exit. |

`<DET>` accepts either 32 hex chars or the colon IPv6 form.

### 2.2 Options
| Flag | Effect |
|---|---|
| `--dns-fallback` | While reading a capture, an untrusted DET triggers **one** DNS lookup and a prompt (see §2.4). One query per untrusted DET per run. Off by default. |
| `--dns-server IP` | Resolver for DNS lookups. Default `141.227.148.117` (the partner's server). |
| `--anchor FILE` | Trusted-identities file. Default `hierarchy.json`. |
| `--keyring FILE` | Extra `DET_HEX PUBKEY_HEX` pairs (one per line, `#` comments allowed). Overrides file entries. |
| `--pubkey HEX` | 32-byte Ed25519 public key (hex) used as a wildcard for any DET with no keyring entry (single unknown drone). |
| `--no-builtin-keys` | Do not load the trust file; only `--keyring`/`--pubkey` supply keys. |
| `--now INT` | Reference Unix time for the freshness check. |
| `--max-age INT` | Max allowed \|age\| in seconds (used with `--now`). |
| `--pure-python` | Force the `ed25519.py` reference backend (~1300× slower; for cross-checking). |
| `--verbose` | Print every decoded item and every finding (not just the first 5 per error). |

### 2.3 Capture formats (auto-detected)
- **L** — ESP32 serial log (from the transmitter's debug output)
- **A** — DRIP_Sniffer air capture
- **W** — Wireshark bytes export
- **B** — flat hex

### 2.4 DNS fallback prompt (with `--dns-fallback`)
When a DET is not in the trust file and DNS returns a key whose binding
**verifies**, you get three choices:

| Key | Meaning |
|---|---|
| `w` | **Write** the identity into `hierarchy.json` **and** trust it for this run. |
| `t` | **Trust this run only** — verify the drone's messages using the DNS key, but **do not** write the file. Uses the key already fetched (no second DNS query). |
| `n` | **No** — ignore, do not verify, skip for the rest of the run. |

If the DNS binding **fails**, you are told plainly and it is **not** offered for
adding. Every untrusted DET is consulted **at most once per run**; declined or
failed DETs are never re-queried. An end-of-run "DNS fallback summary" lists each
untrusted DET and its outcome.

### 2.5 Reading the report
- **Findings by DET** — findings grouped per drone, so you can see which identity
  owns them. A trusted, fully-verified drone shows `0 finding(s)`.
- **Findings** — the same findings grouped by error ID (which frames).
- `E-KEY-01` = "no key on file, so NOT checked" (not a failure — the drone just
  isn't trusted yet).
- `E-DET-02` = binding failed (the key does not derive the DET).
- `E-MAN-02` = a manifest referenced a Message Pack hash not seen in this
  capture (usually packs sent before recording started). Benign; not a parse or
  signature failure. Manifests are deduplicated, so the count is distinct
  unmatched references, not rebroadcasts.

---

## 3. Generate new key pairs (`newkey.py`)

Run from the folder that contains `ed25519.py` and `det.py`:

```
python3 newkey.py
```

The current `newkey.py` generates a fresh key with `os.urandom(32)` (the OS
CSPRNG — cryptographically secure), derives the public key, computes the DET
(raw-key method) at **RAA=255, HDA=14340**, and prints:

```
SEED  (private): ...
PUB   (public) : ...
DET (hex)      : ...
DET (IPv6)     : ...
binding OK     : True
```

Notes:
- **Save the SEED immediately** — a new random key is produced every run; there
  is no way to recover it later.
- `binding OK: True` confirms the key, derivation, and DET are consistent. If it
  ever prints `False`, do not use that identity.
- To change the hierarchy numbers, edit the `RAA`/`HDA` lines at the top.
- To use a different key each time in the firmware table, copy SEED/PUB/DET into
  the `det_generator.cpp` slot row (see §1.4).

Alternative generator: Moskowitz's `det-gen.py` (`--keynameexists n` to generate,
`--keynameexists y` to read an existing `<name>prv.pem`) produces the keypair and
DET together and is byte-compatible with your project's raw-key method.

---

## 4. Add / verify an identity in the observer

The trust file `hierarchy.json` is the **single source of truth** for all
observer keys and DETs (there is no hard-coded key table in `observer.py`). To
make the observer trust a new identity, add it to `hierarchy.json`:

- **UA entry** (in the `ua` array):
  `{ "det": "<HEX>", "raa": 255, "hda": 14340, "public_key": "<HEX>" }`
- The file also holds the Apex/RAA/HDA authorities. It currently carries **two
  chains** (1000/2000 and 255/14340) via the plural `raas` / `hdas` arrays, so
  the observer trusts identities from either chain.

Then verify:
```
python3 observer.py --resolve <DET>          # offline check against hierarchy.json
python3 observer.py --list-keys              # confirm the key loaded
```

---

## 5. Capture logging (`arduino_logger.py`)

Records the ESP32's serial output to a file for the observer to read.

```
python3 arduino_logger.py [options]
```

| Flag | Default | Effect |
|---|---|---|
| `--port` | `COM4` | Serial port. |
| `--baud` | `115200` | `115200` for the transmitter debug log; `921600` for the DRIP_Sniffer (`460800` if the USB chip is flaky). |
| `-o`, `--output` | (built-in) | Output file. |
| `--select N` | — | Send flight index `N` over serial right after connecting (same as typing `N` in the Serial Monitor). |
| `--cmd '<cmd>'` | — | Send an arbitrary playback command instead of `--select` (e.g. `reset`, `stop`, `list`). |
| `--echo` | off | Print every line to the console as it's logged. |

---

## 6. Supporting Python tools

### 6.1 `check_hierarchy.py` — validate the trust chain
```
python3 check_hierarchy.py --header drip_hierarchy.h --json hierarchy.json
```
Re-derives every DET, checks firmware↔observer agreement, and validates the
RAA/HDA numbers against RFC 9886 §6.2.1 / §6.2.1.3 (RAA ranges, reserved HDA
values 0/4096/8192/12288, parent/child number coherence). With the two-chain
file it validates the chain matching the header's UA numbers.
- `--json` (default `hierarchy.json`)
- `--header` (default `drip_hierarchy.h`)
- `--ua-keys FILE` — optional keyring of UA DET/pubkey pairs to check instead of
  the trust file's UAs.

### 6.2 `make_map.py` — plot flight tracks
```
python3 make_map.py capture.txt -o map.html
```
- `file` — capture file (Format L, W, or B)
- `-o`, `--output` (default `map.html`)
- `--title` (default "DRIP flight tracks")

### 6.3 `make_vectors.py` — test vectors / self-test
```
python3 make_vectors.py --selftest        # run the observer self-test
python3 make_vectors.py --write vectors.txt   # write vectors as a Format B file
```

---

## 7. Quick workflows

**Fly 3 drones, log, and validate:**
```
# in the Serial Monitor (or via arduino_logger --cmd):
fleet 3
# then record:
python3 arduino_logger.py --port COM4 --baud 921600 -o capture.txt
python3 observer.py capture.txt
```

**Add a brand-new drone identity end to end:**
```
python3 newkey.py                 # 1. get SEED / PUB / DET
# 2. paste SEED/PUB/DET into det_generator.cpp slot row; bump slot counts; reflash
# 3. add {det,raa,hda,public_key} to hierarchy.json ua[]
python3 check_hierarchy.py        # 4. confirm the chain is coherent
python3 observer.py --resolve <DET>   # 5. confirm the observer trusts it
```

**Read a capture and discover unknown drones from DNS (verify only, no file
changes):**
```
python3 observer.py capture.txt --dns-fallback
# at each prompt, press 't' to trust just this run without writing hierarchy.json
```

---

## 8. Key constants (current values, from source)

| Constant | Value | File |
|---|---|---|
| UA RAA | 255 | `drip_hierarchy.h` |
| UA HDA | 14340 | `drip_hierarchy.h` |
| Wi-Fi channel | 6 | `beacon_tx_raw.h` |
| Transmitter baud | 115200 | `DRIP_Broadcast_RID.ino` |
| Sniffer baud | 921600 (460800 fallback) | `arduino_logger.py` |
| Default DNS server | 141.227.148.117 | `observer.py` |
| Default trust anchor | hierarchy.json | `observer.py` |
| DET hash method | raw 32-byte key | `det.py`, `det_generator.cpp` |


The ESP32 Broadcast boot at 23 May 2025 08:33:20.
