# mpenginedb_parser

Forensic parser for Microsoft Defender's MpEngineDb ("MetaVault"):

```
C:\ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db
C:\ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db-wal
```

The database is SQLite, but every page is encrypted with RC4 using a fixed 256-byte key from mpengine.dll. Normal SQLite tools can't open it. This tool decrypts it, replays the WAL, recovers deleted rows and decodes every field.

## Requirements

Python 3.8 or newer. Standard library only.

## Usage

```
python3 mpenginedb_parser.py -f "...\mpenginedb.db" --wal "..\mpenginedb.db~wal" -o <output folder>
```

| Option | Meaning |
|---|---|
| `-f` | the database file, or the folder that contains `mpenginedb.db` |
| `--wal` | the WAL file, if it was collected under another name |
| `-o` | output folder |
| `--keep-states` | keep the rebuilt database of every WAL commit |
| `--no-carve` | skip carving of deleted records |
| `--all-tables` | also write CSV files for empty tables |
| `--derive-key` | ignore the built-in key and recover the keystream from the evidence only |

Collect the `-wal` file together with the database. Without it the newest changes are missing.

## Output

| File | Content |
|---|---|
| `report.txt` | short human-readable summary |
| `timeline.csv` | every timestamp from every table, live and recovered rows, sorted, UTC |
| `tables/<table>.csv` | each non-empty table, raw columns plus decoded columns |
| `recovered_rows.csv` | rows removed during the WAL period and carved records, marked "deleted row" or "older version of a live row", with a record quality check that flags partially overwritten records |
| `row_history.csv` | every row and the WAL commits it appears in |
| `wal_frames.csv` | every WAL frame, valid or not, and why |
| `mpenginedb_decrypted.db` | decrypted database with the WAL applied (opens in any SQLite tool) |
| `mpenginedb_decrypted_without_wal.db` | decrypted database file alone |
| `summary.json` | all run facts, hashes, versions, counts |
| `run.log` | log of every step, UTC |
| `manifest.csv` | SHA-256 of every output file |

## Evidence handling

- Inputs are only read. MD5, SHA-1 and SHA-256 are taken before the run and SHA-256 again after it. `evidence_unchanged` in `summary.json` confirms the result.
- The WAL is validated with SQLite's own rules on the stored bytes (salts and checksum chain). Frames after a break or after the last commit are not applied but are still carved.
- With `--derive-key` the key comes from the evidence alone (known header plus zero-filled free space). It gives the same result as the built-in key, which you can show in court without relying on the tool's embedded data.

## Decoding

- Times: Windows FILETIME to UTC, 100 ns precision.
- FileHashes: Defender's schema stores **MD5 in the column named SHA1 and SHA-1 in the column named MD5**. The tool labels them correctly. FileID is split into MFT entry and sequence number, VSN into volume serial.
- Rolling queues: `Tech-pid:<pid>,ProcessStart:<FILETIME>` and `Tact-…` names are split into PID and process start time. These queues are Defender's per-process attack scoring.
- BackupProcessInfo.FirstStartTime is a process start time only for executables. For other files it is an identifier, and the tool says so.
- Software inventory (MetaInventory tables): Unix-second times decoded, CPE / package URL identifiers with their CVE IDs, file property payloads decoded, USN journal creation time.
- Labels: MITRE ATT&CK technique names (revoked IDs show their replacement), Microsoft ASR rule names, and a catalogue of 2,266 values written by Defender signatures.

## Lookups

`lookups/` must sit next to the script. The tool still runs without it, just without labels.

| File | Source |
|---|---|
| `mitre_attack.json` | MITRE ATT&CK enterprise, github.com/mitre/cti |
| `asr_rules.json` | Microsoft Learn, ASR rules reference |
| `vdm_catalog.json` | values found in Defender signature scripts (mpasbase/mpavbase.vdm, engine 1.1.26100.4) |

## Tested

Windows 11 build 26100, Defender engine 1.1.26100.4, SQLite 3.51.3, three machines (same key on all). Results checked against a separate decryption, with the key recovered from the file and the key taken from mpengine.dll. Also tested without a WAL, with a plain SQLite file, with a corrupted WAL frame, with a truncated WAL and with junk input.
