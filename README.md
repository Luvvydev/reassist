<p align="center">
  <img src="reassist.png" alt="reassist">
</p>

# REAssist

REAssist is a small CLI that does boring first-pass reverse engineering triage and turns it into a report.

It is intentionally conservative. It does not attempt exploitation, unpacking, decryption, or anything that crosses into offensive automation. It just collects evidence (strings, IOCs, import hints) and formats it.

## What it does

- Runs `strings` and keeps a bounded sample
- Extracts common IOCs from the strings sample (URLs, IPs, domains, email addresses, file paths, registry paths)
- Extracts best-effort import hints (ELF undefined symbols via `readelf`, PE DLL names via `objdump`)
- Writes `analysis.json`
- Renders `report.html` and `report.md`
- Optionally merges a Ghidra export JSON into `analysis.json`

## Install

Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install .
```

On Linux/macOS you likely already have `strings` and `file`. If you do not, install binutils.

Optional extras:

```bash
pip install ".[elf]"      # pyelftools (not required for current import hints)
pip install ".[pe]"       # pefile (not required)
pip install ".[yara]"     # yara-python (not required)
```

## Usage

### Triage

```bash
reassist triage ./some_binary -o analysis.json --min-len 10 --max-strings 8000
```

### Report

```bash
reassist report analysis.json -o out
# out/report.html
# out/report.md
```

### Merge a Ghidra export

```bash
reassist merge-ghidra analysis.json ghidra_export.json
```

## Ghidra export

A minimal export script is included at `ghidra_scripts/ExportREAssist.py`.

Run it from Ghidra's Script Manager after analysis. It writes a JSON file with function names, entry points, and decompiler text.

The output is meant to be merged using `reassist merge-ghidra`.

## Safety and scope

Do not run untrusted samples on your host OS. Use a VM or an isolated environment.

REAssist is meant for:
- your own binaries
- classroom reverse engineering labs
- defensive triage in controlled environments

## Quick Start

```bash
cd reassist
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install .

reassist triage /path/to/binary -o analysis.json
reassist report analysis.json -o out
```

## License

MIT
