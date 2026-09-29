# Bad Password Lookup v3

A Windows desktop tool for IT administrators to investigate Active Directory failed authentication events and account lockouts in real time — without needing RPC access or remote Event Log permissions beyond WinRM.

![Python](https://img.shields.io/badge/Python-3.7%2B-blue) ![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey) ![AD](https://img.shields.io/badge/Environment-Active%20Directory-blue)

---

## What It Does

When a user calls the help desk saying they're locked out, this tool gives you immediate answers:

- **Who got locked out** and current lock status
- **Where the bad password attempts came from** (workstation name + IP)
- **Which authentication protocol was used** (Kerberos, NTLM, interactive, etc.)
- **Which DC reported each event**, aggregated across all DCs in the domain

All in a clean dark-themed GUI — no PowerShell window, no manual event log digging.

---

## Features

- Auto-discovers domain controllers and PDC emulator on launch
- Queries **all DCs in parallel** via WinRM (`Invoke-Command`) — no RPC or remote registry needed
- Covers four security event IDs:
  - `4740` — Account lockout (source machine via `CallerComputerName`)
  - `4771` — Kerberos pre-auth failure (resolves `::ffff:` IPs to hostnames)
  - `4776` — NTLM credential validation failure (successful validations, status `0x0`, are skipped)
  - `4625` — Generic failed logon (all logon types)
- Falls back to **ADSI/LDAP** if `Get-ADUser` (RSAT) is unavailable
- Searches every event in a lookback window (default 24 hours, up to 720), not just the newest few hundred
- Deduplicates events reported by multiple DCs
- Filterable event table by event ID
- DC override field for environments with detection issues
- Compiled to a standalone `.exe` via PyInstaller — no Python install required on the endpoint

---

## Requirements

- Windows, domain-joined machine
- Python 3.7+ (if running from source) — or use the compiled `.exe`
- Your account must be in **Event Log Readers** on DCs, or have Domain Admin
- **WinRM** must be accessible to DCs (open by default on domain controllers)

---

## Usage

**From source:**
```bash
python badpwd_lookup.py
```

**From compiled EXE:**
```
BadPwdLookup.exe
```

1. App auto-detects your domain and all DCs on launch
2. Enter a **username** (sAMAccountName) and press Enter or click **Lookup**
3. Optionally specify a **DC override** if auto-detect fails, or change the **lookback** in hours (default 24)
4. Review the stat cards (lock status, bad pwd count, last bad pwd timestamp)
5. Drill into the event table — filter by event ID, sort by time

---

## How It Works

The tool writes PowerShell scripts to temporary `.ps1` files at runtime (avoiding inline escaping bugs), then executes them via `subprocess` with `CREATE_NO_WINDOW`. The username, DC and lookback are passed to the scripts as parameters, never pasted into the script text. Each DC is queried in a separate thread using `Invoke-Command` over WinRM, reading every event of each type in the lookback window and then filtering to the user. Results are merged, deduplicated by `(Time, EventId, Computer, IP)`, and sorted descending by timestamp before display.

A longer lookback on a busy DC takes longer to read; each DC gets up to 2 minutes.

---

## Building the EXE

```bash
pip install pyinstaller
pyinstaller --onefile --noconsole --name BadPwdLookup badpwd_lookup.py
```

Output will be in `dist/BadPwdLookup.exe`.

### Releases

GitHub Actions (`.github/workflows/build.yml`) runs the tests on Windows and Linux and builds the `.exe` on Windows for every push and pull request; the build is downloadable from the run's **Artifacts**. To publish a release, push a version tag:

```bash
git tag v3.1.0
git push origin v3.1.0
```

That publishes `BadPwdLookup.exe` (and its SHA-256) as a **pre-release**. After trying it against real DCs, edit the release on GitHub and tick **Set as the latest release**.

---

## Tests

The pure-Python helpers and the PowerShell event filtering have tests that run anywhere (the PowerShell ones need `pwsh`, and stand in fake events for `Get-WinEvent`):

```bash
pip install pytest
pytest
```

---

## Intended Use

Built for **IT support and sysadmin teams** in Active Directory environments to speed up lockout investigations.

---

## License

MIT
