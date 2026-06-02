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
  - `4776` — NTLM credential validation failure
  - `4625` — Generic failed logon (all logon types)
- Falls back to **ADSI/LDAP** if `Get-ADUser` (RSAT) is unavailable
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
3. Optionally specify a **DC override** if auto-detect fails
4. Review the stat cards (lock status, bad pwd count, last bad pwd timestamp)
5. Drill into the event table — filter by event ID, sort by time

---

## How It Works

The tool writes PowerShell scripts to temporary `.ps1` files at runtime (avoiding inline escaping bugs), then executes them via `subprocess` with `CREATE_NO_WINDOW`. Each DC is queried in a separate thread using `Invoke-Command` over WinRM. Results are merged, deduplicated by `(Time, EventId, Computer, IP)`, and sorted descending by timestamp before display.

---

## Building the EXE

```bash
pip install pyinstaller
pyinstaller --onefile --noconsole badpwd_lookup.py
```

Output will be in `dist/BadPwdLookup.exe`.

---

## Intended Use

Built for **IT support and sysadmin teams** in Active Directory environments to speed up lockout investigations — replacing the multi-step process of remoting into each DC and manually filtering Security event logs.

---

## License

MIT
