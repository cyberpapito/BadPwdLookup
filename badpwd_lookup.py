"""
Bad Password Lookup  v3
=======================
- Uses Invoke-Command (WinRM) — no RPC/remote event log needed
- Writes PowerShell to a real temp .ps1 file — no inline escaping bugs
- Resolves ::ffff: IPs to hostnames for Kerberos (4771) events
- Queries 4625, 4771, 4776, 4740 across all DCs

Requirements:
  - Python 3.7+, Windows, domain-joined
  - Your account in Event Log Readers on DCs (or Domain Admin)
  - WinRM accessible to DCs (usually open by default on domain DCs)
"""

import tkinter as tk
from tkinter import ttk
import subprocess, json, threading, tempfile, os
from datetime import datetime

# ── palette ───────────────────────────────────────────────────────────────────
BG      = "#0d1117"
SURFACE = "#161b22"
BORDER  = "#30363d"
TEXT    = "#e6edf3"
MUTED   = "#8b949e"
RED     = "#f85149"
BLUE    = "#79c0ff"
GREEN   = "#3fb950"
YELLOW  = "#d29922"
ROW_A   = "#161b22"
ROW_B   = "#0d1117"
SEL     = "#1c2128"

MONO  = ("Consolas", 10)
MONOS = ("Consolas", 9)
UI    = ("Segoe UI", 10)
UIS   = ("Segoe UI", 9)
UIB   = ("Segoe UI Semibold", 10)
UIT   = ("Segoe UI Semibold", 14)

LOGON_TYPES = {
    "2": "Interactive", "3": "Network", "4": "Batch",
    "5": "Service",     "7": "Unlock",  "8": "NetCleartext",
    "10": "RemoteInteractive", "11": "CachedInteractive",
}

# ── PowerShell scripts written to temp files ──────────────────────────────────

PS_DISCOVER = """
try {
    $d    = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $pdc  = $d.PdcRoleOwner.Name
    $dcs  = @($d.DomainControllers | ForEach-Object { $_.Name })
    [PSCustomObject]@{ DomainName=$d.Name; PDC=$pdc; AllDCs=$dcs } | ConvertTo-Json -Depth 3
} catch {
    Write-Output "ERROR:$($_.Exception.Message)"; exit 1
}
"""

# This script runs INSIDE Invoke-Command on the DC itself
# $Username is passed as -ArgumentList
PS_QUERY_ON_DC = """
param([string]$Username)

function Get-Field($e, $name) {
    try {
        $xml  = [xml]$e.ToXml()
        $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $name }
        if ($node) { return ([string]$node.'#text').Trim() }
    } catch {}
    return ''
}

function Resolve-IP([string]$raw) {
    $ip = $raw -replace '^::ffff:',''
    if (-not $ip -or $ip -eq '::1' -or $ip -eq '127.0.0.1' -or $ip -eq '-') { return '' }
    try { return ([System.Net.Dns]::GetHostEntry($ip)).HostName } catch { return $ip }
}

$out = [System.Collections.Generic.List[PSCustomObject]]::new()

# 4740 - Account lockout (CallerComputerName is the source machine)
try {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4740} -MaxEvents 200 -EA Stop |
    Where-Object { (Get-Field $_ 'TargetUserName') -eq $Username } | ForEach-Object {
        $comp = (Get-Field $_ 'CallerComputerName') -replace '\\\\','' -replace '\\',''
        $out.Add([PSCustomObject]@{
            Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            EventId=4740; Computer=$comp; IP=''; LogonType='Lockout'
        })
    }
} catch {}

# 4771 - Kerberos pre-auth failure (IP only, resolve to hostname)
try {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4771} -MaxEvents 500 -EA Stop |
    Where-Object { (Get-Field $_ 'TargetUserName') -eq $Username } | ForEach-Object {
        $rawIp = Get-Field $_ 'IpAddress'
        $ip    = $rawIp -replace '^::ffff:',''
        $comp  = Resolve-IP $rawIp
        $out.Add([PSCustomObject]@{
            Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            EventId=4771; Computer=$comp; IP=$ip; LogonType='Kerberos'
        })
    }
} catch {}

# 4776 - NTLM credential validation (Workstation always present)
try {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4776} -MaxEvents 500 -EA Stop |
    Where-Object { (Get-Field $_ 'TargetUserName') -eq $Username } | ForEach-Object {
        $comp = (Get-Field $_ 'Workstation') -replace '\\\\','' -replace '\\',''
        $out.Add([PSCustomObject]@{
            Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            EventId=4776; Computer=$comp; IP=''; LogonType='NTLM'
        })
    }
} catch {}

# 4625 - Generic failed logon (WorkstationName, fall back to IP resolve)
try {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 500 -EA Stop |
    Where-Object { (Get-Field $_ 'TargetUserName') -eq $Username } | ForEach-Object {
        $comp = (Get-Field $_ 'WorkstationName') -replace '\\\\','' -replace '\\',''
        $ip   = Get-Field $_ 'IpAddress'
        $lt   = Get-Field $_ 'LogonType'
        if (-not $comp -and $ip) { $comp = Resolve-IP $ip }
        $out.Add([PSCustomObject]@{
            Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            EventId=4625; Computer=$comp; IP=($ip -replace '^::ffff:',''); LogonType=$lt
        })
    }
} catch {}

if ($out.Count -gt 0) {
    $out | Sort-Object Time -Descending | ConvertTo-Json -Depth 3
} else {
    Write-Output '[]'
}
"""

PS_GET_USER = """
param([string]$Username, [string]$DC)
$ErrorActionPreference = 'Stop'
try {
    $u = Get-ADUser $Username -Server $DC -Properties BadPwdCount,BadPasswordTime,LockedOut,DisplayName,PasswordLastSet,LastLogonDate -EA Stop
    $ts = if ($u.BadPasswordTime -gt 0) { [datetime]::FromFileTime($u.BadPasswordTime).ToString('yyyy-MM-dd HH:mm:ss') } else { 'Never' }
    [PSCustomObject]@{
        SamAccountName  = $u.SamAccountName
        DisplayName     = $u.DisplayName
        LockedOut       = $u.LockedOut
        BadPwdCount     = $u.BadPwdCount
        LastBadPwd      = $ts
        PasswordLastSet = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
        LastLogon       = if ($u.LastLogonDate)   { $u.LastLogonDate.ToString('yyyy-MM-dd HH:mm:ss')   } else { 'N/A' }
    } | ConvertTo-Json
} catch {
    # ADSI fallback
    $s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$DC")
    $s.Filter = "(&(objectClass=user)(sAMAccountName=$Username))"
    'sAMAccountName','displayName','lockoutTime','badPwdCount','badPasswordTime','pwdLastSet','lastLogon' |
        ForEach-Object { [void]$s.PropertiesToLoad.Add($_) }
    $r = $s.FindOne()
    if (-not $r) { Write-Output "ERROR:User not found"; exit 1 }
    $p = $r.Properties
    $bpt = if ($p['badpasswordtime'][0] -gt 0) { [datetime]::FromFileTime($p['badpasswordtime'][0]).ToString('yyyy-MM-dd HH:mm:ss') } else { 'Never' }
    [PSCustomObject]@{
        SamAccountName  = [string]$p['samaccountname'][0]
        DisplayName     = if ($p['displayname'].Count) { [string]$p['displayname'][0] } else { '' }
        LockedOut       = ($p['lockouttime'].Count -gt 0 -and $p['lockouttime'][0] -gt 0)
        BadPwdCount     = if ($p['badpwdcount'].Count) { [int]$p['badpwdcount'][0] } else { 0 }
        LastBadPwd      = $bpt
        PasswordLastSet = if ($p['pwdlastset'][0] -gt 0) { [datetime]::FromFileTime($p['pwdlastset'][0]).ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
        LastLogon       = if ($p['lastlogon'][0]  -gt 0) { [datetime]::FromFileTime($p['lastlogon'][0]).ToString('yyyy-MM-dd HH:mm:ss')  } else { 'N/A' }
    } | ConvertTo-Json
}
"""


def write_temp_ps(content: str) -> str:
    """Write PS content to a temp .ps1 file, return the path."""
    fd, path = tempfile.mkstemp(suffix=".ps1", prefix="badpwd_")
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(content)
    return path


def run_ps_file(path: str, args: list[str] = None, timeout: int = 45) -> tuple[bool, str]:
    """Run a .ps1 file with optional args."""
    cmd = ["powershell", "-NoProfile", "-NonInteractive",
           "-ExecutionPolicy", "Bypass", "-File", path]
    if args:
        cmd += args
    # CREATE_NO_WINDOW suppresses the console flash on each PowerShell call
    CREATE_NO_WINDOW = 0x08000000
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           creationflags=CREATE_NO_WINDOW)
        out = r.stdout.strip()
        if out.startswith("ERROR:"):
            return False, out[6:]
        if r.returncode != 0:
            return False, (r.stderr.strip() or out)
        return True, out
    except subprocess.TimeoutExpired:
        return False, "Timed out."
    except FileNotFoundError:
        return False, "PowerShell not found."
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass


def run_invoke_command(dc: str, username: str, timeout: int = 60) -> tuple[bool, str]:
    """Run PS_QUERY_ON_DC on a remote DC via Invoke-Command (WinRM)."""
    # Write the inner script to a temp file
    inner_path = write_temp_ps(PS_QUERY_ON_DC)

    # Wrapper that calls Invoke-Command with the script file contents as a scriptblock
    wrapper = f"""
$inner = Get-Content -Path '{inner_path}' -Raw
$sb    = [scriptblock]::Create($inner)
try {{
    $result = Invoke-Command -ComputerName '{dc}' -ScriptBlock $sb -ArgumentList '{username}' -ErrorAction Stop
    $result
}} catch {{
    Write-Output "ERROR:$($_.Exception.Message)"
    exit 1
}}
"""
    wrapper_path = write_temp_ps(wrapper)
    ok, out = run_ps_file(wrapper_path, timeout=timeout)
    try:
        os.unlink(inner_path)
    except Exception:
        pass
    return ok, out


# ── App ───────────────────────────────────────────────────────────────────────

class BadPwdApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Bad Password Lookup  v3")
        self.geometry("920x640")
        self.minsize(780, 500)
        self.configure(bg=BG)
        self.resizable(True, True)

        self._domain  = tk.StringVar(value="Detecting…")
        self._pdc     = tk.StringVar(value="")
        self._all_dcs = []
        self._busy    = False
        self._events  = []

        self._style()
        self._build()
        self._detect_domain()

    # ── styles ────────────────────────────────────────────────────────────────

    def _style(self):
        s = ttk.Style(self)
        s.theme_use("default")
        s.configure("TFrame",         background=BG)
        s.configure("Surface.TFrame", background=SURFACE)
        s.configure("TLabel",         background=BG,      foreground=TEXT,  font=UI)
        s.configure("Muted.TLabel",   background=BG,      foreground=MUTED, font=UIS)
        s.configure("Title.TLabel",   background=BG,      foreground=TEXT,  font=UIT)
        s.configure("TEntry",
                    fieldbackground=SURFACE, foreground=TEXT,
                    insertcolor=TEXT, font=MONO, relief="flat")
        s.configure("Go.TButton",
                    background=RED, foreground=BG,
                    font=UIB, relief="flat", padding=(14, 6))
        s.map("Go.TButton",
              background=[("active", "#ff6b6b"), ("disabled", "#2a2a2a")],
              foreground=[("disabled", "#555")])
        s.configure("Sub.TButton",
                    background=BORDER, foreground=TEXT,
                    font=UIS, relief="flat", padding=(10, 5))
        s.map("Sub.TButton", background=[("active", "#3a424d")])
        s.configure("Ev.Treeview",
                    background=BG, foreground=TEXT,
                    fieldbackground=BG, rowheight=24,
                    font=MONOS, borderwidth=0, relief="flat")
        s.configure("Ev.Treeview.Heading",
                    background=SURFACE, foreground=MUTED,
                    font=("Segoe UI Semibold", 8), relief="flat")
        s.map("Ev.Treeview",
              background=[("selected", SEL)],
              foreground=[("selected", TEXT)])
        s.configure("TSeparator", background=BORDER)
        s.configure("Vertical.TScrollbar",
                    background=SURFACE, troughcolor=BG,
                    arrowcolor=MUTED, relief="flat", borderwidth=0)
        s.configure("Horizontal.TProgressbar",
                    background=RED, troughcolor=SURFACE,
                    borderwidth=0, relief="flat")

    # ── layout ────────────────────────────────────────────────────────────────

    def _build(self):
        # header
        hdr = ttk.Frame(self, padding=(18, 14, 18, 10))
        hdr.pack(fill="x")
        ttk.Label(hdr, text="Bad Password Lookup", style="Title.TLabel").pack(side="left")
        info = ttk.Frame(hdr)
        info.pack(side="right")
        ttk.Label(info, text="Domain:", style="Muted.TLabel").pack(side="left")
        ttk.Label(info, textvariable=self._domain,
                  foreground=GREEN, background=BG, font=MONOS).pack(side="left", padx=(4, 16))
        ttk.Label(info, text="PDC:", style="Muted.TLabel").pack(side="left")
        ttk.Label(info, textvariable=self._pdc,
                  foreground=BLUE, background=BG, font=MONOS).pack(side="left", padx=(4, 0))
        ttk.Separator(self).pack(fill="x")

        # search row
        sr = ttk.Frame(self, padding=(18, 12, 18, 12))
        sr.pack(fill="x")
        ttk.Label(sr, text="Username:", style="Muted.TLabel").grid(row=0, column=0, padx=(0, 8))
        self._ent = ttk.Entry(sr, width=26, font=MONO)
        self._ent.grid(row=0, column=1, ipady=5, padx=(0, 16))
        self._ent.bind("<Return>", lambda _: self._go())
        self._ent.focus()
        ttk.Label(sr, text="DC override:", style="Muted.TLabel").grid(row=0, column=2, padx=(0, 8))
        self._ent_dc = ttk.Entry(sr, width=24, font=MONO)
        self._ent_dc.grid(row=0, column=3, ipady=5, padx=(0, 16))
        self._btn = ttk.Button(sr, text="Lookup", style="Go.TButton", command=self._go)
        self._btn.grid(row=0, column=4, padx=(0, 8))
        ttk.Button(sr, text="Clear", style="Sub.TButton",
                   command=self._clear).grid(row=0, column=5)

        # DC pills
        self._dc_frame = ttk.Frame(self, padding=(18, 0, 18, 8))
        self._dc_frame.pack(fill="x")
        ttk.Separator(self).pack(fill="x")

        # stat cards
        self._cards = ttk.Frame(self, style="Surface.TFrame", padding=(18, 14, 18, 14))
        self._cards.pack(fill="x")
        self._draw_cards()
        ttk.Separator(self).pack(fill="x")

        # table header
        th = ttk.Frame(self, padding=(18, 8, 18, 4))
        th.pack(fill="x")
        ttk.Label(th, text="FAILED AUTH EVENTS",
                  foreground=MUTED, background=BG,
                  font=("Segoe UI Semibold", 8)).pack(side="left")
        self._filter = tk.StringVar(value="All")
        for lbl in ("All", "4740", "4771", "4776", "4625"):
            tk.Radiobutton(th, text=lbl, variable=self._filter, value=lbl,
                           bg=BG, fg=MUTED, selectcolor=SURFACE,
                           activebackground=BG, activeforeground=TEXT,
                           font=("Segoe UI", 8), relief="flat", bd=0,
                           command=self._draw_table).pack(side="left", padx=(12, 0))
        self._ev_count = ttk.Label(th, text="", foreground=MUTED,
                                   background=BG, font=("Segoe UI", 8))
        self._ev_count.pack(side="right")

        # treeview
        tf = ttk.Frame(self, padding=(18, 0, 18, 0))
        tf.pack(fill="both", expand=True)
        cols = ("time", "computer", "ip", "type", "eid", "dc")
        self._tree = ttk.Treeview(tf, columns=cols, show="headings",
                                  style="Ev.Treeview", selectmode="browse")
        self._tree.heading("time",     text="Timestamp",          anchor="w")
        self._tree.heading("computer", text="Source Workstation", anchor="w")
        self._tree.heading("ip",       text="IP Address",         anchor="w")
        self._tree.heading("type",     text="Logon Type",         anchor="w")
        self._tree.heading("eid",      text="Event",              anchor="w")
        self._tree.heading("dc",       text="Reporting DC",       anchor="w")
        self._tree.column("time",    width=155, minwidth=140, anchor="w")
        self._tree.column("computer",width=200, minwidth=150, anchor="w")
        self._tree.column("ip",      width=140, minwidth=110, anchor="w")
        self._tree.column("type",    width=120, minwidth=90,  anchor="w")
        self._tree.column("eid",     width=50,  minwidth=45,  anchor="w")
        self._tree.column("dc",      width=170, minwidth=110, anchor="w")
        self._tree.tag_configure("a",    background=ROW_A)
        self._tree.tag_configure("b",    background=ROW_B)
        self._tree.tag_configure("lock", background="#1a0808", foreground=RED)
        self._tree.tag_configure("ntlm", foreground=YELLOW)
        self._tree.tag_configure("kerb", foreground=BLUE)
        vsb = ttk.Scrollbar(tf, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # status bar
        sb = ttk.Frame(self, style="Surface.TFrame", padding=(14, 5))
        sb.pack(fill="x", side="bottom")
        self._prog = ttk.Progressbar(sb, mode="indeterminate",
                                     style="Horizontal.TProgressbar", length=80)
        self._prog.pack(side="left", padx=(0, 10))
        self._status_lbl = ttk.Label(sb, text="Ready", background=SURFACE,
                                     foreground=MUTED, font=("Segoe UI", 8))
        self._status_lbl.pack(side="left")

    # ── DC pills ──────────────────────────────────────────────────────────────

    def _draw_dc_pills(self):
        for w in self._dc_frame.winfo_children():
            w.destroy()
        if not self._all_dcs:
            return
        ttk.Label(self._dc_frame, text="DCs:", foreground=MUTED,
                  background=BG, font=("Segoe UI", 8)).pack(side="left", padx=(0, 6))
        pdc = self._pdc.get()
        for dc in self._all_dcs:
            is_pdc = dc == pdc
            tk.Label(self._dc_frame, text=dc,
                     bg="#0c2a3a" if is_pdc else SURFACE,
                     fg=BLUE if is_pdc else MUTED,
                     font=("Consolas", 8), padx=6, pady=2).pack(side="left", padx=(0, 4))
            if is_pdc:
                tk.Label(self._dc_frame, text="PDC",
                         bg="#0c2a3a", fg=BLUE,
                         font=("Segoe UI", 7), padx=3).pack(side="left", padx=(0, 6))

    # ── stat cards ────────────────────────────────────────────────────────────

    def _draw_cards(self, d=None):
        for w in self._cards.winfo_children():
            w.destroy()
        if d is None:
            items = [("ACCOUNT","—",TEXT),("LOCK STATUS","—",TEXT),
                     ("BAD PWD COUNT","—",TEXT),("LAST BAD PWD","—",TEXT),
                     ("PASSWORD SET","—",TEXT),("LAST LOGON","—",TEXT)]
        else:
            locked  = d.get("LockedOut", False)
            badcnt  = int(d.get("BadPwdCount") or 0)
            items = [
                ("ACCOUNT",
                 f"{d.get('SamAccountName','?')}" + (f"\n{d.get('DisplayName','')}" if d.get("DisplayName") else ""),
                 BLUE),
                ("LOCK STATUS",  "LOCKED" if locked else "Unlocked",
                 RED if locked else GREEN),
                ("BAD PWD COUNT", str(badcnt),
                 RED if badcnt > 0 else GREEN),
                ("LAST BAD PWD",  d.get("LastBadPwd","Never"),
                 RED if d.get("LastBadPwd","Never") != "Never" else GREEN),
                ("PASSWORD SET",  d.get("PasswordLastSet","N/A"), TEXT),
                ("LAST LOGON",    d.get("LastLogon","N/A"),        TEXT),
            ]
        for i, (lbl, val, col) in enumerate(items):
            f = tk.Frame(self._cards, bg=SURFACE)
            f.grid(row=0, column=i, padx=(0, 20), sticky="nw")
            tk.Label(f, text=lbl, bg=SURFACE, fg=MUTED,
                     font=("Segoe UI Semibold", 7)).pack(anchor="w")
            tk.Label(f, text=val, bg=SURFACE, fg=col,
                     font=MONO, wraplength=170, justify="left").pack(anchor="w")

    # ── domain detection ──────────────────────────────────────────────────────

    def _detect_domain(self):
        self._status("Detecting domain and DCs…")
        path = write_temp_ps(PS_DISCOVER)
        threading.Thread(target=lambda: self._detect_done(*run_ps_file(path, timeout=15)),
                         daemon=True).start()

    def _detect_done(self, ok, out):
        self.after(0, lambda: self._apply_detect(ok, out))

    def _apply_detect(self, ok, out):
        if not ok:
            self._domain.set("not detected")
            self._status(f"Domain detect failed: {out} — use DC override")
            return
        try:
            d = json.loads(out.strip())
            self._domain.set(d.get("DomainName", "?"))
            self._pdc.set(d.get("PDC", ""))
            dcs = d.get("AllDCs", [])
            self._all_dcs = [dcs] if isinstance(dcs, str) else list(dcs)
            self._draw_dc_pills()
            self._status(f"Found {len(self._all_dcs)} DC(s)  ·  PDC: {d.get('PDC')}")
        except Exception as e:
            self._status(f"Domain parse error: {e}")

    # ── lookup ────────────────────────────────────────────────────────────────

    def _go(self):
        if self._busy:
            return
        user = self._ent.get().strip()
        if not user:
            return
        override = self._ent_dc.get().strip()
        dcs = [override] if override else self._all_dcs
        if override and override not in self._all_dcs:
            self._all_dcs = [override] + self._all_dcs
            self._pdc.set(override)
            self._draw_dc_pills()
        if not dcs:
            self._status("No DC found — enter one in DC override")
            return
        self._busy = True
        self._btn.config(state="disabled")
        self._clear(silent=True)
        self._prog.start(12)
        self._status(f"Querying {len(dcs)} DC(s) for '{user}' via WinRM…")
        threading.Thread(target=self._worker, args=(user, dcs), daemon=True).start()

    def _worker(self, user, dcs):
        primary = self._pdc.get() or dcs[0]

        # AD user attributes
        user_path = write_temp_ps(PS_GET_USER)
        ok_u, out_u = run_ps_file(user_path, ["-Username", user, "-DC", primary], timeout=20)

        # Query each DC via Invoke-Command in parallel
        results = {}
        errors  = {}
        lock    = threading.Lock()

        def query(dc):
            ok, out = run_invoke_command(dc, user, timeout=60)
            evts, err = [], ""
            if not ok:
                err = out
            elif out.strip() and out.strip() != "[]":
                try:
                    raw = out.strip()
                    if raw.startswith("{"):
                        raw = f"[{raw}]"
                    parsed = json.loads(raw)
                    evts = parsed if isinstance(parsed, list) else [parsed]
                    # tag each event with which DC reported it
                    for e in evts:
                        e["DC"] = dc
                except Exception as ex:
                    err = f"Parse error: {ex}"
            with lock:
                results[dc] = evts
                if err:
                    errors[dc] = err

        threads = [threading.Thread(target=query, args=(dc,), daemon=True) for dc in dcs]
        for t in threads: t.start()
        for t in threads: t.join(timeout=65)

        # merge & deduplicate
        seen, merged = set(), []
        for dc, evts in results.items():
            for ev in evts:
                key = (ev.get("Time"), ev.get("EventId"), ev.get("Computer"), ev.get("IP"))
                if key not in seen:
                    seen.add(key)
                    merged.append(ev)
        merged.sort(key=lambda e: e.get("Time", ""), reverse=True)

        self.after(0, lambda: self._done(ok_u, out_u, merged, errors, user))

    def _done(self, ok_u, out_u, events, errors, user):
        self._prog.stop()
        self._busy = False
        self._btn.config(state="normal")
        self._events = events

        locked = False
        if ok_u and out_u:
            try:
                d = json.loads(out_u.strip())
                if isinstance(d, list): d = d[0]
                self._draw_cards(d)
                locked = d.get("LockedOut", False)
            except Exception:
                pass
        else:
            self._status(f"AD lookup failed: {out_u}")

        self._draw_table()

        cnt      = len(events)
        has_comp = sum(1 for e in events if e.get("Computer"))

        if errors:
            err_msg = " | ".join(f"{dc}: {msg}" for dc, msg in list(errors.items())[:2])
            self._ev_count.config(
                text=f"{cnt} event(s)  ·  ⚠ {len(errors)} DC error(s)",
                foreground=YELLOW)
            self._status(f"⚠ {err_msg}")
        else:
            self._ev_count.config(
                text=f"{cnt} event(s)  ·  {has_comp} with workstation name",
                foreground=MUTED)
            self._status(
                f"'{user}'  ·  {'LOCKED' if locked else 'Unlocked'}  ·  "
                f"{cnt} event(s)  ·  {has_comp} with computer name")

    # ── table ─────────────────────────────────────────────────────────────────

    def _draw_table(self):
        self._tree.delete(*self._tree.get_children())
        filt     = self._filter.get()
        filtered = [e for e in self._events
                    if filt == "All" or str(e.get("EventId", "")) == filt]
        for i, ev in enumerate(filtered):
            eid  = str(ev.get("EventId", ""))
            comp = ev.get("Computer") or "—"
            ip   = ev.get("IP") or ev.get("IPAddress") or "—"
            lt   = ev.get("LogonType", "")
            if lt.isdigit():
                lt = LOGON_TYPES.get(lt, lt)
            dc   = ev.get("DC", "")
            if eid == "4740":   tag = "lock"
            elif eid == "4776": tag = "ntlm"
            elif eid == "4771": tag = "kerb"
            else:               tag = "a" if i % 2 == 0 else "b"
            self._tree.insert("", "end", iid=str(i),
                              values=(ev.get("Time",""), comp, ip, lt, eid, dc),
                              tags=(tag,))

    # ── helpers ───────────────────────────────────────────────────────────────

    def _clear(self, silent=False):
        self._tree.delete(*self._tree.get_children())
        self._events = []
        self._draw_cards()
        self._ev_count.config(text="")
        if not silent:
            self._status("Cleared")

    def _status(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self._status_lbl.config(text=f"[{ts}]  {msg}")


if __name__ == "__main__":
    BadPwdApp().mainloop()
