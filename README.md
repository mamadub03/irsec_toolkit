# IRSeC 2026 Blue Team Toolkit — README

**Scope:** 17 core scripts (W01–W07, W09–W10; L01–L06, L08–L09) and optional PF01. **W08 and L07 were removed** because W06/L05 already inspect processes and connections.

**Status:** These are **drafts, not verified competition-ready tools**. Run in isolated lab VMs and fix observed errors before relying on them. Exact service paths, account mappings, and ports depend on the deployed machines.

## 1. What the toolkit is for

Use these scripts to rotate *approved* passwords, identify unfamiliar accounts, protect known-good configurations, check scored services, investigate connections and suspicious processes, review firewall rules, find persistence, and perform deeper service-specific diagnostics.

The general sequence is **check → investigate → decide → manually fix → verify**. Nothing should be considered malicious from a single indicator such as an unusual username, IP, folder, or port.

## 2. Safety rules — read before running

- Use only on authorized competition/lab hosts and only when competition rules allow.
- Preserve `whiteteam` access, Datadog identities and agents (`dd-agent`, `ddagentuser`), Wazuh/syslog, NetBird connectivity and scoring dependencies. Never rotate `krbtgt` or the domain controller's DSRM credentials.
- Don't disable unknown accounts or kill unknown processes just because a script flags them. Confirm their role and whether they support scored services.
- W01/W02/L01 **change passwords**; W04/L03 **write backups** and optionally **restore configuration files**; W06/L05 can **terminate a process only after explicit selection and confirmation**. All other core tools described here are inspection-only.
- W06/L05 **do not delete files or block IPs**. File removal and firewall changes are operator actions.
- No script should automatically mass-block IP ranges. Do not interfere with organizers' required infrastructure or change the scored topology.
- Backups may contain sensitive settings/credentials. Restrict access; do not commit them to GitHub or export competition artifacts.
- A local TCP success does **not** prove Hermes can reach or authenticate to the service over pfSense.

## 3. Prepare to run

### Windows

On an authorized Windows host, open **Windows PowerShell 5.1 as Administrator**, navigate to the script directory, and run the relevant `.ps1` script. Some checks may work unprivileged, but event logs, service details and firewall configuration may require elevation. If scripts are blocked by execution policy, use the competition-approved signed-script or execution-policy procedure; don't indiscriminately weaken machine policy.

### Linux

Place `.sh` files on the appropriate Linux host. Run scripts as `sudo bash <script>.sh ...` when they inspect privileged configuration, process ownership or logs. Tools used across scripts include `systemctl`, `ss`, `ip`, `journalctl`, `nft`/`iptables`, and service-specific utilities. If a tool is absent, output may be incomplete.

### pfSense

PF01 is for an authorized **pfSense/FreeBSD shell**, not a general Linux host. It reads current configuration/state and logs; no firewall changes.

## 4. Scripts at a glance

| ID | Script | Where | Primary use | Changes machine? |
|---|---|---|---|---|
| W01 | `Rotate-DomainPassword.ps1` | `pitwall` (AD DC) | Rotate approved domain account passwords | **Yes — passwords** |
| W02 | `Rotate-LocalPassword.ps1` | Windows member/workstation | Rotate approved local passwords | **Yes — passwords** |
| L01 | `Rotate-LocalPassword.sh` | Linux | Rotate approved local passwords | **Yes — passwords** |
| W03 | `WindowsFind-Backdoor.ps1` | Windows/AD | Compare current accounts to approved/protected list | No |
| L02 | `LinuxFind-Backdoor.sh` | Linux | Flag unapproved local accounts, show status | No |
| W04 | `Windows-ConfigGuard.ps1` | `safetycar`, `stewards` | Telnet/IIS config backup, diff, selective restore | **Backup/restore write files** |
| L03 | `Linux-ConfigGuard.sh` | Linux service hosts | SSH/FTP/MariaDB/Docker config backup, diff, restore | **Backup/restore write files** |
| W05 | `Windows-ServiceHealth.ps1` | Windows | Quick **local** service, listener, TCP/WSMan, network checks | No; brief local probes |
| L04 | `Linux-ServiceHealth.sh` | Linux | Quick **local** daemon, port, TCP, network checks | No; brief local probes |
| W06 | `Process-SnifferWindows.ps1` | Windows | Sessions, network PIDs/IPs, auth events, manual PID kill | **Only if Kill confirmed** |
| L05 | `Process-SnifferLinux.sh` | Linux | Sessions, network PIDs/IPs, SSH logs, manual PID termination | **Only if Kill confirmed** |
| W07 | `Windows-FirewallViewer.ps1` | Windows | Active allow/block rules, profile, port/IP filters | No |
| L06 | `Linux-Firewall.sh` | Linux | UFW, firewalld, nftables, iptables | No |
| W09 | `Windows-Persistence.ps1` | Windows | Tasks, services, autoruns, startup folders | No |
| L08 | `Linux-Persistence.sh` | Linux | Cron, systemd, startup, SSH authorized keys | No |
| W10 | `Windows-DeepDiagnostics.ps1`| Windows | Detailed AD/DNS, WinRM, Telnet/ICMP, SMB, IIS investigation | No; local probes |
| L09 | `Linux-DeepDiagnostics.sh` | Linux | Detailed SSH, FTP, Docker/IRC, MariaDB, ICMP investigation | No; local probes |
| PF01 *(optional)* | `pfSense-DefensiveSnapshot.sh` | `barrier` | pfSense interfaces, routing, GUI listeners, pf rules, state, logs | No |

> **Filename note:** The filenames in this README now match the VS Code screenshot you provided. `Windows-DeepDiagnostics` appears **without `.ps1`** in the screenshot. For commands below, rename it to `Windows-DeepDiagnostics.ps1` if it really has no extension. The other filenames below follow your screenshot, including the singular `Rotate-DomainPassword.ps1`. PF01 is optional and not present in your screenshot.


### Actual repository layout

Run commands from inside the relevant folder: `irsec_toolkit/windows/` or `irsec_toolkit/linux/`. If starting in the repository root, first use `cd windows` or `cd linux` after entering `irsec_toolkit`. For example:

```powershell
cd irsec_toolkit\windows
.\Windows-ServiceHealth.ps1 -Role safetycar
```

```bash
cd irsec_toolkit/linux
sudo bash Linux-ServiceHealth.sh pitlane
```

Your screenshot does not show PF01 in either folder. Its README section is optional, not an assertion that the file already exists in your repository.

## 5. Exact commands and what each does

### W01 — AD domain password rotation (`pitwall`)

```powershell
.\Rotate-DomainPassword.ps1
```

Interactive menu: rotate one, selected, all eligible, or regular approved domain users. Requires confirmation; puts the account currently running the script **last** if selected. Does not rotate `krbtgt`, `whiteteam`, built-ins, or detected protected service accounts. **Changes account passwords.** Confirm service dependencies and retain working access before use. Do not run W02 on a domain controller.

### W02 — Windows local password rotation

```powershell
.\Rotate-LocalPassword.ps1
```

Runs on Windows clients and member servers, **not the domain controller**. Rotates eligible local accounts from the approved list. Can change one, selected, or all; your current eligible local account is processed last. **Changes passwords** and can disrupt applications using those credentials if dependencies are not detected.

### L01 — Linux local password rotation

```bash
sudo bash Rotate-LocalPassword.sh
```

Interactive rotation of approved Linux local account passwords. Does not intentionally touch root, `whiteteam`, monitoring accounts, or known systemd service users. **Changes passwords**; review dependencies first.

### W03 — Windows / AD account audit

```powershell
# On pitwall: domain inventory
.\WindowsFind-Backdoor.ps1 -Scope Domain

# On Windows member/workstation: local inventory
.\WindowsFind-Backdoor.ps1 -Scope Local
```

Shows present accounts, whether enabled, and classification (`APPROVED`, `PROTECTED`, `INVESTIGATE`). **No baseline is needed**, and it does not disable accounts. An unfamiliar username is only a lead, not proof of compromise. Audit account privileges separately if needed.

### L02 — Linux account audit

```bash
sudo bash LinuxFind-Backdoor.sh
```

Lists `/etc/passwd` local users, UIDs, basic login-shell indicators, approved/protected classifications and unexpected accounts. **No baseline** and no account changes. `NO_LOGIN` is not the same thing as a verified locked password.

### W04 — Windows Telnet/IIS configuration guard

```powershell
# On safetycar
.\Windows-ConfigGuard.ps1 -Service Telnet -Action Backup
.\Windows-ConfigGuard.ps1 -Service Telnet -Action Compare
.\Windows-ConfigGuard.ps1 -Service Telnet -Action Restore

# On stewards
.\Windows-ConfigGuard.ps1 -Service IIS -Action Backup
.\Windows-ConfigGuard.ps1 -Service IIS -Action Compare
.\Windows-ConfigGuard.ps1 -Service IIS -Action Restore
```

`Backup` copies discovered configuration files; `Compare` reports changed/missing/added files and line-level differences where possible; `Restore` requires choosing a specific saved file and typing confirmation. No automatic service restart. **The original backup may already be tampered with**; validate it before trusting it. Test ACL and site path behavior in lab. Does not restore AD DS, SMB or WinRM settings.

### L03 — Linux service configuration guard

```bash
# pitlane (SSH)
sudo bash Linux-ConfigGuard.sh ssh backup
sudo bash Linux-ConfigGuard.sh ssh compare
sudo bash Linux-ConfigGuard.sh ssh restore

# garage (FTP)
sudo bash Linux-ConfigGuard.sh ftp backup
sudo bash Linux-ConfigGuard.sh ftp compare
sudo bash Linux-ConfigGuard.sh ftp restore

# scrutineering (MariaDB)
sudo bash Linux-ConfigGuard.sh mariadb backup
sudo bash Linux-ConfigGuard.sh mariadb compare
sudo bash Linux-ConfigGuard.sh mariadb restore

# grandstand (Docker Compose; substitute actual project directory)
sudo bash Linux-ConfigGuard.sh docker backup /opt/irc
sudo bash Linux-ConfigGuard.sh docker compare /opt/irc
sudo bash Linux-ConfigGuard.sh docker restore /opt/irc
```

Backup, comparison and selective restoration of tracked service config files. This is **not** a MariaDB data backup, Docker volume backup, or exhaustive config discovery. It does not restart services after restore.

### W05 — Windows quick local service health

```powershell
# Automatically uses the local hostname when it matches an IRSeC role
.\Windows-ServiceHealth.ps1

# Lab/profile override (still checks the machine you run it on)
.\Windows-ServiceHealth.ps1 -Role safetycar
.\Windows-ServiceHealth.ps1 -Role teamradio
.\Windows-ServiceHealth.ps1 -Role pitwall
.\Windows-ServiceHealth.ps1 -Role transporters
.\Windows-ServiceHealth.ps1 -Role stewards
```

Checks local network configuration, firewall overview, service state, expected TCP listeners and selected application checks. For example: WinRM local WSMan response; Telnet port 23 local TCP; AD/DNS services and DNS resolution; SMB service/shares; IIS sites and listeners. Prints **PASS / WARN / FAIL**, details, and suggested investigations. **Use the original local-only W05 version**, not the later optional remote-probe revision.

### L04 — Linux quick local service health

```bash
sudo bash Linux-ServiceHealth.sh
sudo bash Linux-ServiceHealth.sh pitlane
sudo bash Linux-ServiceHealth.sh garage
sudo bash Linux-ServiceHealth.sh grandstand /opt/irc
sudo bash Linux-ServiceHealth.sh scrutineering
```

Checks network IP/default route, local firewall overview, daemon/systemd status, expected listener, local TCP connectivity, and selected application checks (SSH syntax, Docker containers, MariaDB ping). **Use the original local-only L04 version** with positional host role and optional Compose directory. It does not verify access through pfSense.

### W06 — Windows session and process investigation

```powershell
.\Process-SnifferWindows.ps1
.\Process-SnifferWindows.ps1 -Minutes 120 -FailureThreshold 3
```

Interactive menu: **1** live connections/processes, **2** inspect PID including owner/parent/path/command/hash/connections, **3** user sessions + recent auth-source IPs, **4** select PID for **manual kill with exact confirmation**, **5** refresh all, **Q** quit. **No automatic kill, executable deletion or firewall block.** A process is not confirmed malicious just because it is unfamiliar.

### L05 — Linux session and process investigation

```bash
sudo bash Process-SnifferLinux.sh
sudo bash Process-SnifferLinux.sh 120
```

Interactive menu: **1** TCP connections, **2** inspect PID (owner, tree, executable, command line, hash, sockets), **3** sessions/SSH auth IPs, **4** request SIGTERM on selected PID **after confirmation**, **5** refresh all, **Q** quit. Does not automatically delete files or block IPs. Termination may not succeed if a process ignores SIGTERM; verify manually.

### W07 — Windows firewall viewer

```powershell
# All enabled rules (no port needed)
.\Windows-FirewallViewer.ps1

# Rules potentially affecting Telnet / WinRM / SMB
.\Windows-FirewallViewer.ps1 -Port 23
.\Windows-FirewallViewer.ps1 -Port 5985
.\Windows-FirewallViewer.ps1 -Port 445

# Include disabled rules / limit direction
.\Windows-FirewallViewer.ps1 -ShowAll
.\Windows-FirewallViewer.ps1 -Port 23 -Direction Inbound
```

Shows active firewall profiles, allow/block rules, port/protocol restrictions, source/destination IP restrictions, application/service associations, and a matching TCP listener. **Does not yet read actual dropped-packet logs**, even though a block rule may be visible. A matching rule is not a complete effective-access decision.

### L06 — Linux firewall viewer

```bash
# All available firewall configurations (no port needed)
sudo bash Linux-Firewall.sh

# Focus output on a service/IP
sudo bash Linux-Firewall.sh --port 22
sudo bash Linux-Firewall.sh --port 21
sudo bash Linux-Firewall.sh --port 3306
sudo bash Linux-Firewall.sh --ip 10.1.1.45
```

Shows UFW, firewalld, nftables, and iptables rules/policies plus interface/route details. Filtering is a **text search**, not an effective-firewall simulator. **It does not yet summarize historical dropped-packet logs**. No rules changed.

### W09 — Windows persistence scanner

```powershell
# Highlight entries with suspicious indicators
.\Windows-Persistence.ps1

# Show all discovered entries
.\Windows-Persistence.ps1 -All
```

Investigates scheduled tasks, Windows services, Run/RunOnce registry entries, and startup folders. Shows execution commands, users, locations and unusual path/command indicators. **Read-only; nothing disabled or deleted.** Coverage is not exhaustive.

### L08 — Linux persistence scanner

```bash
# Flag entries matching suspicious indicators
sudo bash Linux-Persistence.sh

# Show full collected cron/systemd/startup entries
sudo bash Linux-Persistence.sh --all
```

Investigates system/user cron, systemd service/timer units, selected startup scripts, and SSH authorized-key paths/fingerprints. **Read-only; nothing deleted or disabled.** SSH key entries merit manual comparison with approved administrators.

### W10 — Windows deep service diagnostics

```powershell
.\Windows-DeepDiagnostics.ps1
.\Windows-DeepDiagnostics.ps1 -Role safetycar
.\Windows-DeepDiagnostics.ps1 -Role teamradio
.\Windows-DeepDiagnostics.ps1 -Role pitwall
.\Windows-DeepDiagnostics.ps1 -Role transporters
.\Windows-DeepDiagnostics.ps1 -Role stewards
```

Use when W05 reports a failure or the scoring result disagrees with basic checks. Service-specific detail: Telnet initial prompt and ICMP firewall rules; WinRM listeners/authentication; AD/DNS records and services; SMB configuration; IIS websites/app pools and HTTP errors. Read-only local investigation and suggestions, **not proof of remote Hermes connectivity**. The exact W10 behavior should be cross-checked against your saved script before competition.

### L09 — Linux deep service diagnostics

```bash
sudo bash Linux-DeepDiagnostics.sh pitlane
sudo bash Linux-DeepDiagnostics.sh garage
sudo bash Linux-DeepDiagnostics.sh grandstand /opt/irc
sudo bash Linux-DeepDiagnostics.sh scrutineering
```

Service-specific detail: kernel ICMP echo-ignore setting and firewall excerpts on each Linux host; SSH effective config, syntax/banner; FTP greeting/passive-range settings; Docker containers and Compose project status; MariaDB bind/port config, server ping, optional local `SELECT 1` with existing credentials. It does not modify settings and **cannot prove remote scoring access**. For `grandstand`, substitute the actual Compose directory.

### PF01 — Optional pfSense diagnostic snapshot (`barrier`)

```sh
sh pfSense-DefensiveSnapshot.sh
```

Run only on the authorized pfSense shell. Displays interfaces, routes, pf rules/NAT, firewall state counters, GUI/SSH listeners and selected logs. **Does not modify firewall rules, revoke sessions or guarantee detection of GUI session reuse.** Check path/name against your saved PF01 file.

## 6. Competition workflow (who runs what)

1. **Immediately check uptime:** W05/L04 on each service host. If a check fails or Hermes disagrees, run W10/L09 for that host.
2. **Preserve access:** verify current authorized admin access and crucial services before password changes. Coordinate W01 for domain accounts and W02/L01 for local accounts; leave protected identities alone.
3. **Find obvious footholds:** W03/L02 to identify unfamiliar accounts; W06/L05 for suspicious sessions, processes and IPs.
4. **Preserve verified configs:** use W04/L03 `Backup` only after reviewing the current state. If tampering occurs, `Compare`; `Restore` only for a chosen verified file.
5. **Investigate blocked traffic:** W07/L06 for host firewall, PF01 for pfSense; manually confirm routing and scoring connectivity before editing rules.
6. **Investigate re-entry mechanisms:** W09/L08 for tasks, cron/systemd, startup items, keys and unusual service commands.
7. **After every manual change:** rerun W05/L04 and the affected W10/L09 check. Verify the scored service from an authorized client when possible.

These are **parallel workstreams** for your team, not mandatory strictly sequential steps. Never prioritize an account or firewall change over keeping the scoring environment available.

## 7. Quick troubleshooting examples

| Symptom | First script | Then | What to investigate manually |
|---|---|---|---|
| Telnet port 23 not listening / no prompt | W05 `safetycar` | W10; W04 `Compare` | inetd/Telnet config, child process, firewall, real login prompt |
| WinRM down / WSMan failure | W05 `teamradio` | W10; W07 `-Port 5985` | listener, service logs, profile, allowed sources |
| Windows ping fails | W05 `safetycar` | W10; W07 | ICMPv4 allow/block rule, profile, remote network path |
| SSH unavailable | L04 `pitlane` | L09; L06 `--port 22` | daemon, syntax, bind address, firewall |
| FTP login/data transfer fails | L04 `garage` | L09; L06 `--port 21` | greeting, auth, passive data range |
| MariaDB TCP 3306 works but scoring fails | L04 `scrutineering` | L09; L06 `--port 3306` | bind address, SQL authentication, grants and expected query |
| IIS is running but website fails | W05 `stewards` | W10; W04 `Compare` | site/app pool, bindings, config, HTTP status |
| IRC/bot appears offline | L04 `grandstand` | L09; L03 `Compare` | actual Compose directory, container logs, ports, bot state |
| Unknown connected remote IP | W06/L05 | W07/L06 | PID, process owner, executable path, auth evidence |
| Suspicious process keeps returning | W06/L05 | W09/L08 | scheduled task, service, cron, systemd, autorun |
| Everything works locally but not to scorer | W05/L04 | W07/L06 + PF01 | remote path, router rules, correct destination, scoring-specific auth |

## 8. Testing before IRSeC

- Test **read-only scanners first** on isolated Windows and Linux VMs: W05/L04, W10/L09, W07/L06, W03/L02, W09/L08.
- Deliberately create a harmless known failure in the lab (stopped service, test firewall rule, edited test config), rerun the diagnostic, and verify the report matches reality.
- For W06/L05, launch a disposable test process, inspect its PID/path/network fields, and confirm termination affects only the chosen test process. Do **not** test kill against critical services.
- For W01/W02/L01, create test users and snapshot your VMs; confirm approved-user selection, protected-user exclusions, password changes and current-user-last behavior.
- For W04/L03, back up a reviewed test configuration, make a harmless modification, compare, restore a selected file, then verify permissions and service behavior.
- Test on the OS versions most like the packet: Windows Server 2025/2022, Windows 10/11, Debian 12, Ubuntu 22.04/24.04, Rocky Linux 9, pfSense 2.7.2 where possible.
- Record script bugs and correct the **full saved script** before competition day. Syntax checks alone are insufficient.

## 9. Known limitations

- No local script can conclusively establish remote Hermes/pfSense reachability; test from another authorized host when needed.
- Firewall viewers show rules, not a definitive packet-decision calculation; **dropped-packet log summaries are not yet implemented**.
- W05/L04 are **local-only** quick checks. W10/L09 provide the deeper explanations; both are still drafts.
- Some scripts use conventional service ports, paths and user allowlists that must match the actual competition machines.
- Password rotators' service-dependency detection is not exhaustive. Do not rotate system/service secrets casually.
- W06/L05 termination is manual/confirmed; executable deletion and source-IP blocking remain entirely manual.
- Account audits and persistence scans flag indicators, not proof of compromise.
- The Windows and Linux scripts have **not been validated together on the actual IRSeC infrastructure**.

**Final reminder:** Prioritize availability, preserve competition-protected identities and monitoring, and verify every response action against the scoring requirements.
