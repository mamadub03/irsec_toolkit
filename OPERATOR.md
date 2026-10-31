# IRSeC 2026 — Operator Quick Start

Run Windows scripts in **Administrator PowerShell** and Linux scripts with `sudo` where required. Run commands from the directory containing the scripts.

## Windows

### 1. Backdoor Account Detection
**Script:** `Find-BackdoorAccounts.ps1`

Find suspicious or unauthorized accounts, including privileged users.

```powershell
.\Find-BackdoorAccounts.ps1
```

### 2. Domain Password Rotation
**Script:** `Rotate-DomainPasswords.ps1`

Rotate domain account passwords on `pitwall` after confirming which accounts are authorized.

```powershell
.\Rotate-DomainPasswords.ps1
```

### 3. Local Password Rotation
**Script:** `Rotate-LocalPasswords.ps1`

Rotate local Windows account passwords on the current machine.

```powershell
.\Rotate-LocalPasswords.ps1
```

### 4. Windows Service Health
**Script:** `Windows-ServiceHealth.ps1`

Quickly verify scored services and network connectivity. Use when a service stops scoring.

```powershell
.\Windows-ServiceHealth.ps1
.\Windows-ServiceHealth.ps1 -Role safetycar
.\Windows-ServiceHealth.ps1 -Role teamradio -RemoteTarget 10.X.1.2
```

- `-Role`: Selects the machine profile.
- `-RemoteTarget`: Tests a remote host.
- `-TimeoutSeconds`: Changes the connection timeout.

### 5. Windows Deep Diagnostics
**Script:** `Windows-DeepDiagnostics.ps1`

Investigate service failures, firewall restrictions, open ports, and relevant event logs.

```powershell
.\Windows-DeepDiagnostics.ps1
.\Windows-DeepDiagnostics.ps1 -Role safetycar -RecentMinutes 60
.\Windows-DeepDiagnostics.ps1 -Role pitwall
```

- `-Role`: Selects the machine.
- `-RecentMinutes`: Controls the event-log lookback period.

## Linux

### 6. Backdoor Account Detection
**Script:** `Find-BackdoorAccounts.sh`

Identify suspicious Linux users and unexpected privileges.

```bash
sudo bash Find-BackdoorAccounts.sh
```

### 7. Local Password Rotation
**Script:** `Rotate-LocalPasswords.sh`

Rotate local Linux account passwords.

```bash
sudo bash Rotate-LocalPasswords.sh
```

### 8. Linux Service Health
**Script:** `Linux-ServiceHealth.sh`

Quickly assess scored Linux services when troubleshooting uptime failures.

```bash
sudo bash Linux-ServiceHealth.sh
sudo bash Linux-ServiceHealth.sh pitlane
sudo bash Linux-ServiceHealth.sh grandstand /opt/irc
```

### 9. Linux Deep Diagnostics
**Script:** `Linux-DeepDiagnostics.sh`

Investigate SSH, FTP, Docker/IRC, MariaDB, firewall, and network issues.

```bash
sudo bash Linux-DeepDiagnostics.sh
sudo bash Linux-DeepDiagnostics.sh garage
sudo bash Linux-DeepDiagnostics.sh scrutineering
sudo bash Linux-DeepDiagnostics.sh grandstand /opt/irc
```

The first argument selects the host role. The optional second argument provides the Docker Compose directory.

---

**Note:** The command-line options for `-Local` and `-Domain` have not been verified against the account scripts; they are not included here. Likewise, process sniffer, persistence scanner, firewall viewer, and ConfigGuard commands are omitted pending their exact syntax.
