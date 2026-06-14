# Endpoint Agent

An **optional**, admin-installed agent that runs **on a destination host** and
reports a local inventory back to the Threat Intelligence Briefing Agent. It
complements the app's agentless network scanning by collecting what a remote
scan can't see: installed packages and exact versions, running services, local
listening ports, local users, and OS patch level.

- **Read-only.** It collects and reports; it never changes host state and never
  accepts remote commands.
- **No dependencies.** Pure Python 3 standard library (Linux). On Windows the
  *true-service* installer adds `pywin32`; the *Scheduled Task* installer needs
  nothing extra.
- **Opt-in.** A host is only ever covered if an admin installs the agent there.

## 1. Enroll

In the app: **Settings → Endpoint agents** → copy the **enrollment token** and
your server URL. Each host's `agent.config.json` carries that token; the server
rejects any check-in without it.

## 2. Install (Linux — systemd)

Copy the `endpoint/` folder to the host, then:

```bash
sudo endpoint/packaging/linux/install.sh
sudo nano /etc/sec-endpoint/agent.config.json     # set server_url + token
sudo systemctl start sec-endpoint-agent.service
journalctl -u sec-endpoint-agent -f               # watch it check in
```

## 3. Install (Windows — service)

Copy the `endpoint\` folder to the host, open an **elevated PowerShell**:

```powershell
# Option A — true Windows service (adds pywin32):
.\endpoint\packaging\windows\install-service.ps1
notepad C:\ProgramData\sec-endpoint\agent.config.json   # set server_url + token
python "C:\Program Files\sec-endpoint\win_service.py" start

# Option B — no dependencies (Scheduled Task, runs as SYSTEM):
.\endpoint\packaging\windows\install-task.ps1
notepad C:\ProgramData\sec-endpoint\agent.config.json
Start-ScheduledTask -TaskName SecEndpointAgent
```

## Test without installing

```bash
python -m endpoint.agent --print                      # show what it would send
python -m endpoint.agent --config ./agent.config.json --once   # one check-in
```

## Config (`agent.config.json`)

| Field | Meaning |
|-------|---------|
| `server_url` | Base URL of the app, e.g. `https://intel.company.com:5000` |
| `token` | Enrollment token from Settings → Endpoint agents |
| `interval_seconds` | Check-in interval in loop/service mode (min 60) |
| `verify_tls` | `true` to verify the server cert; `false` for self-signed labs only |
| `ca_bundle` | Optional path to a CA file for a private/internal CA |
| `tags` | Optional labels stored with the host (e.g. `["production"]`) |

## Security notes

- Always run the server over **HTTPS** in production — the token and inventory
  travel in the request. `verify_tls: false` is for lab/self-signed servers only.
- Treat the enrollment token like a secret; rotate it from the UI if exposed
  (existing agents then need the new token).
- The agent runs as root/SYSTEM by default for a complete inventory; see
  `secagent.service` for a least-privilege (`User=`) variant.
