# ProxyGate — Production Deployment Guide

This document covers how to run ProxyGate in production, with emphasis on the
**privileged-port problem**: on Linux, binding to ports below 1024 (`:80`, `:443`)
requires either root privileges or the `CAP_NET_BIND_SERVICE` capability.
**Do not run ProxyGate as root.** Use one of the four approaches below.

---

## Default ports

ProxyGate ships with these defaults when no config file exists:

| Service    | Default port | Notes                          |
|------------|-------------|--------------------------------|
| HTTP proxy | 8080        | Change to 80 in config for production |
| HTTPS proxy| 8443        | Change to 443 in config for production |
| Admin UI   | 9090        | localhost-only by default       |

Set `http_port` and `https_port` in your config file to `80`/`443` once you
have a privilege-granting mechanism in place (see below).

---

## Option 1 — systemd with `AmbientCapabilities` (recommended)

The cleanest production setup: the service runs as an unprivileged `proxygate`
user, but systemd grants it `CAP_NET_BIND_SERVICE` at startup so it can bind
port 80 and 443.

### Install

```bash
# 1. Build or download the binary
make build           # or: go build -o bin/proxygate ./cmd/proxygate/
sudo mkdir -p /opt/proxygate
sudo cp bin/proxygate /opt/proxygate/proxygate

# 2. Create a dedicated system user (no login shell, no home dir)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin proxygate

# 3. Create directories and hand ownership to the service user
sudo mkdir -p /opt/proxygate/{data,certs}
sudo chown -R proxygate:proxygate /opt/proxygate

# 4. Install the unit file
sudo cp examples/systemd/proxygate.service /etc/systemd/system/

# 5. Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now proxygate

# 6. Check status
sudo systemctl status proxygate
journalctl -u proxygate -f

# 7. First sign-in: the admin UI is locked until you set a password with the
#    one-time code ProxyGate wrote on first start (it is never logged).
sudo cat /opt/proxygate/data/setup-code
ssh -L 9090:127.0.0.1:9090 <server>   # then open http://127.0.0.1:9090
```

Lost the admin password later? `sudo -u proxygate /opt/proxygate/proxygate passwd --config /opt/proxygate/data/proxygate.json`
sets a new one and signs out every session. See the
[security guide](https://gcis.github.io/proxygate/security.html) for HTTPS on
the admin port, API tokens and the other hardening options.

### Config snippet (`/opt/proxygate/data/proxygate.json`)

```json
{
  "server": {
    "http_port": 80,
    "https_port": 443,
    "admin_port": 9090,
    "admin_host": "127.0.0.1",
    "allowed_networks": ["127.0.0.0/8", "::1/128"]
  }
}
```

The systemd unit file (`examples/systemd/proxygate.service`) already contains:

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

These two lines are all that is needed. The process never has root UID.

---

## Start at boot on macOS and Windows

ProxyGate is a single program, so any service manager can run it. Give it an
absolute `--config` path and set its working directory: certificates are saved
in `certs/` relative to where it starts. Neither macOS nor Windows restricts
ports below 1024, so no capability setup is needed.

### macOS (launchd)

```bash
# Install the binary in its own folder
sudo mkdir -p /usr/local/proxygate/data
sudo cp bin/proxygate /usr/local/proxygate/
sudo chown -R "$USER" /usr/local/proxygate

# Start it at boot, as your user, and restart it if it stops
sudo tee /Library/LaunchDaemons/proxygate.plist >/dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>proxygate</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/proxygate/proxygate</string>
    <string>--config</string>
    <string>/usr/local/proxygate/data/proxygate.json</string>
  </array>
  <key>WorkingDirectory</key><string>/usr/local/proxygate</string>
  <key>UserName</key><string>$USER</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/usr/local/proxygate/proxygate.log</string>
  <key>StandardErrorPath</key><string>/usr/local/proxygate/proxygate.log</string>
</dict>
</plist>
EOF
sudo launchctl bootstrap system /Library/LaunchDaemons/proxygate.plist
```

Logs go to `/usr/local/proxygate/proxygate.log`. To stop it:
`sudo launchctl bootout system /Library/LaunchDaemons/proxygate.plist`.

### Windows (Task Scheduler)

```powershell
# In PowerShell as Administrator, next to the downloaded proxygate.exe
$dir = "C:\ProxyGate"
New-Item -ItemType Directory -Force "$dir\data" | Out-Null
Copy-Item .\proxygate.exe $dir

# Start it at boot and restart it if it stops
$action   = New-ScheduledTaskAction -Execute "$dir\proxygate.exe" `
               -Argument "--config $dir\data\proxygate.json" -WorkingDirectory $dir
$trigger  = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 `
               -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName ProxyGate -Action $action -Trigger $trigger `
               -Settings $settings -User SYSTEM -RunLevel Highest
Start-ScheduledTask -TaskName ProxyGate
```

Task Scheduler does not keep console output; check the task's status with
`Get-ScheduledTask -TaskName ProxyGate | Get-ScheduledTaskInfo`.

## Option 2 — `setcap` (non-systemd setups)

Use this on servers that don't use systemd, or for quick local testing.

```bash
sudo setcap 'cap_net_bind_service=+ep' /opt/proxygate/proxygate
```

**Important**: capabilities are stored on the binary file. Every time you
replace the binary (new build, `cp`, package upgrade), you must re-run the
`setcap` command. A deployment script should include it:

```bash
# Example deploy step
sudo cp bin/proxygate /opt/proxygate/proxygate
sudo setcap 'cap_net_bind_service=+ep' /opt/proxygate/proxygate
sudo systemctl restart proxygate   # or however you manage the process
```

To verify the capability is set:

```bash
getcap /opt/proxygate/proxygate
# proxygate = cap_net_bind_service+ep
```

---

## Option 3 — Reverse proxy in front of ProxyGate

Run ProxyGate on an unprivileged port (e.g. 8080) and have nginx, Caddy, or
Traefik terminate port 80/443 and forward to ProxyGate. This is the right
choice when you also need TLS termination at the edge, or when you already
have an existing nginx/Caddy installation.

### nginx example

```nginx
# /etc/nginx/sites-available/proxygate
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade    $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host       $host;
        proxy_set_header   X-Real-IP  $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/proxygate /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### Caddy example (`Caddyfile`)

```caddyfile
:80 {
    reverse_proxy localhost:8080
}
```

In this mode set `http_port: 8080` (and `https_port: 8443`) in ProxyGate's
config and let the front-end proxy handle TLS.

---

## Option 4 — Container with `NET_BIND_SERVICE` capability

If you run ProxyGate in Docker or a similar container runtime, grant the
capability at container start:

### Docker

```bash
docker run -d \
  --name proxygate \
  --cap-add=NET_BIND_SERVICE \
  -p 80:80 -p 443:443 -p 127.0.0.1:9090:9090 \
  -v /opt/proxygate/data:/data \
  -v /opt/proxygate/certs:/certs \
  ghcr.io/gcis/proxygate:latest \
  --config /data/proxygate.json
```

### Docker Compose

```yaml
services:
  proxygate:
    image: ghcr.io/gcis/proxygate:latest
    cap_add:
      - NET_BIND_SERVICE
    ports:
      - "80:80"
      - "443:443"
      - "127.0.0.1:9090:9090"
    volumes:
      - ./data:/data
      - ./certs:/certs
    command: ["--config", "/data/proxygate.json"]
    restart: unless-stopped
```

Inside a container the admin listener must bind all interfaces to be reachable
through the published port: set `"admin_host": "0.0.0.0"` and add the Docker
bridge range (for example `172.16.0.0/12`) to `allowed_networks`. Publishing it
on `127.0.0.1` as above keeps it off the network. The setup code for the first
sign-in is in `data/setup-code` on the mounted volume.

### Kubernetes

```yaml
securityContext:
  capabilities:
    add:
      - NET_BIND_SERVICE
    drop:
      - ALL
  runAsNonRoot: true
  runAsUser: 65534   # nobody
```

---

## Diagnosing bind failures

If ProxyGate fails to bind a privileged port you will see a log line like:

```
level=ERROR msg="cannot bind privileged port — binary needs CAP_NET_BIND_SERVICE.
Run: sudo setcap 'cap_net_bind_service=+ep' /path/to/proxygate
Or change http_port to 8080 in config. See docs/deployment.md for all options."
port=80
```

Quick diagnosis:

```bash
# Is something else holding the port?
sudo ss -tlnp | grep ':80'

# Does the binary have the capability?
getcap /opt/proxygate/proxygate

# Does the running process have it?
cat /proc/$(pgrep proxygate)/status | grep Cap
```

---

## Upgrading to the version with admin login

The first start of this version changes three things:

1. **The admin UI is locked** until a password is set. Read the one-time code
   from `data/setup-code` and enter it in the admin UI, or run
   `proxygate passwd --config <path>` on the machine. Routes keep serving
   throughout.
2. **Scripts that call the API get `401`.** Create a token for each with
   `proxygate token create <name> --config <path>` and send it as
   `Authorization: Bearer <token>`. `/healthz` stays public, so liveness probes
   need no change.
3. **Stored credentials are encrypted.** Without `PROXYGATE_CONFIG_KEY`, the
   GoDaddy key, secret and ACME email are encrypted with a new
   `data/secret.key` (mode 0600). Back that file up with the config.

### Rolling back

Earlier versions refuse to start on an encrypted config unless they are given
the key. Either restore the config backup taken before the upgrade, or start
the older binary with the generated key:

```bash
PROXYGATE_CONFIG_KEY=$(cat /opt/proxygate/data/secret.key) /opt/proxygate/proxygate --config /opt/proxygate/data/proxygate.json
```

Older versions ignore the new `security` section and the auth files, so they
can stay in place.

---

## Production readiness checklist

| Feature | Status | Notes |
|---------|--------|-------|
| SIGTERM graceful shutdown | ✅ | 30-second drain window |
| Structured logging to stdout | ✅ | Compatible with journald / log shippers |
| `--version` flag | ✅ | Prints build version and exits |
| `/healthz` liveness endpoint | ✅ | Returns `{"status":"ok"}` on admin port |
| Default port non-privileged (8080) | ✅ | Only needs CAP when config sets 80 |
| Actionable bind-error message | ✅ | Points to this doc |
| systemd unit with AmbientCapabilities | ✅ | `examples/systemd/proxygate.service` |
| Admin UI localhost-only by default | ✅ | `admin_host: "127.0.0.1"` |
| No runtime `setuid`/root assumption | ✅ | Capabilities only |
| Admin UI login | ✅ | Password set on first start with a one-time code; `proxygate passwd` to recover |
| API tokens for scripts | ✅ | `proxygate token create`; only hashes are stored |
| HTTPS on the admin port | ✅ | Opt-in: `security.admin_tls` (own certificate or generated self-signed) |
| Stored credentials encrypted | ✅ | AES-256-GCM by default; key from `PROXYGATE_CONFIG_KEY` or `data/secret.key` |
| Two-factor login, audit log | ❌ | On the roadmap in the security guide |
| Automatic certificate renewal | ✅ | Daily check; renews 30 days before expiry with hot-reload |
