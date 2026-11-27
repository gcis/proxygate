# Active Routes Inventory

This file documents the routes provisioned on the live ProxyGate instance on
this host. The runtime config (`data/proxygate.json`) is gitignored because it
is machine-local state; this document is the durable record of WHAT is
deployed, WHERE it points, and WHO/WHEN added it.

Keep this file in sync when adding or removing routes via the admin API.

| Domain              | Upstream             | TLS / Cert                            | Added       | Notes                                              |
|---------------------|----------------------|---------------------------------------|-------------|----------------------------------------------------|
| simply.gcsm.io      | 127.0.0.1:55173      | Let's Encrypt (auto_cert)             | 2026-04-27  | Simple-Claw frontend (Vite dev server)             |
| simply.gcsm.io/mqtt | 127.0.0.1:59001      | Cert shared with simply.gcsm.io       | 2026-04-27  | Mosquitto WebSocket; `path_prefix: /mqtt`          |
| health.s.gcsm.io    | 127.0.0.1:55174      | Let's Encrypt (auto_cert)             | 2026-04-30  | Simple-Claw recovery UI                            |
| health.gcsm.io      | 127.0.0.1:45723      | Let's Encrypt (auto_cert, DNS-01)     | 2026-05-18  | Vitalog (`~/projects/vitalog`, `node app/server.js`) |
| casa.gcsm.io        | 127.0.0.1:47080      | Let's Encrypt (auto_cert, DNS-01)     | 2026-11-14  | Casa (`~/projects/casa`, Next.js)                  |
| ext.casa.gcsm.io    | 127.0.0.1:47080      | Let's Encrypt (auto_cert, DNS-01)     | 2026-11-15  | Same Casa upstream as casa.gcsm.io                 |

## Conventions

- **Targets bind on all interfaces.** Confirm `ss -tlnp | grep <port>` shows
  `*:<port>` or `0.0.0.0:<port>` — never `127.0.0.1:<port>` only — so
  ProxyGate can reach the upstream from any local interface.
- **TLS certs** are issued via Let's Encrypt DNS-01 challenge through the
  GoDaddy API integration (`POST /api/acme/request` then `POST /api/acme/complete`
  with `auto_dns: true`). Certs land in `certs/<domain>.{pem,key}`.
- **Public DNS** is not automatic for new domains. After adding a route, decide
  whether the domain should be public (add A record via GoDaddy) or
  Tailscale-only (add to `/etc/hosts` on the client devices that need it).
  The existing `*.gcsm.io` routes are Tailscale-only via `/etc/hosts → 100.77.19.9`.

## Admin access

The admin API requires authentication (see `docs/security.html`). Scripts on
this host use an API token kept in a file readable only by the service user;
create one with `./bin/proxygate token create <name> --config data/proxygate.json`
and store its output in a 0600 file. To recover the admin password, run
`./bin/proxygate passwd --config data/proxygate.json` from `~/projects/proxygate`.

Stored GoDaddy credentials are encrypted with `data/secret.key`. Back it up
together with `data/proxygate.json`: without it, ProxyGate keeps serving routes
but cannot renew certificates until the credentials are entered again.

## Adding a new route — runbook

```bash
cd ~/projects/proxygate
AUTH="Authorization: Bearer $(cat <path to your token file>)"

# 1. Add the route without TLS (proxygate persists to data/proxygate.json)
curl -X POST http://localhost:9090/api/routes -H "$AUTH" \
  -H 'Content-Type: application/json' \
  -d '{
        "name": "...",
        "domain": "...",
        "target_host": "127.0.0.1",
        "target_port": <PORT>,
        "enabled": true
      }'

# 2. Request the cert (DNS-01)
curl -X POST http://localhost:9090/api/acme/request -H "$AUTH" \
  -H 'Content-Type: application/json' \
  -d '{"domain":"<domain>"}'

# 3. Complete the challenge: publishes the GoDaddy TXT record, waits ~30s,
#    then switches TLS on for every route on <domain> (cert_file, key_file,
#    auto_cert). Takes a couple of minutes.
curl -X POST http://localhost:9090/api/acme/complete -H "$AUTH" \
  -H 'Content-Type: application/json' \
  -d '{"domain":"<domain>","auto_dns":true}'

# 4. Verify end-to-end
curl --resolve <domain>:443:127.0.0.1 https://<domain>/

# 5. Update this file with the new row.
```

Turning TLS on before the certificate exists is refused: the proxy would
redirect visitors to HTTPS with no certificate to serve.
