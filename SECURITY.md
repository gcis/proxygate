# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/gcis/proxygate/security/advisories/new)
rather than a public issue.

## How ProxyGate is secured

The admin UI requires a login, stored credentials are encrypted by default,
and further hardening (HTTPS for the admin UI, stricter login rules, session
lifetimes) is available through the `security` section of the config.

The full guide, including password recovery with `proxygate passwd`, API
tokens, advanced settings and the roadmap, is in
[docs/security.html](https://gcis.github.io/proxygate/security.html)
(also served by ProxyGate itself at `/docs/security.html`).
