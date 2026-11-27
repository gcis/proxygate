// ProxyGate Console Client — zero inline handlers, strict XSS-safe rendering

let ws = null;
let config = null;
let routes = [];
let challenges = [];
let allDomains = [];
let currentDnsRecords = [];
let eventHistory = [];

let routeFilter = 'all';
let routeSearch = '';
let dashboardSearch = '';
let eventFilter = '';
let domainSearch = '';
let includeInactiveDomains = false;
let selectedDomain = '';
let dnsTypeFilter = 'ALL';
let dnsRecordSearch = '';

let confirmResolver = null;

// Authentication state. The app only loads data once signed in.
let authenticated = false;
let appStarted = false;

const PAGE_TITLES = {
    dashboard: 'Dashboard',
    routes: 'Proxy Routes',
    certificates: 'Certificates',
    dns: 'DNS Management',
    settings: 'Settings',
};

// --- Utilities ---
function el(tag, attrs = {}, text = null) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
        if (k === 'className') {
            node.className = v;
        } else if (k.startsWith('data-')) {
            node.setAttribute(k, String(v));
        } else if (v !== undefined && v !== null) {
            node.setAttribute(k, String(v));
        }
    }
    if (text !== null) {
        node.textContent = String(text);
    }
    return node;
}

function formatDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    return d.toISOString().slice(0, 10);
}

// Run an async action with the button disabled and marked busy, so slow
// operations (ACME validation, GoDaddy calls) cannot be double-submitted.
async function withBusy(btn, fn) {
    if (!btn || btn.getAttribute('aria-busy') === 'true') return undefined;
    btn.setAttribute('aria-busy', 'true');
    btn.disabled = true;
    try {
        return await fn();
    } finally {
        btn.removeAttribute('aria-busy');
        btn.disabled = false;
    }
}

// Form sections the user is editing. Live config_changed refreshes must not
// overwrite unsaved input.
const dirtyForms = new Set();
const FORM_FIELDS = {
    server: ['httpPort', 'httpsPort', 'adminPort', 'adminHost', 'allowedNetworks'],
    acme: ['acmeEmail', 'acmeStaging'],
    godaddy: ['gdApiKey', 'gdApiSecret', 'gdBaseUrl'],
};

function setField(id, prop, value) {
    const node = document.getElementById(id);
    if (node) node[prop] = value;
}

function isGoDaddyConfigured() {
    return Boolean(config && config.godaddy && config.godaddy.api_key && config.godaddy.api_secret);
}

// --- API Client ---
async function api(method, path, body = null) {
    const opts = {
        method,
        headers: { 'Content-Type': 'application/json' },
    };
    if (body !== null) {
        opts.body = JSON.stringify(body);
    }

    const resp = await fetch(`/api${path}`, opts);
    if (resp.status === 401 && !path.startsWith('/auth/')) {
        // Session expired, signed out elsewhere, or password reset on the machine.
        showAuthScreen('login');
        throw new Error('Signed out. Please sign in again.');
    }
    let data = {};
    try {
        data = await resp.json();
    } catch {
        data = {};
    }

    if (!resp.ok) {
        throw new Error(data.error || `HTTP ${resp.status}`);
    }
    return data;
}

// --- WebSocket ---
function connectWebSocket() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}/ws`);

    ws.onopen = () => {
        updateWSStatus(true);
    };

    ws.onclose = () => {
        updateWSStatus(false);
        if (authenticated) setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = () => {
        updateWSStatus(false);
    };

    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleWSMessage(msg);
        } catch {
            // Ignore malformed messages
        }
    };
}

function updateWSStatus(connected) {
    const container = document.getElementById('wsStatus');
    if (!container) return;
    const dot = container.querySelector('.status-dot');
    const label = container.querySelector('.ws-label');
    if (dot) dot.className = `status-dot ${connected ? 'connected' : 'disconnected'}`;
    if (label) label.textContent = connected ? 'Connected' : 'Disconnected';
}

function describeEvent(msg) {
    const p = msg.payload || {};
    switch (msg.type) {
        case 'config_changed':
            return 'Configuration saved';
        case 'route_added':
        case 'route_updated':
            return `${p.domain || ''}${p.path_prefix || ''} -> ${p.target_host}:${p.target_port}${p.enabled === false ? ' (disabled)' : ''}`;
        case 'route_deleted':
            return `Route ${p.id || ''} removed`;
        case 'acme_challenge':
            return `${p.domain || ''}: challenge ${p.status || 'pending'}`;
        case 'cert_obtained':
            return `${p.domain || ''}: certificate issued`;
        case 'dns_record_created':
            return `${p.domain || ''}: ${typeof p.record === 'string' ? p.record : `${p.record?.type || ''} ${p.record?.name || ''}`}`;
        case 'dns_record_deleted':
            return `${p.domain || ''}: ${p.type || ''} ${p.name || ''} deleted`;
        case 'auto_dns_created':
            return `${p.subdomain || ''}.${p.domain || ''} (${p.type || 'A'})`;
        default:
            return typeof msg.payload === 'string' ? msg.payload : JSON.stringify(p).slice(0, 120);
    }
}

function handleWSMessage(msg) {
    addEvent(msg.type || 'event', describeEvent(msg));

    switch (msg.type) {
        case 'config_changed':
            loadConfig();
            loadRoutes();
            loadSecurityStatus();
            break;
        case 'route_added':
        case 'route_updated':
        case 'route_deleted':
            loadRoutes();
            break;
        case 'cert_obtained':
            showToast(`Certificate issued for ${msg.payload?.domain || 'domain'}`, 'success');
            showStep(3);
            renderCertDetails(msg.payload?.cert, null);
            loadRoutes();
            loadChallenges();
            loadCertsStatus();
            break;
        case 'acme_challenge':
            loadChallenges();
            break;
        case 'dns_record_created':
        case 'dns_record_deleted':
        case 'auto_dns_created':
            if (selectedDomain) loadDNSRecords(selectedDomain);
            break;
    }
}

// --- Toast & In-App Confirmation ---
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = el('div', { className: `toast toast-${type}` }, message);
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 3800);
}

function askConfirm(title, message, confirmLabel = 'Delete') {
    return new Promise((resolve) => {
        confirmResolver = resolve;
        document.getElementById('confirmModalTitle').textContent = title;
        document.getElementById('confirmModalMessage').textContent = message;
        document.getElementById('confirmAcceptBtn').textContent = confirmLabel;
        document.getElementById('confirmModal').classList.remove('hidden');
        document.getElementById('confirmAcceptBtn').focus();
    });
}

function finishConfirm(result) {
    document.getElementById('confirmModal').classList.add('hidden');
    if (confirmResolver) {
        const fn = confirmResolver;
        confirmResolver = null;
        fn(result);
    }
}

function closeModal(id) {
    const modal = document.getElementById(id);
    if (modal) modal.classList.add('hidden');
    if (id === 'confirmModal' && confirmResolver) {
        finishConfirm(false);
    }
}

// --- Live Event Stream ---
function addEvent(type, detail) {
    eventHistory.unshift({
        time: new Date().toLocaleTimeString(),
        type,
        detail,
    });
    if (eventHistory.length > 60) {
        eventHistory.pop();
    }
    renderEvents();
}

function renderEvents() {
    const log = document.getElementById('eventLog');
    if (!log) return;
    log.textContent = '';

    const needle = eventFilter.trim().toLowerCase();
    const visible = needle
        ? eventHistory.filter(
              (ev) =>
                  ev.type.toLowerCase().includes(needle) ||
                  ev.detail.toLowerCase().includes(needle),
          )
        : eventHistory;

    if (visible.length === 0) {
        log.appendChild(
            el(
                'div',
                { className: 'event-empty' },
                eventHistory.length === 0
                    ? 'Waiting for proxy events...'
                    : 'No events match your filter.',
            ),
        );
        return;
    }

    for (const ev of visible) {
        const row = el('div', { className: 'event-entry' });
        row.appendChild(el('span', { className: 'event-time' }, ev.time));
        row.appendChild(el('span', { className: 'event-type' }, ev.type));
        row.appendChild(el('span', { className: 'event-detail' }, ev.detail));
        log.appendChild(row);
    }
}

// --- Config & Settings ---
async function loadConfig() {
    try {
        config = await api('GET', '/config');
        updateDashboardStats();
        populateSettings();
        // A deep link to #dns renders before config arrives; load domains now
        // that we know whether GoDaddy is configured.
        if (document.getElementById('page-dns')?.classList.contains('active')) {
            loadGoDaddyDomains();
        }
    } catch (e) {
        showToast(`Failed to load config: ${e.message}`, 'error');
    }
}

function populateSettings() {
    if (!config) return;
    if (!dirtyForms.has('server')) {
        setField('httpPort', 'value', config.server.http_port);
        setField('httpsPort', 'value', config.server.https_port);
        setField('adminPort', 'value', config.server.admin_port);
        setField('adminHost', 'value', config.server.admin_host);
        setField('allowedNetworks', 'value', (config.server.allowed_networks || []).join(', '));
    }
    if (!dirtyForms.has('acme')) {
        setField('acmeEmail', 'value', config.acme.email || '');
        setField('acmeStaging', 'checked', Boolean(config.acme.use_staging));
    }

    const gdConfigured = isGoDaddyConfigured();
    if (!dirtyForms.has('godaddy')) {
        setField('gdApiKey', 'value', config.godaddy.api_key || '');
        const baseUrl = config.godaddy.base_url || 'https://api.godaddy.com';
        const envSelect = document.getElementById('gdBaseUrl');
        // A config edited by hand may use another endpoint; show it instead of a blank select.
        if (envSelect && ![...envSelect.options].some((o) => o.value === baseUrl)) {
            envSelect.appendChild(el('option', { value: baseUrl }, `Custom (${baseUrl})`));
        }
        setField('gdBaseUrl', 'value', baseUrl);
        const secretInput = document.getElementById('gdApiSecret');
        if (secretInput) {
            secretInput.placeholder = config.godaddy.api_secret
                ? 'Saved — leave blank to keep'
                : 'GoDaddy API Secret';
        }
    }
    updateAutoDNSAvailability();
    const gdMeta = document.getElementById('gdConnectionMeta');
    if (gdMeta) {
        gdMeta.textContent = gdConfigured ? 'Credentials saved' : 'Not configured';
        gdMeta.className = `toolbar-meta ${gdConfigured ? 'state-ok' : 'state-muted'}`;
    }
}

async function saveServerConfig() {
    const note = document.getElementById('serverRestartNote');
    if (note) note.classList.add('hidden');
    try {
        const networksRaw = document.getElementById('allowedNetworks').value;
        const allowedNetworks = networksRaw
            ? networksRaw
                  .split(',')
                  .map((s) => s.trim())
                  .filter(Boolean)
            : [];

        const res = await api('PUT', '/config/server', {
            http_port: parseInt(document.getElementById('httpPort').value, 10),
            https_port: parseInt(document.getElementById('httpsPort').value, 10),
            admin_port: parseInt(document.getElementById('adminPort').value, 10),
            admin_host: document.getElementById('adminHost').value.trim(),
            allowed_networks: allowedNetworks,
        });
        dirtyForms.delete('server');
        showToast('Server configuration saved', 'success');
        if (res && res.restart_required && note) note.classList.remove('hidden');
        loadSecurityStatus();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function saveACMEConfig() {
    try {
        const staging = document.getElementById('acmeStaging').checked;
        await api('PUT', '/acme/config', {
            email: document.getElementById('acmeEmail').value.trim(),
            directory: staging
                ? 'https://acme-staging-v02.api.letsencrypt.org/directory'
                : 'https://acme-v02.api.letsencrypt.org/directory',
            cert_dir: config?.acme?.cert_dir || './certs',
            use_staging: staging,
        });
        dirtyForms.delete('acme');
        showToast('ACME configuration saved', 'success');
        loadSecurityStatus();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

function secretsItem(status) {
    const s = status.secrets || {};
    const key = 'Stored Credentials (AES-256-GCM)';
    if (s.error) return { key, val: `Could not decrypt: ${s.error}`, cls: 'state-err' };
    switch (s.mode) {
        case 'env':
            return { key, val: 'Encrypted · key from PROXYGATE_CONFIG_KEY', cls: 'state-ok' };
        case 'file':
            return { key, val: 'Encrypted · key file data/secret.key', cls: 'state-ok' };
        case 'disabled':
            return { key, val: 'Plaintext (security.encrypt_secrets is off)', cls: 'state-warn' };
        default:
            return { key, val: 'Encrypted when saved', cls: 'state-ok' };
    }
}

async function loadSecurityStatus() {
    const grid = document.getElementById('securityStatusGrid');
    if (!grid) return;

    try {
        const status = await api('GET', '/security/status');
        grid.textContent = '';

        const items = [
            {
                key: 'Admin Login',
                val: status.admin_login?.strong_password_policy
                    ? 'Password · strong rules'
                    : 'Password · basic rules (8+ characters)',
                cls: status.admin_login?.strong_password_policy ? 'state-ok' : 'state-warn',
            },
            {
                key: 'This Connection',
                val: status.admin_https
                    ? 'HTTPS'
                    : status.admin_login?.require_secure_login
                      ? 'HTTP · login limited to localhost'
                      : 'HTTP (enable security.admin_tls for HTTPS)',
                cls: status.admin_https ? 'state-ok' : 'state-warn',
            },
            {
                key: 'Sessions',
                val: `Idle ${status.admin_login?.session_idle_timeout || '12h'} · max ${status.admin_login?.session_max_age || '7d'} · ${status.admin_login?.api_tokens ?? 0} API token${status.admin_login?.api_tokens === 1 ? '' : 's'}`,
                cls: 'state-ok',
            },
            secretsItem(status),
            {
                key: 'Content Security Policy',
                val: status.csp_enforced ? "Enforced (script-src 'self')" : 'Disabled',
                cls: status.csp_enforced ? 'state-ok' : 'state-err',
            },
            {
                key: 'API Rate Limiter',
                val: `${status.rate_limit.max_requests} req / ${status.rate_limit.window_seconds}s`,
                cls: 'state-ok',
            },
            {
                key: 'Admin Network Allowlist',
                val: `${status.allowed_networks_count} CIDR rule${status.allowed_networks_count === 1 ? '' : 's'}`,
                cls: status.allowed_networks_count > 0 ? 'state-ok' : 'state-warn',
            },
            {
                key: 'GoDaddy API',
                val: `${status.godaddy_configured ? 'Configured' : 'Not configured'} · ${status.godaddy_base_url}`,
                cls: status.godaddy_configured ? 'state-ok' : 'state-muted',
            },
            {
                key: 'ACME Mode',
                val: status.acme_staging ? 'Staging (Test)' : 'Production',
                cls: status.acme_staging ? 'state-warn' : 'state-ok',
            },
        ];

        for (const item of items) {
            const cell = el('div', { className: 'security-item' });
            cell.appendChild(el('span', { className: 'security-key' }, item.key));
            cell.appendChild(el('span', { className: `security-val ${item.cls}` }, item.val));
            grid.appendChild(cell);
        }
    } catch {
        // Non-blocking
    }
}

function exportConfigJson() {
    if (!config) {
        showToast('Configuration not loaded yet', 'warning');
        return;
    }
    const blob = new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'proxygate-config.json';
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showToast('Exported redacted config JSON', 'success');
}

// --- Routes ---
async function loadRoutes() {
    try {
        routes = await api('GET', '/routes');
        if (!Array.isArray(routes)) routes = [];
        updateDashboardStats();
        renderDashboardRoutes();
        renderRoutes();
        populateConfiguredDomainsList();
    } catch (e) {
        showToast(`Failed to load routes: ${e.message}`, 'error');
    }
}

function populateConfiguredDomainsList() {
    const datalist = document.getElementById('configuredDomainsList');
    if (!datalist) return;
    datalist.textContent = '';
    const uniqueDomains = [...new Set(routes.map((r) => r.domain))].sort();
    for (const d of uniqueDomains) {
        datalist.appendChild(el('option', { value: d }));
    }
}

function updateDashboardStats() {
    const activeCount = routes.filter((r) => r.enabled).length;
    const tlsCount = routes.filter((r) => r.tls_enabled).length;
    const pendingCount = challenges.filter(
        (c) => c.status === 'pending' || c.status === 'processing',
    ).length;

    document.getElementById('activeRoutes').textContent = String(activeCount);
    document.getElementById('tlsRoutes').textContent = String(tlsCount);
    document.getElementById('pendingCerts').textContent = String(pendingCount);

    const gdEl = document.getElementById('godaddyStatus');
    const configured = isGoDaddyConfigured();
    gdEl.textContent = configured ? 'Configured' : 'Not configured';
    gdEl.className = `stat-value stat-value-text ${configured ? 'state-ok' : 'state-muted'}`;
}

function renderDashboardRoutes() {
    const tbody = document.querySelector('#dashboardRoutes tbody');
    if (!tbody) return;
    tbody.textContent = '';

    const needle = dashboardSearch.trim().toLowerCase();
    const filtered = needle
        ? routes.filter(
              (r) =>
                  r.domain.toLowerCase().includes(needle) ||
                  (r.name || '').toLowerCase().includes(needle) ||
                  `${r.target_host}:${r.target_port}`.toLowerCase().includes(needle),
          )
        : routes;

    if (filtered.length === 0) {
        const tr = el('tr');
        const td = el(
            'td',
            { colspan: 5, className: 'table-empty' },
            routes.length === 0
                ? 'No proxy routes configured yet. Use "+ Add Route" to create your first route.'
                : 'No routes match your filter.',
        );
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
    }

    for (const r of filtered) {
        const tr = el('tr');

        const domainTd = el('td', { className: 'mono' });
        domainTd.appendChild(document.createTextNode(r.domain));
        if (r.path_prefix) {
            domainTd.appendChild(el('span', { className: 'route-prefix' }, r.path_prefix));
        }
        tr.appendChild(domainTd);

        tr.appendChild(el('td', { className: 'mono' }, `${r.target_host}:${r.target_port}`));

        const tlsTd = el('td');
        tlsTd.appendChild(
            el(
                'span',
                { className: `state-text ${r.tls_enabled ? 'state-ok' : 'state-muted'}` },
                r.tls_enabled ? 'Enabled' : 'Off',
            ),
        );
        tr.appendChild(tlsTd);

        const statusTd = el('td');
        statusTd.appendChild(
            el(
                'span',
                { className: `state-text ${r.enabled ? 'state-ok' : 'state-err'}` },
                r.enabled ? 'Active' : 'Disabled',
            ),
        );
        tr.appendChild(statusTd);

        const actionsTd = el('td', { className: 'col-right' });
        const actionsWrap = el('div', { className: 'row-actions' });
        actionsWrap.appendChild(
            el(
                'button',
                {
                    type: 'button',
                    className: 'btn btn-ghost btn-sm',
                    'data-action': 'toggle-route',
                    'data-id': r.id,
                },
                r.enabled ? 'Pause' : 'Enable',
            ),
        );
        actionsWrap.appendChild(
            el(
                'button',
                {
                    type: 'button',
                    className: 'btn btn-secondary btn-sm',
                    'data-action': 'edit-route',
                    'data-id': r.id,
                },
                'Edit',
            ),
        );
        actionsTd.appendChild(actionsWrap);
        tr.appendChild(actionsTd);

        tbody.appendChild(tr);
    }
}

function renderRoutes() {
    const container = document.getElementById('routesList');
    const countMeta = document.getElementById('routesCountMeta');
    if (!container) return;
    container.textContent = '';

    const needle = routeSearch.trim().toLowerCase();
    const filtered = routes.filter((r) => {
        if (routeFilter === 'active' && !r.enabled) return false;
        if (routeFilter === 'disabled' && r.enabled) return false;
        if (routeFilter === 'tls' && !r.tls_enabled) return false;
        if (!needle) return true;
        return (
            (r.name || '').toLowerCase().includes(needle) ||
            r.domain.toLowerCase().includes(needle) ||
            (r.path_prefix || '').toLowerCase().includes(needle) ||
            r.target_host.toLowerCase().includes(needle) ||
            String(r.target_port).includes(needle)
        );
    });

    if (countMeta) {
        countMeta.textContent = `${filtered.length} of ${routes.length} route${routes.length === 1 ? '' : 's'}`;
    }

    if (filtered.length === 0) {
        const empty = el('div', { className: 'empty-state' });
        empty.appendChild(
            el(
                'p',
                {},
                routes.length === 0
                    ? 'No proxy routes configured yet. Add a route to forward traffic from a domain to a local host and port.'
                    : 'No routes match the current search and status filter.',
            ),
        );
        if (routes.length === 0) {
            empty.appendChild(
                el(
                    'button',
                    {
                        type: 'button',
                        className: 'btn btn-primary',
                        'data-action': 'open-add-route',
                    },
                    '+ Add First Route',
                ),
            );
        }
        container.appendChild(empty);
        return;
    }

    for (const r of filtered) {
        const row = el('div', { className: 'route-row' });

        const main = el('div', { className: 'route-main' });
        const titleLine = el('div', { className: 'route-title-line' });
        titleLine.appendChild(el('span', { className: 'route-name' }, r.name || r.domain));

        const domainSpan = el('span', { className: 'route-domain' });
        domainSpan.appendChild(document.createTextNode(r.domain));
        if (r.path_prefix) {
            domainSpan.appendChild(el('span', { className: 'route-prefix' }, r.path_prefix));
        }
        titleLine.appendChild(domainSpan);
        main.appendChild(titleLine);

        const metaLine = el('div', { className: 'route-meta-line' });
        metaLine.appendChild(el('span', {}, `-> ${r.target_host}:${r.target_port}`));
        metaLine.appendChild(el('span', { className: 'meta-sep', 'aria-hidden': 'true' }, '·'));
        metaLine.appendChild(
            el(
                'span',
                { className: `state-text ${r.enabled ? 'state-ok' : 'state-err'}` },
                r.enabled ? 'Active' : 'Disabled',
            ),
        );
        metaLine.appendChild(el('span', { className: 'meta-sep', 'aria-hidden': 'true' }, '·'));
        metaLine.appendChild(
            el(
                'span',
                { className: `state-text ${r.tls_enabled ? 'state-warn' : 'state-muted'}` },
                r.tls_enabled ? (r.auto_cert ? 'TLS Auto-Cert' : 'TLS Enabled') : 'HTTP Only',
            ),
        );
        main.appendChild(metaLine);
        row.appendChild(main);

        const actions = el('div', { className: 'route-actions' });
        actions.appendChild(
            el(
                'button',
                {
                    type: 'button',
                    className: 'btn btn-secondary btn-sm',
                    'data-action': 'toggle-route',
                    'data-id': r.id,
                },
                r.enabled ? 'Disable' : 'Enable',
            ),
        );

        if (!r.tls_enabled) {
            actions.appendChild(
                el(
                    'button',
                    {
                        type: 'button',
                        className: 'btn btn-secondary btn-sm',
                        'data-action': 'request-tls',
                        'data-domain': r.domain,
                    },
                    'Request TLS',
                ),
            );
        }

        actions.appendChild(
            el(
                'button',
                {
                    type: 'button',
                    className: 'btn btn-secondary btn-sm',
                    'data-action': 'edit-route',
                    'data-id': r.id,
                },
                'Edit',
            ),
        );

        actions.appendChild(
            el(
                'button',
                {
                    type: 'button',
                    className: 'btn btn-danger btn-sm',
                    'data-action': 'delete-route',
                    'data-id': r.id,
                },
                'Delete',
            ),
        );

        row.appendChild(actions);
        container.appendChild(row);
    }
}

// TLS can only be switched on once the route has a certificate; otherwise the
// proxy would redirect visitors to an HTTPS listener with nothing to serve.
function configureRouteTLSControl(route) {
    const box = document.getElementById('routeTLS');
    const hint = document.getElementById('routeTLSHint');
    const hasCert = Boolean(route && route.cert_file && route.key_file);
    box.disabled = !hasCert;
    box.checked = hasCert && Boolean(route.tls_enabled);
    if (hint) {
        hint.textContent = !hasCert
            ? 'Save the route, then use "Request TLS". TLS switches on automatically once the certificate is issued.'
            : isGoDaddyConfigured()
              ? `Using ${route.cert_file}. Renewed automatically when it has under 30 days left.`
              : `Using ${route.cert_file}. Automatic renewal needs GoDaddy configured on the DNS page; otherwise request a new certificate before it expires.`;
    }
}

function setRouteFormError(message) {
    const box = document.getElementById('routeFormError');
    if (!box) return;
    box.textContent = message || '';
    box.classList.toggle('hidden', !message);
}

function showAddRouteModal() {
    setRouteFormError('');
    document.getElementById('editRouteId').value = '';
    document.getElementById('routeModalTitle').textContent = 'Add Proxy Route';
    document.getElementById('routeName').value = '';
    document.getElementById('routeDomain').value = '';
    document.getElementById('routePathPrefix').value = '';
    document.getElementById('routeTargetHost').value = '127.0.0.1';
    document.getElementById('routeTargetPort').value = '';
    document.getElementById('routeEnabled').checked = true;
    configureRouteTLSControl(null);
    document.getElementById('addRouteModal').classList.remove('hidden');
    document.getElementById('routeDomain').focus();
}

function editRoute(id) {
    const route = routes.find((r) => r.id === id);
    if (!route) return;

    setRouteFormError('');
    document.getElementById('editRouteId').value = id;
    document.getElementById('routeModalTitle').textContent = 'Edit Proxy Route';
    document.getElementById('routeName').value = route.name || '';
    document.getElementById('routeDomain').value = route.domain;
    document.getElementById('routePathPrefix').value = route.path_prefix || '';
    document.getElementById('routeTargetHost').value = route.target_host;
    document.getElementById('routeTargetPort').value = route.target_port;
    document.getElementById('routeEnabled').checked = Boolean(route.enabled);
    configureRouteTLSControl(route);
    document.getElementById('addRouteModal').classList.remove('hidden');
    document.getElementById('routeName').focus();
}

async function saveRoute(event) {
    event.preventDefault();
    const id = document.getElementById('editRouteId').value;
    const prefix = document.getElementById('routePathPrefix').value.trim();

    const route = {
        name: document.getElementById('routeName').value.trim(),
        domain: document.getElementById('routeDomain').value.trim(),
        // Always send the prefix so clearing it on edit actually removes it.
        path_prefix: prefix,
        target_host: document.getElementById('routeTargetHost').value.trim(),
        target_port: parseInt(document.getElementById('routeTargetPort').value, 10),
        enabled: document.getElementById('routeEnabled').checked,
        tls_enabled: document.getElementById('routeTLS').checked,
    };

    setRouteFormError('');
    await withBusy(document.getElementById('saveRouteBtn'), async () => {
        try {
            if (id) {
                await api('PUT', `/routes/${encodeURIComponent(id)}`, route);
                showToast('Route updated', 'success');
            } else {
                await api('POST', '/routes', route);
                showToast(`Route created for ${route.domain}`, 'success');
            }
            closeModal('addRouteModal');
            loadRoutes();
        } catch (e) {
            // Keep the modal open with the user's input and show why.
            setRouteFormError(e.message);
        }
    });
}

async function toggleRoute(id) {
    try {
        const res = await api('PATCH', `/routes/${encodeURIComponent(id)}/toggle`);
        const active = res?.route?.enabled;
        showToast(active ? 'Route enabled' : 'Route disabled', 'info');
        loadRoutes();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function deleteRoute(id) {
    const route = routes.find((r) => r.id === id);
    const label = route ? route.domain : id;
    const ok = await askConfirm(
        'Delete Proxy Route',
        `Remove route for "${label}"? This takes effect immediately.`,
        'Delete Route',
    );
    if (!ok) return;

    try {
        await api('DELETE', `/routes/${encodeURIComponent(id)}`);
        showToast(`Deleted route ${label}`, 'success');
        loadRoutes();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

// --- ACME & Certificates ---
function renderCertDetails(certFile, keyFile) {
    const container = document.getElementById('certDetails');
    if (!container) return;
    container.textContent = '';

    if (certFile) {
        const p = el('p');
        p.appendChild(document.createTextNode('Certificate: '));
        p.appendChild(el('code', {}, certFile));
        container.appendChild(p);
    }
    if (keyFile) {
        const p = el('p');
        p.appendChild(document.createTextNode('Private Key: '));
        p.appendChild(el('code', {}, keyFile));
        container.appendChild(p);
    }
}

function showStep(n) {
    for (let i = 1; i <= 3; i++) {
        const stepEl = document.getElementById(`step${i}`);
        if (stepEl) stepEl.classList.toggle('hidden', i > n);
    }
}

function resetAcmeWizard() {
    document.getElementById('acmeDomain').value = '';
    document.getElementById('dnsRecordName').textContent = '';
    document.getElementById('dnsRecordValue').textContent = '';
    document.getElementById('autoDNSStatus').classList.add('hidden');
    document.getElementById('certProgress').classList.add('hidden');
    showStep(1);
}

function updateAutoDNSAvailability() {
    const box = document.getElementById('acmeAutoDNS');
    const hint = document.getElementById('acmeAutoDNSHint');
    if (!box) return;
    const configured = isGoDaddyConfigured();
    box.disabled = !configured;
    if (!configured) box.checked = false;
    if (hint) {
        hint.textContent = configured
            ? 'Publishes the TXT record for you, then waits ~30s for DNS propagation.'
            : 'Configure GoDaddy on the DNS page to enable this.';
    }
}

function updateAcmeDomainNote() {
    const note = document.getElementById('acmeDomainNote');
    if (!note) return;
    const domain = document.getElementById('acmeDomain').value.trim().toLowerCase();
    const hasRoute = routes.some((r) => r.domain === domain);
    if (domain && !hasRoute) {
        note.textContent = `No route uses ${domain} yet. The certificate will be saved, but it is only served once a route for this domain exists.`;
        note.classList.remove('hidden');
    } else {
        note.classList.add('hidden');
    }
}

async function requestCertificate() {
    const domain = document.getElementById('acmeDomain').value.trim();
    if (!domain) {
        showToast('Enter a domain name first', 'warning');
        return;
    }

    await withBusy(document.getElementById('requestCertBtn'), () => doRequestCertificate(domain));
}

async function doRequestCertificate(domain) {
    try {
        const result = await api('POST', '/acme/request', { domain });
        document.getElementById('dnsRecordName').textContent = result.record_name || '';
        document.getElementById('dnsRecordValue').textContent = result.record_value || '';
        showStep(2);

        const autoDNS = document.getElementById('acmeAutoDNS').checked;
        const autoStatus = document.getElementById('autoDNSStatus');
        if (autoDNS) {
            autoStatus.textContent =
                'Auto-DNS enabled: TXT record will be published via GoDaddy when you click Verify & Complete.';
            autoStatus.classList.remove('hidden');
        } else {
            autoStatus.classList.add('hidden');
        }

        showToast('DNS-01 challenge ready', 'info');
        loadChallenges();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function completeCertificate() {
    await withBusy(document.getElementById('completeCertBtn'), doCompleteCertificate);
}

async function doCompleteCertificate() {
    const domain = document.getElementById('acmeDomain').value.trim();
    const autoDNS = document.getElementById('acmeAutoDNS').checked;
    const progressEl = document.getElementById('certProgress');
    const progressText = document.getElementById('certProgressText');
    if (progressText) {
        progressText.textContent = autoDNS
            ? 'Publishing TXT record, waiting ~30s for DNS propagation, then validating with Let\'s Encrypt. This can take a couple of minutes — keep this tab open.'
            : 'Asking Let\'s Encrypt to validate the TXT record. This can take up to a minute.';
    }
    progressEl.classList.remove('hidden');

    try {
        const result = await api('POST', '/acme/complete', { domain, auto_dns: autoDNS });
        progressEl.classList.add('hidden');
        showStep(3);
        renderCertDetails(result.cert_file, result.key_file);
        showToast(`Certificate issued for ${domain}`, 'success');
        loadRoutes();
        loadChallenges();
        loadCertsStatus();
    } catch (e) {
        progressEl.classList.add('hidden');
        showToast(`Verification failed: ${e.message}`, 'error');
    }
}

async function loadChallenges() {
    try {
        const result = await api('GET', '/acme/challenges');
        challenges = Array.isArray(result) ? result : [];
        updateDashboardStats();

        const container = document.getElementById('challengesList');
        if (!container) return;
        container.textContent = '';

        if (challenges.length === 0) {
            container.appendChild(
                el('div', { className: 'table-empty' }, 'No ACME challenges recorded yet.'),
            );
            return;
        }

        for (const c of challenges) {
            const row = el('div', { className: 'challenge-row' });
            const left = el('div');
            left.appendChild(el('strong', {}, c.domain));
            left.appendChild(el('span', { className: 'meta-sep' }, '·'));
            const stateCls =
                c.status === 'valid'
                    ? 'state-ok'
                    : c.status === 'invalid'
                      ? 'state-err'
                      : 'state-warn';
            left.appendChild(el('span', { className: `state-text ${stateCls}` }, c.status));
            if (c.error) {
                left.appendChild(el('span', { className: 'meta-sep' }, '·'));
                left.appendChild(el('span', { className: 'state-err' }, c.error));
            }
            row.appendChild(left);

            if (c.status === 'pending' && c.record_name) {
                row.appendChild(
                    el(
                        'button',
                        {
                            type: 'button',
                            className: 'btn btn-secondary btn-sm',
                            'data-action': 'resume-challenge',
                            'data-domain': c.domain,
                        },
                        'Resume',
                    ),
                );
            }
            container.appendChild(row);
        }
    } catch {
        // Non-blocking
    }
}

async function loadCertsStatus() {
    const tbody = document.querySelector('#certsStatusTable tbody');
    const metricsEl = document.getElementById('certMetricsMeta');
    if (!tbody) return;

    try {
        const res = await api('GET', '/certs/status');
        if (metricsEl && res.metrics) {
            metricsEl.textContent = `Renewals: ${res.metrics.renewal_success} ok · ${res.metrics.renewal_failed} failed`;
        }

        const certs = Array.isArray(res.certs) ? res.certs : [];
        tbody.textContent = '';

        if (certs.length === 0) {
            const tr = el('tr');
            tr.appendChild(
                el(
                    'td',
                    { colspan: 5, className: 'table-empty' },
                    'No TLS certificates issued yet.',
                ),
            );
            tbody.appendChild(tr);
            return;
        }

        for (const c of certs) {
            const tr = el('tr');
            tr.appendChild(el('td', { className: 'mono' }, c.domain));
            tr.appendChild(el('td', { className: 'mono cell-truncate' }, c.cert_file || '—'));
            tr.appendChild(el('td', { className: 'mono' }, formatDate(c.expires_at)));
            tr.appendChild(
                el(
                    'td',
                    { className: 'mono col-right' },
                    c.days_remaining !== undefined ? String(c.days_remaining) : '—',
                ),
            );

            const stateTd = el('td');
            const stateLabel = c.error
                ? c.error
                : c.needs_renewal
                  ? 'Renew soon'
                  : 'Healthy';
            const stateCls = c.error ? 'state-err' : c.needs_renewal ? 'state-warn' : 'state-ok';
            stateTd.appendChild(el('span', { className: `state-text ${stateCls}` }, stateLabel));
            tr.appendChild(stateTd);
            tbody.appendChild(tr);
        }
    } catch {
        // Non-blocking
    }
}

// --- GoDaddy DNS ---
async function saveGoDaddyConfig() {
    await withBusy(document.getElementById('saveGoDaddyBtn'), doSaveGoDaddyConfig);
}

async function doSaveGoDaddyConfig() {
    try {
        await api('PUT', '/godaddy/config', {
            api_key: document.getElementById('gdApiKey').value.trim(),
            api_secret: document.getElementById('gdApiSecret').value.trim(),
            base_url: document.getElementById('gdBaseUrl').value,
        });
        showToast('GoDaddy credentials saved', 'success');
        document.getElementById('gdApiSecret').value = '';
        dirtyForms.delete('godaddy');
        await loadConfig();
        loadSecurityStatus();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function verifyGoDaddy() {
    await withBusy(document.getElementById('verifyGoDaddyBtn'), doVerifyGoDaddy);
}

async function doVerifyGoDaddy() {
    const resultEl = document.getElementById('gdVerifyResult');
    resultEl.classList.remove('hidden');
    resultEl.className = 'status-note state-warn';
    resultEl.textContent = 'Testing GoDaddy API connection...';

    try {
        await api('POST', '/godaddy/verify');
        resultEl.className = 'status-note state-ok';
        resultEl.textContent = 'Connection verified — GoDaddy API is reachable.';
        showToast('GoDaddy API connected', 'success');
        loadGoDaddyDomains();
    } catch (e) {
        resultEl.className = 'status-note state-err';
        resultEl.textContent = `Connection failed: ${e.message}`;
    }
}

async function loadGoDaddyDomains() {
    const container = document.getElementById('gdDomainsList');
    const select = document.getElementById('dnsRecordsDomain');
    if (!container) return;

    if (!isGoDaddyConfigured()) {
        container.textContent = '';
        container.appendChild(
            el(
                'div',
                { className: 'table-empty' },
                'Configure your GoDaddy API key and secret above to list active domains.',
            ),
        );
        return;
    }

    try {
        const query = includeInactiveDomains ? '?include_inactive=true' : '';
        const domains = await api('GET', `/godaddy/domains${query}`);
        allDomains = Array.isArray(domains) ? domains : [];
        renderDomains();

        const datalist = document.getElementById('gdDomainsDatalist');
        if (datalist) {
            datalist.textContent = '';
            for (const d of allDomains) datalist.appendChild(el('option', { value: d.domain }));
        }

        if (select) {
            const previous = select.value;
            select.textContent = '';
            select.appendChild(el('option', { value: '' }, 'Select a domain...'));
            for (const d of allDomains) {
                select.appendChild(el('option', { value: d.domain }, d.domain));
            }
            if (previous && allDomains.some((d) => d.domain === previous)) {
                select.value = previous;
            }
        }
    } catch (e) {
        container.textContent = '';
        container.appendChild(el('div', { className: 'table-empty state-err' }, e.message));
    }
}

function renderDomains() {
    const container = document.getElementById('gdDomainsList');
    if (!container) return;
    container.textContent = '';

    const needle = domainSearch.trim().toLowerCase();
    const visible = needle
        ? allDomains.filter((d) => d.domain.toLowerCase().includes(needle))
        : allDomains;

    if (visible.length === 0) {
        container.appendChild(
            el(
                'div',
                { className: 'table-empty' },
                allDomains.length === 0
                    ? includeInactiveDomains
                        ? 'No domains found in GoDaddy account.'
                        : 'No active domains found. Switch to "All Statuses" to inspect expired or inactive domains.'
                    : 'No domains match your search.',
            ),
        );
        return;
    }

    for (const d of visible) {
        const isActive = String(d.status || '').toUpperCase() === 'ACTIVE';
        const btn = el('button', {
            type: 'button',
            className: `domain-row${selectedDomain === d.domain ? ' selected' : ''}`,
            'data-action': 'select-domain',
            'data-domain': d.domain,
        });

        btn.appendChild(el('span', {}, d.domain));

        const meta = el('span', { className: 'domain-row-meta' });
        if (d.expires) {
            meta.appendChild(el('span', {}, `exp ${formatDate(d.expires)}`));
        }
        meta.appendChild(
            el(
                'span',
                { className: `state-text ${isActive ? 'state-ok' : 'state-warn'}` },
                d.status || 'UNKNOWN',
            ),
        );
        btn.appendChild(meta);
        container.appendChild(btn);
    }
}

async function loadDNSRecords(domain) {
    const targetDomain = domain || document.getElementById('dnsRecordsDomain').value;
    const tbody = document.querySelector('#dnsRecordsTable tbody');
    if (!tbody) return;

    if (!targetDomain) {
        currentDnsRecords = [];
        renderDNSRecords();
        return;
    }

    selectedDomain = targetDomain;
    document.getElementById('dnsRecordsDomain').value = targetDomain;
    document.getElementById('quickDnsDomain').value = targetDomain;
    renderDomains();

    tbody.textContent = '';
    const loadingRow = el('tr');
    loadingRow.appendChild(
        el('td', { colspan: 5, className: 'table-empty' }, `Loading records for ${targetDomain}...`),
    );
    tbody.appendChild(loadingRow);

    try {
        const records = await api(
            'GET',
            `/godaddy/domains/${encodeURIComponent(targetDomain)}/records`,
        );
        currentDnsRecords = Array.isArray(records) ? records : [];
        renderDNSRecords();
    } catch (e) {
        currentDnsRecords = [];
        tbody.textContent = '';
        const errRow = el('tr');
        errRow.appendChild(el('td', { colspan: 5, className: 'table-empty state-err' }, e.message));
        tbody.appendChild(errRow);
    }
}

function renderDNSRecords() {
    const tbody = document.querySelector('#dnsRecordsTable tbody');
    if (!tbody) return;
    tbody.textContent = '';

    if (!selectedDomain) {
        const tr = el('tr');
        tr.appendChild(
            el(
                'td',
                { colspan: 5, className: 'table-empty' },
                'Select an active domain above to view DNS records.',
            ),
        );
        tbody.appendChild(tr);
        return;
    }

    const needle = dnsRecordSearch.trim().toLowerCase();
    const filtered = currentDnsRecords.filter((r) => {
        if (dnsTypeFilter !== 'ALL' && String(r.type).toUpperCase() !== dnsTypeFilter) {
            return false;
        }
        if (!needle) return true;
        return (
            String(r.name || '').toLowerCase().includes(needle) ||
            String(r.data || '').toLowerCase().includes(needle) ||
            String(r.type || '').toLowerCase().includes(needle)
        );
    });

    if (filtered.length === 0) {
        const tr = el('tr');
        tr.appendChild(
            el('td', { colspan: 5, className: 'table-empty' }, 'No matching DNS records.'),
        );
        tbody.appendChild(tr);
        return;
    }

    for (const r of filtered) {
        const tr = el('tr');
        const typeTd = el('td');
        typeTd.appendChild(el('span', { className: 'state-text state-warn' }, r.type));
        tr.appendChild(typeTd);

        tr.appendChild(el('td', { className: 'mono' }, r.name));
        tr.appendChild(el('td', { className: 'mono cell-truncate', title: r.data }, r.data));
        tr.appendChild(el('td', { className: 'mono col-right' }, String(r.ttl)));

        const actionsTd = el('td', { className: 'col-right' });
        actionsTd.appendChild(
            el(
                'button',
                {
                    type: 'button',
                    className: 'btn btn-danger btn-sm',
                    'data-action': 'delete-dns-record',
                    'data-domain': selectedDomain,
                    'data-type': r.type,
                    'data-name': r.name,
                },
                'Delete',
            ),
        );
        tr.appendChild(actionsTd);
        tbody.appendChild(tr);
    }
}

async function createQuickDNS() {
    const domain = document.getElementById('quickDnsDomain').value.trim();
    const type = document.getElementById('quickDnsType').value;
    const name = document.getElementById('quickDnsName').value.trim();
    const data = document.getElementById('quickDnsValue').value.trim();
    const ttl = parseInt(document.getElementById('quickDnsTtl').value, 10) || 600;

    if (!domain || !name || !data) {
        showToast('Fill in domain, name, and value', 'warning');
        return;
    }

    await withBusy(document.getElementById('createQuickDnsBtn'), async () => {
    try {
        await api('POST', `/godaddy/domains/${encodeURIComponent(domain)}/records`, {
            type,
            name,
            data,
            ttl,
        });
        showToast(`Created ${type} record "${name}"`, 'success');
        document.getElementById('quickDnsValue').value = '';
        loadDNSRecords(domain);
    } catch (e) {
        showToast(e.message, 'error');
    }
    });
}

async function deleteDNSRecord(domain, type, name) {
    const ok = await askConfirm(
        'Delete DNS Record',
        `Delete every ${type} record named "${name}" on ${domain}? GoDaddy removes all values for this name and type, and the change is live immediately.`,
        'Delete Record',
    );
    if (!ok) return;

    try {
        await api(
            'DELETE',
            `/godaddy/domains/${encodeURIComponent(domain)}/records/${encodeURIComponent(type)}/${encodeURIComponent(name)}`,
        );
        showToast(`Deleted ${type} record "${name}"`, 'success');
        loadDNSRecords(domain);
    } catch (e) {
        showToast(e.message, 'error');
    }
}

// --- Navigation & Mobile Sidebar ---
function navigateTo(page) {
    if (!PAGE_TITLES[page]) return;

    document.querySelectorAll('#navLinks a').forEach((link) => {
        link.classList.toggle('active', link.dataset.page === page);
    });
    document.querySelectorAll('.page').forEach((section) => {
        section.classList.toggle('active', section.id === `page-${page}`);
    });

    const titleEl = document.getElementById('currentPageTitle');
    if (titleEl) titleEl.textContent = PAGE_TITLES[page];
    document.title = `${PAGE_TITLES[page]} · ProxyGate`;
    if (location.hash !== `#${page}`) {
        history.replaceState(null, '', `#${page}`);
    }

    if (page === 'certificates') {
        loadChallenges();
        loadCertsStatus();
    } else if (page === 'dns') {
        loadGoDaddyDomains();
    } else if (page === 'settings') {
        loadSecurityStatus();
        loadPasswordPolicy();
    }

    closeSidebar();
}

function openSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    const btn = document.getElementById('hamburgerBtn');
    if (!sidebar) return;
    sidebar.classList.add('open');
    overlay.classList.add('visible');
    btn.classList.add('active');
    btn.setAttribute('aria-expanded', 'true');
    document.body.style.overflow = 'hidden';
}

function closeSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    const btn = document.getElementById('hamburgerBtn');
    if (!sidebar) return;
    sidebar.classList.remove('open');
    overlay.classList.remove('visible');
    if (btn) {
        btn.classList.remove('active');
        btn.setAttribute('aria-expanded', 'false');
    }
    document.body.style.overflow = '';
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (sidebar && sidebar.classList.contains('open')) {
        closeSidebar();
    } else {
        openSidebar();
    }
}

// --- Clipboard Copy ---
async function copyFromElement(targetId) {
    const target = document.getElementById(targetId);
    if (!target || !target.textContent) return;
    try {
        await navigator.clipboard.writeText(target.textContent);
        showToast('Copied to clipboard', 'success');
    } catch {
        showToast('Unable to copy automatically — select text manually', 'warning');
    }
}

// --- Event Wiring ---
function bindEvents() {
    // Sidebar nav
    document.querySelectorAll('#navLinks a').forEach((a) => {
        a.addEventListener('click', (e) => {
            e.preventDefault();
            navigateTo(a.dataset.page);
        });
    });

    // Mobile drawer
    document.getElementById('hamburgerBtn')?.addEventListener('click', toggleSidebar);
    document.getElementById('sidebarOverlay')?.addEventListener('click', closeSidebar);

    // Topbar / mobile Add Route buttons
    document.getElementById('topbarAddRouteBtn')?.addEventListener('click', showAddRouteModal);
    document.getElementById('mobileAddRouteBtn')?.addEventListener('click', showAddRouteModal);

    // Modal close buttons & backdrop click
    document.querySelectorAll('[data-close-modal]').forEach((btn) => {
        btn.addEventListener('click', () => closeModal(btn.dataset.closeModal));
    });
    document.querySelectorAll('.modal').forEach((modal) => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal(modal.id);
        });
    });

    // Confirmation modal
    document.getElementById('confirmCancelBtn')?.addEventListener('click', () => finishConfirm(false));
    document.getElementById('confirmAcceptBtn')?.addEventListener('click', () => finishConfirm(true));

    // Route form submit
    document.getElementById('routeForm')?.addEventListener('submit', saveRoute);

    // Dashboard search & event log controls
    document.getElementById('dashboardRouteSearch')?.addEventListener('input', (e) => {
        dashboardSearch = e.target.value;
        renderDashboardRoutes();
    });
    document.getElementById('eventFilterInput')?.addEventListener('input', (e) => {
        eventFilter = e.target.value;
        renderEvents();
    });
    document.getElementById('clearEventsBtn')?.addEventListener('click', () => {
        eventHistory = [];
        renderEvents();
    });

    // Routes search & segmented filter
    document.getElementById('routeSearchInput')?.addEventListener('input', (e) => {
        routeSearch = e.target.value;
        renderRoutes();
    });
    document.getElementById('routeFilterGroup')?.addEventListener('click', (e) => {
        const btn = e.target.closest('button[data-filter]');
        if (!btn) return;
        routeFilter = btn.dataset.filter;
        document.querySelectorAll('#routeFilterGroup .seg-btn').forEach((b) => {
            b.classList.toggle('active', b === btn);
        });
        renderRoutes();
    });

    // Certificates controls
    document.getElementById('requestCertBtn')?.addEventListener('click', requestCertificate);
    document.getElementById('completeCertBtn')?.addEventListener('click', completeCertificate);
    document.getElementById('resetAcmeBtn')?.addEventListener('click', resetAcmeWizard);
    document.getElementById('refreshChallengesBtn')?.addEventListener('click', () => {
        loadChallenges();
        loadCertsStatus();
    });

    // Copy buttons
    document.querySelectorAll('.copy-btn').forEach((btn) => {
        btn.addEventListener('click', () => copyFromElement(btn.dataset.copyTarget));
    });

    // GoDaddy DNS controls
    document.getElementById('saveGoDaddyBtn')?.addEventListener('click', saveGoDaddyConfig);
    document.getElementById('verifyGoDaddyBtn')?.addEventListener('click', verifyGoDaddy);
    document.getElementById('refreshDomainsBtn')?.addEventListener('click', loadGoDaddyDomains);
    document.getElementById('createQuickDnsBtn')?.addEventListener('click', createQuickDNS);

    document.getElementById('domainSearchInput')?.addEventListener('input', (e) => {
        domainSearch = e.target.value;
        renderDomains();
    });

    document.getElementById('domainStatusFilter')?.addEventListener('click', (e) => {
        const btn = e.target.closest('button[data-include-inactive]');
        if (!btn) return;
        includeInactiveDomains = btn.dataset.includeInactive === 'true';
        document.querySelectorAll('#domainStatusFilter .seg-btn').forEach((b) => {
            b.classList.toggle('active', b === btn);
        });
        loadGoDaddyDomains();
    });

    document.getElementById('dnsRecordsDomain')?.addEventListener('change', (e) => {
        loadDNSRecords(e.target.value);
    });
    document.getElementById('dnsRecordTypeFilter')?.addEventListener('change', (e) => {
        dnsTypeFilter = e.target.value;
        renderDNSRecords();
    });
    document.getElementById('dnsRecordSearch')?.addEventListener('input', (e) => {
        dnsRecordSearch = e.target.value;
        renderDNSRecords();
    });

    // Track unsaved edits per settings section
    for (const [form, ids] of Object.entries(FORM_FIELDS)) {
        for (const id of ids) {
            const input = document.getElementById(id);
            if (!input) continue;
            input.addEventListener('input', () => dirtyForms.add(form));
            input.addEventListener('change', () => dirtyForms.add(form));
        }
    }

    document.getElementById('acmeDomain')?.addEventListener('input', updateAcmeDomainNote);

    // Settings controls
    document.getElementById('saveServerConfigBtn')?.addEventListener('click', (e) =>
        withBusy(e.currentTarget, saveServerConfig),
    );
    document.getElementById('saveAcmeConfigBtn')?.addEventListener('click', (e) =>
        withBusy(e.currentTarget, saveACMEConfig),
    );
    document.getElementById('exportConfigBtn')?.addEventListener('click', exportConfigJson);

    // Delegated dynamic actions (routes, challenges, domains, DNS records)
    document.addEventListener('click', (e) => {
        const target = e.target.closest('[data-action]');
        if (!target) return;

        const action = target.dataset.action;
        if (action === 'open-add-route') {
            showAddRouteModal();
        } else if (action === 'edit-route') {
            editRoute(target.dataset.id);
        } else if (action === 'toggle-route') {
            toggleRoute(target.dataset.id);
        } else if (action === 'delete-route') {
            deleteRoute(target.dataset.id);
        } else if (action === 'request-tls') {
            const domain = target.dataset.domain || '';
            document.getElementById('acmeDomain').value = domain;
            showStep(1);
            navigateTo('certificates');
            updateAcmeDomainNote();
        } else if (action === 'resume-challenge') {
            const ch = challenges.find((c) => c.domain === target.dataset.domain);
            if (ch) {
                document.getElementById('acmeDomain').value = ch.domain;
                document.getElementById('dnsRecordName').textContent = ch.record_name || '';
                document.getElementById('dnsRecordValue').textContent = ch.record_value || '';
                showStep(2);
            }
        } else if (action === 'select-domain') {
            loadDNSRecords(target.dataset.domain);
        } else if (action === 'delete-dns-record') {
            deleteDNSRecord(target.dataset.domain, target.dataset.type, target.dataset.name);
        }
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && confirmResolver) {
            closeModal('confirmModal');
            return;
        }
        if (e.key === 'Escape') {
            closeModal('addRouteModal');
            closeModal('confirmModal');
            closeSidebar();
        }
    });
}

// --- Authentication ---
function setFormError(id, message) {
    const box = document.getElementById(id);
    if (!box) return;
    box.textContent = message || '';
    box.classList.toggle('hidden', !message);
}

function showAuthScreen(mode, status = {}) {
    authenticated = false;
    if (ws) {
        try { ws.close(); } catch { /* already closed */ }
    }
    const screen = document.getElementById('authScreen');
    screen.classList.remove('hidden');
    document.getElementById('authLoading').classList.add('hidden');
    document.getElementById('authTitle').textContent = mode === 'setup' ? 'Set up ProxyGate' : 'Sign in';
    document.getElementById('setupForm').classList.toggle('hidden', mode !== 'setup');
    document.getElementById('loginForm').classList.toggle('hidden', mode !== 'login');
    if (status.insecure_transport !== undefined) {
        document.getElementById('authInsecureWarning').classList.toggle('hidden', !status.insecure_transport);
    }
    if (status.setup_code_path) {
        document.getElementById('setupCodePath').textContent = status.setup_code_path;
    }
    setFormError('setupError', '');
    setFormError('loginError', '');
    document.getElementById(mode === 'setup' ? 'setupCode' : 'loginPassword')?.focus();
}

async function checkAuth() {
    let status;
    try {
        const resp = await fetch('/api/auth/status');
        status = await resp.json();
    } catch {
        document.getElementById('authLoading').textContent = 'Cannot reach ProxyGate. Retrying…';
        setTimeout(checkAuth, 3000);
        return;
    }
    if (status.setup_required) {
        showAuthScreen('setup', status);
    } else if (!status.authenticated) {
        showAuthScreen('login', status);
    } else {
        startApp();
    }
}

function startApp() {
    authenticated = true;
    document.getElementById('authScreen').classList.add('hidden');
    connectWebSocket();
    loadConfig();
    loadRoutes();
    loadChallenges();
    loadCertsStatus();
    loadSecurityStatus();
    const page = location.hash.replace('#', '');
    navigateTo(PAGE_TITLES[page] ? page : 'dashboard');
    appStarted = true;
}

async function submitSetup(event) {
    event.preventDefault();
    const password = document.getElementById('setupPassword').value;
    if (password !== document.getElementById('setupPasswordConfirm').value) {
        setFormError('setupError', 'The passwords do not match.');
        return;
    }
    setFormError('setupError', '');
    await withBusy(document.getElementById('setupSubmit'), async () => {
        try {
            await api('POST', '/auth/setup', {
                setup_code: document.getElementById('setupCode').value.trim(),
                password,
                strong_password_policy: document.getElementById('setupStrong').checked,
            });
            document.getElementById('setupForm').reset();
            showToast('Admin password set', 'success');
            startApp();
        } catch (e) {
            setFormError('setupError', e.message);
        }
    });
}

async function submitLogin(event) {
    event.preventDefault();
    setFormError('loginError', '');
    await withBusy(document.getElementById('loginSubmit'), async () => {
        try {
            await api('POST', '/auth/login', { password: document.getElementById('loginPassword').value });
            document.getElementById('loginForm').reset();
            startApp();
        } catch (e) {
            setFormError('loginError', e.message);
        }
    });
}

async function signOut() {
    try {
        await api('POST', '/auth/logout');
    } catch {
        // Signing out locally is enough if the server is unreachable.
    }
    showAuthScreen('login');
}

async function submitChangePassword(event) {
    event.preventDefault();
    const next = document.getElementById('newPassword').value;
    if (next !== document.getElementById('newPasswordConfirm').value) {
        setFormError('changePasswordError', 'The new passwords do not match.');
        return;
    }
    setFormError('changePasswordError', '');
    await withBusy(document.getElementById('changePasswordBtn'), async () => {
        try {
            await api('POST', '/auth/password', {
                current_password: document.getElementById('currentPassword').value,
                new_password: next,
            });
            document.getElementById('changePasswordForm').reset();
            showToast('Password changed. Other browsers are signed out.', 'success');
        } catch (e) {
            setFormError('changePasswordError', e.message);
        }
    });
}

async function loadPasswordPolicy() {
    const meta = document.getElementById('passwordPolicyMeta');
    if (!meta) return;
    try {
        const st = await api('GET', '/auth/status');
        meta.textContent = st.strong_password_policy ? 'Strong rules: 12+ characters' : 'Basic rules: 8+ characters';
    } catch {
        meta.textContent = '';
    }
}

function bindAuthEvents() {
    document.getElementById('setupForm')?.addEventListener('submit', submitSetup);
    // Let the browser enforce the same minimum the server will.
    document.getElementById('setupStrong')?.addEventListener('change', (e) => {
        const min = e.target.checked ? '12' : '8';
        document.getElementById('setupPassword').minLength = Number(min);
        document.getElementById('setupPasswordConfirm').minLength = Number(min);
    });
    document.getElementById('loginForm')?.addEventListener('submit', submitLogin);
    document.getElementById('signOutBtn')?.addEventListener('click', signOut);
    document.getElementById('changePasswordForm')?.addEventListener('submit', submitChangePassword);
}

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
    bindEvents();
    bindAuthEvents();
    window.addEventListener('hashchange', () => {
        const page = location.hash.replace('#', '');
        if (authenticated && PAGE_TITLES[page]) navigateTo(page);
    });
    checkAuth();
});
