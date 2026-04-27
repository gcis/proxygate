// ProxyGate Admin UI

let ws = null;
let config = null;
let routes = [];

// --- WebSocket ---
function connectWebSocket() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}/ws`);

    ws.onopen = () => {
        updateWSStatus(true);
        showToast('Connected to ProxyGate', 'success');
    };

    ws.onclose = () => {
        updateWSStatus(false);
        setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = () => {
        updateWSStatus(false);
    };

    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        handleWSMessage(msg);
    };
}

function updateWSStatus(connected) {
    const el = document.getElementById('wsStatus');
    const dot = el.querySelector('.status-dot');
    const text = el.querySelector('span:last-child');
    dot.className = `status-dot ${connected ? 'connected' : 'disconnected'}`;
    text.textContent = connected ? 'Connected' : 'Disconnected';
}

function handleWSMessage(msg) {
    addEvent(msg.type, JSON.stringify(msg.payload).substring(0, 100));

    switch (msg.type) {
        case 'config_changed':
            loadConfig();
            loadRoutes();
            break;
        case 'route_added':
        case 'route_updated':
        case 'route_deleted':
            loadRoutes();
            showToast(`Route ${msg.type.replace('route_', '')}`, 'info');
            break;
        case 'cert_obtained':
            showToast(`Certificate obtained for ${msg.payload.domain}`, 'success');
            showStep(3);
            document.getElementById('certDetails').innerHTML =
                `<p>Cert: <code>${msg.payload.cert}</code></p>`;
            loadRoutes();
            break;
        case 'acme_challenge':
            showToast('ACME challenge created', 'info');
            break;
        case 'dns_record_created':
        case 'auto_dns_created':
            showToast('DNS record created', 'success');
            break;
    }
}

// --- API Calls ---
async function api(method, path, body = null) {
    const opts = {
        method,
        headers: { 'Content-Type': 'application/json' },
    };
    if (body) opts.body = JSON.stringify(body);

    const resp = await fetch(`/api${path}`, opts);
    const data = await resp.json();

    if (!resp.ok) {
        throw new Error(data.error || `HTTP ${resp.status}`);
    }
    return data;
}

// --- Config ---
async function loadConfig() {
    try {
        config = await api('GET', '/config');
        updateDashboardStats();
        populateSettings();
    } catch (e) {
        showToast('Failed to load config: ' + e.message, 'error');
    }
}

function populateSettings() {
    if (!config) return;
    document.getElementById('httpPort').value = config.server.http_port;
    document.getElementById('httpsPort').value = config.server.https_port;
    document.getElementById('adminPort').value = config.server.admin_port;
    document.getElementById('adminHost').value = config.server.admin_host;
    document.getElementById('acmeEmail').value = config.acme.email || '';
    document.getElementById('acmeStaging').checked = config.acme.use_staging;

    const networks = config.server.allowed_networks || [];
    document.getElementById('allowedNetworks').value = networks.join(', ');

    if (config.godaddy.api_key) {
        document.getElementById('gdApiKey').value = config.godaddy.api_key;
    }
}

async function saveServerConfig() {
    try {
        const networksRaw = document.getElementById('allowedNetworks').value;
        const allowedNetworks = networksRaw
            ? networksRaw.split(',').map(s => s.trim()).filter(s => s.length > 0)
            : [];
        await api('PUT', '/config/server', {
            http_port: parseInt(document.getElementById('httpPort').value),
            https_port: parseInt(document.getElementById('httpsPort').value),
            admin_port: parseInt(document.getElementById('adminPort').value),
            admin_host: document.getElementById('adminHost').value,
            allowed_networks: allowedNetworks,
        });
        showToast('Server config saved', 'success');
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

async function saveACMEConfig() {
    try {
        const staging = document.getElementById('acmeStaging').checked;
        await api('PUT', '/acme/config', {
            email: document.getElementById('acmeEmail').value,
            directory: staging
                ? 'https://acme-staging-v02.api.letsencrypt.org/directory'
                : 'https://acme-v02.api.letsencrypt.org/directory',
            cert_dir: config.acme.cert_dir || './certs',
            use_staging: staging,
        });
        showToast('ACME config saved', 'success');
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

// --- Routes ---
async function loadRoutes() {
    try {
        routes = await api('GET', '/routes');
        renderRoutes();
        updateDashboardStats();
        renderDashboardRoutes();
    } catch (e) {
        showToast('Failed to load routes: ' + e.message, 'error');
    }
}

function renderRoutes() {
    const container = document.getElementById('routesList');
    if (!routes || routes.length === 0) {
        container.innerHTML = '<div class="card"><p class="help-text">No routes configured. Click "Add Route" to get started.</p></div>';
        return;
    }

    container.innerHTML = routes.map(r => `
        <div class="route-card">
            <div class="route-header">
                <div>
                    <div class="route-name">${esc(r.name || r.domain)}</div>
                    <div class="route-domain">${esc(r.domain)}</div>
                </div>
            </div>
            <div class="route-target">&rarr; ${esc(r.target_host)}:${r.target_port}</div>
            <div class="route-badges">
                <span class="badge ${r.enabled ? 'badge-success' : 'badge-danger'}">${r.enabled ? 'Active' : 'Disabled'}</span>
                ${r.tls_enabled ? '<span class="badge badge-info">TLS</span>' : ''}
                ${r.auto_cert ? '<span class="badge badge-warning">Auto-Cert</span>' : ''}
            </div>
            <div class="route-actions">
                <button class="btn btn-sm btn-secondary" onclick="editRoute('${r.id}')">Edit</button>
                <button class="btn btn-sm btn-danger" onclick="deleteRoute('${r.id}')">Delete</button>
            </div>
        </div>
    `).join('');
}

function renderDashboardRoutes() {
    const tbody = document.querySelector('#dashboardRoutes tbody');
    if (!routes || routes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No routes</td></tr>';
        return;
    }

    tbody.innerHTML = routes.map(r => `
        <tr>
            <td>${esc(r.domain)}</td>
            <td>${esc(r.target_host)}:${r.target_port}</td>
            <td>${r.tls_enabled ? '<span class="badge badge-info">Yes</span>' : '<span class="badge badge-danger">No</span>'}</td>
            <td><span class="badge ${r.enabled ? 'badge-success' : 'badge-danger'}">${r.enabled ? 'Active' : 'Off'}</span></td>
        </tr>
    `).join('');
}

function updateDashboardStats() {
    if (!routes) return;
    document.getElementById('activeRoutes').textContent = routes.filter(r => r.enabled).length;
    document.getElementById('tlsRoutes').textContent = routes.filter(r => r.tls_enabled).length;

    const gdStatus = config && config.godaddy.api_key ? 'Connected' : 'Not configured';
    document.getElementById('godaddyStatus').textContent = gdStatus;
}

function showAddRouteModal() {
    document.getElementById('editRouteId').value = '';
    document.getElementById('routeModalTitle').textContent = 'Add Proxy Route';
    document.getElementById('routeName').value = '';
    document.getElementById('routeDomain').value = '';
    document.getElementById('routeTargetHost').value = '127.0.0.1';
    document.getElementById('routeTargetPort').value = '';
    document.getElementById('routeEnabled').checked = true;
    document.getElementById('routeTLS').checked = false;
    document.getElementById('addRouteModal').classList.remove('hidden');
}

function editRoute(id) {
    const route = routes.find(r => r.id === id);
    if (!route) return;

    document.getElementById('editRouteId').value = id;
    document.getElementById('routeModalTitle').textContent = 'Edit Proxy Route';
    document.getElementById('routeName').value = route.name || '';
    document.getElementById('routeDomain').value = route.domain;
    document.getElementById('routeTargetHost').value = route.target_host;
    document.getElementById('routeTargetPort').value = route.target_port;
    document.getElementById('routeEnabled').checked = route.enabled;
    document.getElementById('routeTLS').checked = route.tls_enabled;
    document.getElementById('addRouteModal').classList.remove('hidden');
}

async function saveRoute() {
    const id = document.getElementById('editRouteId').value;
    const route = {
        name: document.getElementById('routeName').value,
        domain: document.getElementById('routeDomain').value,
        target_host: document.getElementById('routeTargetHost').value,
        target_port: parseInt(document.getElementById('routeTargetPort').value),
        enabled: document.getElementById('routeEnabled').checked,
        tls_enabled: document.getElementById('routeTLS').checked,
    };

    try {
        if (id) {
            await api('PUT', `/routes/${id}`, route);
            showToast('Route updated', 'success');
        } else {
            await api('POST', '/routes', route);
            showToast('Route created', 'success');
        }
        closeModal('addRouteModal');
        loadRoutes();
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

async function deleteRoute(id) {
    if (!confirm('Delete this route?')) return;
    try {
        await api('DELETE', `/routes/${id}`);
        showToast('Route deleted', 'success');
        loadRoutes();
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

// --- ACME ---
async function requestCertificate() {
    const domain = document.getElementById('acmeDomain').value;
    if (!domain) {
        showToast('Enter a domain', 'warning');
        return;
    }

    try {
        const result = await api('POST', '/acme/request', { domain });
        document.getElementById('dnsRecordName').textContent = result.record_name;
        document.getElementById('dnsRecordValue').textContent = result.record_value;
        showStep(2);

        const autoDNS = document.getElementById('acmeAutoDNS').checked;
        if (autoDNS) {
            document.getElementById('autoDNSStatus').textContent = 'Auto-creating DNS record via GoDaddy...';
            document.getElementById('autoDNSStatus').classList.remove('hidden');
        }

        showToast('DNS challenge created. Create the TXT record shown.', 'info');
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

async function completeCertificate() {
    const domain = document.getElementById('acmeDomain').value;
    const autoDNS = document.getElementById('acmeAutoDNS').checked;

    document.getElementById('certProgress').classList.remove('hidden');

    try {
        const result = await api('POST', '/acme/complete', { domain, auto_dns: autoDNS });
        showStep(3);
        document.getElementById('certDetails').innerHTML = `
            <p><strong>Certificate:</strong> <code>${result.cert_file}</code></p>
            <p><strong>Key:</strong> <code>${result.key_file}</code></p>
        `;
        showToast('Certificate issued!', 'success');
    } catch (e) {
        showToast('Verification failed: ' + e.message, 'error');
        document.getElementById('certProgress').classList.add('hidden');
    }
}

async function loadChallenges() {
    try {
        const challenges = await api('GET', '/acme/challenges');
        const container = document.getElementById('challengesList');
        if (!challenges || challenges.length === 0) {
            container.innerHTML = '<p class="help-text">No active challenges.</p>';
            return;
        }
        container.innerHTML = challenges.map(c => `
            <div class="domain-item">
                <span><strong>${esc(c.domain)}</strong> - ${c.status}</span>
                ${c.error ? `<span style="color:var(--danger)">${esc(c.error)}</span>` : ''}
            </div>
        `).join('');
    } catch (e) {
        console.error('Failed to load challenges:', e);
    }
}

function showStep(n) {
    for (let i = 1; i <= 3; i++) {
        document.getElementById(`step${i}`).classList.toggle('hidden', i > n);
    }
}

// --- GoDaddy ---
async function saveGoDaddyConfig() {
    try {
        await api('PUT', '/godaddy/config', {
            api_key: document.getElementById('gdApiKey').value,
            api_secret: document.getElementById('gdApiSecret').value,
            base_url: 'https://api.godaddy.com',
        });
        showToast('GoDaddy config saved', 'success');
        loadConfig();
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

async function verifyGoDaddy() {
    const el = document.getElementById('gdVerifyResult');
    el.classList.remove('hidden');
    el.innerHTML = '<span style="color:var(--text-muted)">Testing connection...</span>';

    try {
        await api('POST', '/godaddy/verify');
        el.innerHTML = '<span style="color:var(--success)">Connection successful!</span>';
        showToast('GoDaddy API connected', 'success');
    } catch (e) {
        el.innerHTML = `<span style="color:var(--danger)">Failed: ${esc(e.message)}</span>`;
    }
}

async function loadGoDaddyDomains() {
    try {
        const domains = await api('GET', '/godaddy/domains');
        const container = document.getElementById('gdDomainsList');
        const select = document.getElementById('dnsRecordsDomain');

        if (!domains || domains.length === 0) {
            container.innerHTML = '<p class="help-text">No domains found.</p>';
            return;
        }

        container.innerHTML = domains.map(d => `
            <div class="domain-item">
                <span><strong>${esc(d.domain)}</strong></span>
                <span class="badge ${d.status === 'ACTIVE' ? 'badge-success' : 'badge-warning'}">${d.status}</span>
            </div>
        `).join('');

        // Populate select
        select.innerHTML = '<option value="">Select a domain...</option>' +
            domains.map(d => `<option value="${esc(d.domain)}">${esc(d.domain)}</option>`).join('');
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

async function loadDNSRecords() {
    const domain = document.getElementById('dnsRecordsDomain').value;
    if (!domain) return;

    try {
        const records = await api('GET', `/godaddy/domains/${domain}/records`);
        const tbody = document.querySelector('#dnsRecordsTable tbody');

        tbody.innerHTML = records.map(r => `
            <tr>
                <td><span class="badge badge-info">${esc(r.type)}</span></td>
                <td>${esc(r.name)}</td>
                <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc(r.data)}</td>
                <td>${r.ttl}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="deleteDNSRecord('${esc(domain)}','${esc(r.type)}','${esc(r.name)}')">Delete</button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

async function createQuickDNS() {
    const domain = document.getElementById('quickDnsDomain').value;
    const type = document.getElementById('quickDnsType').value;
    const name = document.getElementById('quickDnsName').value;
    const data = document.getElementById('quickDnsValue').value;

    if (!domain || !name || !data) {
        showToast('Fill in all fields', 'warning');
        return;
    }

    try {
        await api('POST', `/godaddy/domains/${domain}/records`, { type, name, data, ttl: 600 });
        showToast('DNS record created', 'success');
        loadDNSRecords();
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

async function deleteDNSRecord(domain, type, name) {
    if (!confirm(`Delete ${type} record "${name}"?`)) return;
    try {
        await api('DELETE', `/godaddy/domains/${domain}/records/${type}/${name}`);
        showToast('Record deleted', 'success');
        loadDNSRecords();
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

// --- Navigation ---
document.querySelectorAll('.nav-links a').forEach(a => {
    a.addEventListener('click', (e) => {
        e.preventDefault();
        const page = a.dataset.page;

        document.querySelectorAll('.nav-links a').forEach(x => x.classList.remove('active'));
        a.classList.add('active');

        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        document.getElementById(`page-${page}`).classList.add('active');

        // Load data for the page
        if (page === 'certificates') loadChallenges();
        if (page === 'dns') loadGoDaddyDomains();

        // Close sidebar drawer on mobile after navigation
        closeSidebar();
    });
});

// --- UI Helpers ---
function closeModal(id) {
    document.getElementById(id).classList.add('hidden');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}

function addEvent(type, detail) {
    const log = document.getElementById('eventLog');
    const entry = document.createElement('div');
    entry.className = 'event-entry';
    const time = new Date().toLocaleTimeString();
    entry.innerHTML = `<span class="event-time">${time}</span><span class="event-type">${esc(type)}</span>${esc(detail)}`;
    log.prepend(entry);

    // Keep only last 50 events
    while (log.children.length > 50) {
        log.removeChild(log.lastChild);
    }
}

function esc(str) {
    if (str == null) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

// Close modals on escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal').forEach(m => m.classList.add('hidden'));
        closeSidebar();
    }
});

// --- Mobile sidebar toggle ---
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

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
    connectWebSocket();
    loadConfig();
    loadRoutes();
});
