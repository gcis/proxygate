document.addEventListener('DOMContentLoaded', () => {
    // Copy buttons on documentation code blocks
    document.querySelectorAll('[data-copy-code]').forEach((btn) => {
        btn.addEventListener('click', async () => {
            const targetId = btn.getAttribute('data-copy-code');
            const codeEl = targetId ? document.getElementById(targetId) : null;
            if (!codeEl) return;
            try {
                await navigator.clipboard.writeText(codeEl.textContent || '');
                const original = btn.textContent;
                btn.textContent = 'Copied';
                setTimeout(() => {
                    btn.textContent = original;
                }, 1600);
            } catch {
                btn.textContent = 'Select text';
            }
        });
    });

    // Live endpoint search on api.html
    const searchInput = document.getElementById('apiSearchInput');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            const needle = (e.target.value || '').trim().toLowerCase();
            document.querySelectorAll('.endpoint').forEach((card) => {
                const text = (card.textContent || '').toLowerCase();
                card.classList.toggle('hidden', Boolean(needle) && !text.includes(needle));
            });
            document.querySelectorAll('.endpoint-group').forEach((group) => {
                const visibleEndpoints = group.querySelectorAll('.endpoint:not(.hidden)');
                group.classList.toggle('hidden', Boolean(needle) && visibleEndpoints.length === 0);
            });
        });
    }
});

// ProxyGate serves these pages at /docs/, next to its admin UI. Anywhere else
// (GitHub Pages, a local preview, a file) there is no admin UI to open, so
// hide the links to it.
(() => {
    const servedByProxyGate = location.pathname === '/docs' || location.pathname.startsWith('/docs/');
    if (servedByProxyGate) return;
    document.querySelectorAll('[data-console-link]').forEach((a) => {
        a.hidden = true;
    });
    document.querySelectorAll('[data-pages-only]').forEach((a) => {
        a.hidden = false;
    });
})();
