// alerts.js

let allAlerts = [];
let filteredAlerts = [];
let currentPage = 1;
const PAGE_SIZE = 50;
let currentSort = { col: 'timestamp_iso', asc: false };

let activeAlert = null;

document.addEventListener("DOMContentLoaded", () => {
    // Initial fetch (load up to 200)
    fetchAlerts();

    // Setup Filters
    setupFilters();
    
    // Setup Drawer
    setupDrawer();
});

async function fetchAlerts() {
    try {
        const response = await fetch('/api/v1/alerts?page=1&page_size=200');
        const data = await response.json();
        
        allAlerts = data.alerts || [];
        // Optional mock data for empty state if no alerts
        if (allAlerts.length === 0) {
            allAlerts = [
                {
                    id: "mock-123", severity: "CRITICAL", timestamp_iso: new Date().toISOString(),
                    source_ip: "45.33.32.156", method: "POST", path: "/api/users/login",
                    attack_type: "SQL Injection", detection_source: "RULE", rule_id: "942100",
                    confidence: null, payload_snippet: "username=admin' OR '1'='1"
                }
            ];
        }
        
        applyFilters();
    } catch (err) {
        console.error("Failed to fetch alerts", err);
    }
}

function setupFilters() {
    const searchInput = document.getElementById('filter-search');
    const sourceSelect = document.getElementById('filter-source');
    const statusSelect = document.getElementById('filter-status');
    const clearBtn = document.getElementById('btn-clear-filters');
    const sevButtons = document.querySelectorAll('[data-filter="severity"]');

    searchInput.addEventListener('input', applyFilters);
    sourceSelect.addEventListener('change', applyFilters);
    statusSelect.addEventListener('change', applyFilters);
    
    sevButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            sevButtons.forEach(b => {
                b.classList.remove('bg-[var(--bg-elevated)]', 'text-[var(--text-primary)]', 'active-filter');
                b.classList.add('text-[var(--text-secondary)]');
            });
            e.currentTarget.classList.add('bg-[var(--bg-elevated)]', 'text-[var(--text-primary)]', 'active-filter');
            e.currentTarget.classList.remove('text-[var(--text-secondary)]');
            applyFilters();
        });
    });

    clearBtn.addEventListener('click', () => {
        searchInput.value = '';
        sourceSelect.value = '';
        statusSelect.value = '';
        sevButtons.forEach(b => {
            b.classList.remove('bg-[var(--bg-elevated)]', 'text-[var(--text-primary)]', 'active-filter');
            b.classList.add('text-[var(--text-secondary)]');
        });
        sevButtons[0].classList.add('bg-[var(--bg-elevated)]', 'text-[var(--text-primary)]', 'active-filter');
        sevButtons[0].classList.remove('text-[var(--text-secondary)]');
        applyFilters();
    });

    // Setup sorting
    document.querySelectorAll('th[data-sort]').forEach(th => {
        th.addEventListener('click', () => {
            const col = th.getAttribute('data-sort');
            if (currentSort.col === col) {
                currentSort.asc = !currentSort.asc;
            } else {
                currentSort.col = col;
                currentSort.asc = true;
            }
            renderTable();
        });
    });

    // Pagination
    document.getElementById('btn-page-prev').addEventListener('click', () => {
        if (currentPage > 1) { currentPage--; renderTable(); }
    });
    document.getElementById('btn-page-next').addEventListener('click', () => {
        const maxPage = Math.ceil(filteredAlerts.length / PAGE_SIZE);
        if (currentPage < maxPage) { currentPage++; renderTable(); }
    });
}

function applyFilters() {
    const q = document.getElementById('filter-search').value.toLowerCase();
    const source = document.getElementById('filter-source').value;
    const status = document.getElementById('filter-status').value;
    const sev = document.querySelector('[data-filter="severity"].active-filter').getAttribute('data-val');

    filteredAlerts = allAlerts.filter(a => {
        if (sev && a.severity !== sev) return false;
        if (source && a.detection_source !== source) return false;
        // status is mocked on client for prototype
        const aStatus = a._mock_status || "New";
        if (status && aStatus !== status) return false;
        
        if (q) {
            const str = Object.values(a).join(' ').toLowerCase();
            if (!str.includes(q)) return false;
        }
        return true;
    });

    currentPage = 1;
    updateCounts();
    renderTable();
}

function updateCounts() {
    let c = 0, h = 0, m = 0;
    filteredAlerts.forEach(a => {
        if (a.severity === 'CRITICAL') c++;
        else if (a.severity === 'HIGH') h++;
        else if (a.severity === 'MEDIUM') m++;
    });
    
    document.getElementById('count-crit').textContent = c;
    document.getElementById('count-high').textContent = h;
    document.getElementById('count-med').textContent = m;
    document.getElementById('count-visible').textContent = filteredAlerts.length;
}

function renderTable() {
    // Sort
    filteredAlerts.sort((a, b) => {
        let valA = a[currentSort.col] || '';
        let valB = b[currentSort.col] || '';
        if (valA < valB) return currentSort.asc ? -1 : 1;
        if (valA > valB) return currentSort.asc ? 1 : -1;
        return 0;
    });

    const tbody = document.getElementById('alerts-tbody');
    if (!tbody) return;

    if (filteredAlerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="10" class="text-center py-8 text-[var(--text-secondary)]">No alerts match the filters</td></tr>`;
        document.getElementById('page-indicator').textContent = `Page 1 / 1`;
        document.getElementById('btn-page-prev').disabled = true;
        document.getElementById('btn-page-next').disabled = true;
        return;
    }

    const start = (currentPage - 1) * PAGE_SIZE;
    const end = Math.min(start + PAGE_SIZE, filteredAlerts.length);
    const pageData = filteredAlerts.slice(start, end);

    let html = '';
    pageData.forEach(a => {
        let dotColor = "bg-[var(--success)]";
        if (a.severity === "CRITICAL") dotColor = "bg-[var(--critical)]";
        else if (a.severity === "HIGH") dotColor = "bg-[var(--warning)]";
        else if (a.severity === "MEDIUM") dotColor = "bg-[#D97706]";
        else if (a.severity === "LOW") dotColor = "bg-[var(--info)]";
        
        const badgeClass = `badge-${a.severity.toLowerCase()}`;
        
        const methodBadge = `badge-${a.method?.toLowerCase() || 'get'}`;
        const sourceChip = a.detection_source === 'RULE' ? 
            '<span class="text-[9px] px-1 bg-[var(--accent-primary)]/20 text-[var(--accent-primary)] border border-[var(--accent-primary)]/30 rounded">SIG</span>' : 
            '<span class="text-[9px] px-1 bg-[var(--info)]/20 text-[var(--info)] border border-[var(--info)]/30 rounded">ML</span>';
            
        const confBarHtml = a.confidence ? `
            <div class="flex items-center gap-1 w-16">
                <div class="w-full bg-[var(--bg-deep)] h-1 rounded overflow-hidden">
                    <div class="bg-[var(--info)] h-full" style="width: ${a.confidence*100}%"></div>
                </div>
                <span class="text-[9px]">${(a.confidence*100).toFixed(0)}%</span>
            </div>` : '-';
            
        const rowStatus = a._mock_status || "New";

        html += `
        <tr class="hover:bg-[var(--bg-elevated)] transition-colors group cursor-pointer" onclick="openDrawer('${a.id}')">
            <td class="px-4 py-2 flex items-center gap-2">
                <div class="w-2 h-2 rounded-full ${dotColor}"></div>
                <span class="px-2 py-0.5 rounded-full text-[10px] ${badgeClass}">${a.severity}</span>
            </td>
            <td class="px-4 py-2 text-[var(--text-secondary)] font-mono-code">${new Date(a.timestamp_iso || new Date()).toLocaleString()}</td>
            <td class="px-4 py-2 font-mono-code">${a.source_ip || 'unknown'}</td>
            <td class="px-4 py-2"><span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${methodBadge}">${a.method || 'GET'}</span></td>
            <td class="px-4 py-2 truncate max-w-[200px]" title="${a.path}">${a.path}</td>
            <td class="px-4 py-2 font-semibold">${a.attack_type || 'Anomaly'}</td>
            <td class="px-4 py-2">${sourceChip}</td>
            <td class="px-4 py-2">${confBarHtml}</td>
            <td class="px-4 py-2"><span class="px-1.5 py-0.5 rounded bg-[var(--bg-elevated)] text-[var(--text-secondary)] border border-[var(--border)] text-[10px]">${rowStatus}</span></td>
            <td class="px-4 py-2 text-right">
                <button class="btn btn-outline text-xs h-6 px-3" onclick="event.stopPropagation(); openDrawer('${a.id}')">Inspect</button>
            </td>
        </tr>
        `;
    });

    tbody.innerHTML = html;

    // Update pagination
    const maxPage = Math.ceil(filteredAlerts.length / PAGE_SIZE) || 1;
    document.getElementById('page-indicator').textContent = `Page ${currentPage} / ${maxPage}`;
    document.getElementById('btn-page-prev').disabled = currentPage === 1;
    document.getElementById('btn-page-next').disabled = currentPage === maxPage;
}

// ---------------- Drawer Logic ----------------

function setupDrawer() {
    document.getElementById('btn-close-drawer').addEventListener('click', closeDrawer);
    document.getElementById('drawer-overlay').addEventListener('click', closeDrawer);
    
    document.getElementById('btn-block-ip').addEventListener('click', () => {
        if(typeof showToast === 'function') {
            showToast({severity: 'INFO', attack_type: 'IP Blocked', source_ip: activeAlert.source_ip, detail: "Logged to watchlist"});
        }
    });

    document.getElementById('btn-flag-fp').addEventListener('click', () => {
        if(activeAlert) activeAlert._mock_status = "False Positive";
        closeDrawer();
        renderTable();
    });

    document.getElementById('btn-ack').addEventListener('click', () => {
        if(activeAlert) activeAlert._mock_status = "Acknowledged";
        closeDrawer();
        renderTable();
    });

    document.getElementById('btn-export-json').addEventListener('click', () => {
        if(!activeAlert) return;
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(activeAlert, null, 2));
        const a = document.createElement('a');
        a.href = dataStr;
        a.download = `alert_${activeAlert.id}.json`;
        a.click();
    });
}

window.openDrawer = function(id) {
    activeAlert = allAlerts.find(a => a.id === id);
    if (!activeAlert) return;

    // Populate Data
    document.getElementById('drawer-id').textContent = activeAlert.id || 'N/A';
    document.getElementById('drawer-sev-badge').textContent = activeAlert.severity;
    document.getElementById('drawer-sev-badge').className = `px-2 py-0.5 rounded text-[10px] font-bold badge-${activeAlert.severity.toLowerCase()}`;
    
    document.getElementById('drawer-timestamp').textContent = new Date(activeAlert.timestamp_iso || new Date()).toLocaleString();
    document.getElementById('drawer-status').textContent = activeAlert._mock_status || "New";
    
    document.getElementById('drawer-pattern').textContent = activeAlert.attack_type || "ML Anomaly Detected";
    
    // Map OWASP Category
    let owaspCat = "A10:2021 Server-Side Request Forgery / Unknown";
    const rid = activeAlert.rule_id ? String(activeAlert.rule_id) : "";
    if(rid.startsWith("942")) owaspCat = "A03:2021 Injection (SQL)";
    else if(rid.startsWith("941")) owaspCat = "A03:2021 Injection (XSS)";
    else if(rid.startsWith("930")) owaspCat = "A05:2021 Security Misconfig (Path Traversal)";
    document.getElementById('drawer-owasp').textContent = owaspCat;

    if (activeAlert.detection_source === 'RULE') {
        document.getElementById('drawer-rule-row').classList.remove('hidden');
        document.getElementById('drawer-rule-id').textContent = activeAlert.rule_id;
        document.getElementById('drawer-conf-row').classList.add('hidden');
    } else {
        document.getElementById('drawer-rule-row').classList.add('hidden');
        document.getElementById('drawer-conf-row').classList.remove('hidden');
        const cVal = activeAlert.confidence ? activeAlert.confidence * 100 : 0;
        document.getElementById('drawer-conf-bar').style.width = cVal + '%';
        document.getElementById('drawer-conf-val').textContent = cVal.toFixed(1) + '%';
    }

    document.getElementById('drawer-ip').textContent = activeAlert.source_ip || 'unknown';

    // Build Payload block
    const m = activeAlert.method || 'GET';
    const p = activeAlert.path || '/';
    let raw = `[${m}] ${p} HTTP/1.1\nHost: example.com\nUser-Agent: Mozill...`;
    
    // Highlight Snippet if provided
    if (activeAlert.payload_snippet) {
         raw += `\n\n${activeAlert.payload_snippet}`;
         // Simple highlight replace
         const safeSnip = activeAlert.payload_snippet.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
         const re = new RegExp(`(${safeSnip})`, 'g');
         const escapeHtml = (unsafe) => unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
         raw = escapeHtml(raw).replace(re, '<span class="payload-highlight">$1</span>');
    } else {
         const escapeHtml = (unsafe) => unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
         raw = escapeHtml(raw);
    }
    
    document.getElementById('drawer-payload').innerHTML = raw;

    // Show 
    document.getElementById('drawer-overlay').classList.remove('hidden');
    // small reflow trick
    void document.getElementById('drawer-overlay').offsetWidth;
    document.getElementById('drawer-overlay').classList.add('opacity-100');
    document.getElementById('alert-drawer').classList.remove('translate-x-full');
}

function closeDrawer() {
    document.getElementById('drawer-overlay').classList.remove('opacity-100');
    document.getElementById('alert-drawer').classList.add('translate-x-full');
    setTimeout(() => {
        document.getElementById('drawer-overlay').classList.add('hidden');
    }, 300);
}
