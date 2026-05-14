// charts.js
// Handles rendering of Chart.js graphs and fetching dashboard data

let timelineChartInstance = null;
let donutChartInstance = null;
let confidenceChartInstance = null;

// Theming function as specified in prompt section 11
function applyChartTheme(isDark) {
    const textColor = isDark ? '#94A3B8' : '#475569';
    const gridColor = isDark ? '#1E2D45' : '#E2E8F0';
    
    if (typeof Chart !== 'undefined') {
        Chart.defaults.color = textColor;
        Chart.defaults.borderColor = gridColor;
        if(Chart.defaults.plugins && Chart.defaults.plugins.legend) {
            Chart.defaults.plugins.legend.labels.color = textColor;
        }
    }

    if(timelineChartInstance) timelineChartInstance.update();
    if(donutChartInstance) donutChartInstance.update();
    if(confidenceChartInstance) confidenceChartInstance.update();
}

async function initOverview() {
    // Determine initial theme
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    applyChartTheme(isDark);

    // Fetch and populate data once immediately
    await refreshOverviewData();

    // Event listeners for timeline pills
    document.querySelectorAll('#timeline-pills button').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            // update active styling
            document.querySelectorAll('#timeline-pills button').forEach(b => {
                b.classList.remove('bg-[var(--bg-elevated)]', 'text-[var(--text-primary)]', 'shadow-sm', 'active-pill');
                b.classList.add('text-[var(--text-secondary)]');
            });
            e.target.classList.add('bg-[var(--bg-elevated)]', 'text-[var(--text-primary)]', 'shadow-sm', 'active-pill');
            e.target.classList.remove('text-[var(--text-secondary)]');
            
            const range = e.target.getAttribute('data-range');
            await fetchAndDrawTimeline(range);
        });
    });

    // Auto refresh logic
    const refreshSelect = document.getElementById('auto-refresh-select');
    let refreshInterval = null;
    
    if (refreshSelect) {
        refreshSelect.addEventListener('change', (e) => {
            const val = parseInt(e.target.value);
            if(refreshInterval) clearInterval(refreshInterval);
            
            if(val > 0) {
                refreshInterval = setInterval(refreshOverviewData, val * 1000);
            }
        });
    }
}

async function refreshOverviewData() {
    const range = document.querySelector('#timeline-pills button.active-pill')?.getAttribute('data-range') || '24h';
    
    await Promise.all([
        fetchAndDrawTimeline(range),
        fetchAndDrawDonut(),
        fetchAndDrawStats(),
        fetchAndDrawTopIPs(),
        fetchAndDrawTopEndpoints(),
        fetchAndDrawLiveFeed(),
        fetchAndDrawMLMetrics(),
        buildHeatmap()
    ]);
}

async function fetchAndDrawTimeline(range) {
    try {
        const res = await fetch(`/dashboard/timeline?range=${range}`);
        const data = await res.json();
        const buckets = data.buckets;

        const labels = buckets.map(b => {
            const d = new Date(b.timestamp);
            return range === '24h' || range === '7d' ? 
                d.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}) :
                d.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}); // simplify for prototype
        });

        const ctx = document.getElementById('timelineChart')?.getContext('2d');
        if(!ctx) return;

        if (timelineChartInstance) {
            timelineChartInstance.data.labels = labels;
            timelineChartInstance.data.datasets[0].data = buckets.map(b => b.normal);
            timelineChartInstance.data.datasets[1].data = buckets.map(b => b.attacks);
            timelineChartInstance.data.datasets[2].data = buckets.map(b => b.anomalies);
            timelineChartInstance.update();
            return;
        }

        timelineChartInstance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Normal',
                        data: buckets.map(b => b.normal),
                        borderColor: '#3B82F6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        fill: true,
                        tension: 0.4
                    },
                    {
                        label: 'Attacks',
                        data: buckets.map(b => b.attacks),
                        borderColor: '#EF4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        fill: true,
                        tension: 0.4
                    },
                    {
                        label: 'Anomalies',
                        data: buckets.map(b => b.anomalies),
                        borderColor: '#F59E0B',
                        backgroundColor: 'rgba(245, 158, 11, 0.1)',
                        fill: true,
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false } },
                    y: { beginAtZero: true }
                }
            }
        });
    } catch(err) { console.error(err); }
}

async function fetchAndDrawDonut() {
    try {
        const res = await fetch(`/dashboard/attack-breakdown`);
        const data = await res.json();
        const attackTypes = data.attack_types;
        
        const ObjectKeys = Object.keys(attackTypes);
        const labels = ObjectKeys.filter(k => attackTypes[k] > 0);
        const counts = labels.map(k => attackTypes[k]);
        
        const colors = [];
        labels.forEach(l => {
            if(l === 'SQL Injection') colors.push('#EF4444');
            else if(l === 'XSS') colors.push('#F97316');
            else if(l === 'Path Traversal') colors.push('#EAB308');
            else if(l === 'Encoding Evasion') colors.push('#8B5CF6');
            else if(l === 'Protocol Anomaly') colors.push('#3B82F6');
            else if(l === 'Scanner') colors.push('#06B6D4');
            else if(l === 'Entropy Anomaly') colors.push('#10B981');
            else if(l === 'ML Anomaly') colors.push('#6366F1');
            else colors.push('#94A3B8');
        });

        if(labels.length === 0) {
            labels.push("No Data");
            counts.push(1);
            colors.push('rgba(148, 163, 184, 0.1)');
        }

        const ctx = document.getElementById('attackDonutChart')?.getContext('2d');
        if(!ctx) return;

        if (donutChartInstance) {
            donutChartInstance.data.labels = labels;
            donutChartInstance.data.datasets[0].data = counts;
            donutChartInstance.data.datasets[0].backgroundColor = colors;
            donutChartInstance.update();
            return;
        }

        donutChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: counts,
                    backgroundColor: colors,
                    borderWidth: 0,
                    cutout: '70%'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { 
                    legend: { position: 'right', labels: { boxWidth: 10 } }
                }
            }
        });
    } catch(err) { console.error(err); }
}

async function fetchAndDrawStats() {
    try {
        const res = await fetch(`/dashboard/stats`);
        const data = await res.json();
        
        const formatNum = (num) => new Intl.NumberFormat().format(num || 0);
        
        const kTotal = document.getElementById('kpi-total-requests');
        if(kTotal) kTotal.textContent = formatNum(data.total_requests);
        
        const kAttacks = document.getElementById('kpi-attacks');
        if(kAttacks) kAttacks.textContent = formatNum(data.attacks_detected);
        
        const kAnomalies = document.getElementById('kpi-anomalies');
        if(kAnomalies) kAnomalies.textContent = formatNum(data.anomaly_alerts);
        
        const kBenign = document.getElementById('kpi-benign');
        if(kBenign) kBenign.textContent = formatNum(data.benign_requests);
        
        const kFP = document.getElementById('kpi-false-positives');
        if(kFP) kFP.textContent = formatNum(data.false_positives_flagged);
        
        const kAcc = document.getElementById('kpi-accuracy');
        if(kAcc) kAcc.textContent = data.detection_accuracy_pct + '%';
        
        const kAccBar = document.getElementById('kpi-accuracy-bar');
        if(kAccBar) kAccBar.style.width = data.detection_accuracy_pct + '%';
        
    } catch(err) { console.error(err); }
}

async function fetchAndDrawTopIPs() {
    try {
        const res = await fetch(`/dashboard/top-ips`);
        const data = await res.json();
        
        const tbody = document.querySelector('#top-ips-table tbody');
        if(!tbody) return;
        
        if(!data.ips || data.ips.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="text-center py-4 text-[var(--text-secondary)]">No IP data</td></tr>`;
            return;
        }
        
        tbody.innerHTML = data.ips.map(ip => {
            const badgeClass = `badge-${ip.severity.toLowerCase()}`;
            return `
            <tr class="hover:bg-[var(--bg-elevated)] transition-colors">
                <td class="px-2 py-2 font-mono-code">${ip.ip}</td>
                <td class="px-2 py-2">${ip.attack_count}</td>
                <td class="px-2 py-2"><span class="px-2 py-0.5 rounded-full text-[10px] ${badgeClass}">${ip.severity}</span></td>
                <td class="px-2 py-2"><a href="/forensics?ip=${ip.ip}" class="btn btn-outline text-[10px] h-6 px-2 py-0">Inspect</a></td>
            </tr>`;
        }).join('');
    } catch(err) { console.error(err); }
}

async function fetchAndDrawTopEndpoints() {
    try {
        const res = await fetch(`/dashboard/top-endpoints`);
        const data = await res.json();
        
        const tbody = document.querySelector('#top-endpoints-table tbody');
        if(!tbody) return;
        
        if(!data.endpoints || data.endpoints.length === 0) {
            tbody.innerHTML = `<tr><td colspan="3" class="text-center py-4 text-[var(--text-secondary)]">No endpoint data</td></tr>`;
            return;
        }
        
        tbody.innerHTML = data.endpoints.map(ep => {
            const methodBadge = `badge-${ep.method.toLowerCase()}`;
            return `
            <tr class="hover:bg-[var(--bg-elevated)] transition-colors">
                <td class="px-2 py-2 flex items-center gap-2">
                    <span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${methodBadge}">${ep.method}</span>
                    <span class="truncate max-w-[150px]" title="${ep.path}">${ep.path}</span>
                </td>
                <td class="px-2 py-2">${ep.hit_count}</td>
                <td class="px-2 py-2"><span class="px-2 py-0.5 rounded-full text-[10px] bg-[var(--bg-elevated)] border border-[var(--border)]">${ep.most_common_attack}</span></td>
            </tr>`;
        }).join('');
    } catch(err) { console.error(err); }
}

async function fetchAndDrawLiveFeed() {
    try {
        const res = await fetch(`/dashboard/recent-alerts`);
        const data = await res.json();
        
        const container = document.getElementById('live-feed-container');
        if(!container) return;
        
        if(!data.alerts || data.alerts.length === 0) {
            container.innerHTML = `<div class="text-center py-4 text-[var(--text-secondary)]">Feed is empty</div>`;
            return;
        }
        
        container.innerHTML = data.alerts.map(a => generateFeedItemHTML(a)).join('');
    } catch(err) { console.error(err); }
}

function generateFeedItemHTML(a) {
    let dotColor = "bg-[var(--success)]";
    if(a.severity === "CRITICAL") dotColor = "bg-[var(--critical)]";
    else if(a.severity === "HIGH") dotColor = "bg-[var(--warning)]";
    else if(a.severity === "MEDIUM") dotColor = "bg-[#D97706]";
    else if(a.severity === "LOW") dotColor = "bg-[var(--info)]";
    
    const sourceChip = a.detection_source === 'RULE' ? 
        '<span class="text-[9px] px-1 bg-[var(--accent-primary)]/20 text-[var(--accent-primary)] border border-[var(--accent-primary)]/30 rounded">RULE</span>' : 
        '<span class="text-[9px] px-1 bg-[var(--info)]/20 text-[var(--info)] border border-[var(--info)]/30 rounded">ML</span>';
        
    return `
    <div class="flex items-start gap-3 text-xs border-b border-[var(--border)] pb-2 last:border-0" data-alert-id="${a.id}">
        <div class="w-2 h-2 rounded-full ${dotColor} mt-1 shrink-0"></div>
        <div class="flex-1 overflow-hidden">
            <div class="flex justify-between mb-0.5">
                <span class="font-semibold text-[var(--text-primary)] truncate" title="${a.attack_type}">${a.attack_type}</span>
                <span class="text-[var(--text-muted)] text-[10px] whitespace-nowrap pl-2" data-timestamp="${a.timestamp_iso}">${a.timestamp_relative}</span>
            </div>
            <div class="text-[var(--text-secondary)] flex items-center gap-2">
                <span class="font-mono-code truncate max-w-[80px]" title="${a.source_ip}">${a.source_ip}</span>
                <span class="material-symbols-outlined text-[10px] shrink-0">arrow_forward</span>
                <span class="truncate" title="${a.path}">${a.path}</span>
                <div class="shrink-0 ml-auto">${sourceChip}</div>
            </div>
        </div>
    </div>`;
}

// Ensure realtime.js can call this
window.prependAlertToFeed = function(data) {
    const container = document.getElementById('live-feed-container');
    if(!container) return;
    
    // Remove empty state if present
    if(container.children.length === 1 && container.children[0].textContent === "Feed is empty") {
        container.innerHTML = '';
    }
    
    // Generate data for UI payload using structure returned by /analyze
    const tsIso = data.timestamp_iso || new Date().toISOString() + "Z";
    const mappedAlert = {
        id: data.id || Math.random().toString(36).substr(2, 9),
        severity: (data.severity || 'LOW').toUpperCase(),
        timestamp_iso: tsIso,
        timestamp_relative: "just now",
        source_ip: data.source_ip || 'unknown',
        method: data.method || 'GET',
        path: data.path || '/',
        attack_type: data.attack_type || 'Unknown Anomaly',
        detection_source: data.detection_source || 'ML'
    };
    
    const html = generateFeedItemHTML(mappedAlert);
    container.insertAdjacentHTML('afterbegin', html);
    
    // Keep max 10
    if(container.children.length > 10) {
        container.lastElementChild.remove();
    }
}

async function fetchAndDrawMLMetrics() {
    try {
        const res = await fetch(`/dashboard/ml-metrics`);
        const data = await res.json();
        
        const kF1 = document.getElementById('kpi-f1');
        if(kF1) kF1.textContent = data.f1_score.toFixed(3);
        
        const kFpr = document.getElementById('kpi-fpr');
        if(kFpr) kFpr.textContent = (data.false_positive_rate * 100).toFixed(1) + '%';
        
        const dist = data.confidence_distribution || {};
        const labels = Object.keys(dist);
        const counts = labels.map(k => dist[k]);
        
        const ctx = document.getElementById('confidenceChart')?.getContext('2d');
        if(!ctx) return;
        
        // Gradient color logic mock - 5 buckets
        const bgColors = ['#10B981', '#EAB308', '#F59E0B', '#F97316', '#EF4444'];
        
        if(confidenceChartInstance) {
            confidenceChartInstance.data.datasets[0].data = counts;
            confidenceChartInstance.update();
            return;
        }
        
        confidenceChartInstance = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    data: counts,
                    backgroundColor: bgColors,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y', // horizontal bar
                plugins: { legend: { display: false }, tooltip: {
                    callbacks: {
                        label: function(context) { return context.raw + " alerts"; }
                    }
                }},
                scales: {
                    x: { grid: { display: false } },
                    y: { grid: { display: false } }
                }
            }
        });
        
    } catch(err) { console.error(err); }
}

// ── Heatmap ──────────────────────────────────────────────────────────────────
async function buildHeatmap() {
    const container = document.getElementById('heatmap-container');
    if (!container) return;

    try {
        const res  = await fetch('/dashboard/timeline?range=7d');
        const data = await res.json();
        const buckets = data.buckets || [];

        // Aggregate into [weekday 0-6][hour 0-23] grid
        const grid = Array.from({length: 7}, () => new Array(24).fill(0));
        buckets.forEach(b => {
            const d = new Date(b.timestamp);
            const day  = d.getDay();   // 0=Sun
            const hour = d.getHours();
            grid[day][hour] += (b.attacks || 0) + (b.anomalies || 0);
        });

        const maxVal = Math.max(1, ...grid.flat());
        const days   = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];

        let html = '<div style="overflow-x:auto;height:100%">';
        html += '<table style="border-collapse:collapse;width:100%;height:100%;font-size:10px">';
        // Hour header
        html += '<tr><th style="width:28px"></th>';
        for (let h = 0; h < 24; h++) {
            html += `<th style="color:var(--text-muted);font-weight:400;padding:0 1px;text-align:center">${h}</th>`;
        }
        html += '</tr>';

        grid.forEach((row, di) => {
            html += `<tr><td style="color:var(--text-secondary);padding-right:4px;white-space:nowrap">${days[di]}</td>`;
            row.forEach((val, hi) => {
                const intensity = val / maxVal;
                const alpha     = (0.05 + intensity * 0.95).toFixed(2);
                const bg        = val === 0
                    ? 'var(--bg-elevated)'
                    : `rgba(239,68,68,${alpha})`;
                const title     = `${days[di]} ${hi}:00 — ${val} events`;
                html += `<td title="${title}" style="background:${bg};border-radius:2px;padding:2px;cursor:default"></td>`;
            });
            html += '</tr>';
        });

        html += '</table></div>';
        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = '<div class="text-[var(--text-secondary)] text-xs flex items-center justify-center h-full">Heatmap unavailable</div>';
    }
}
