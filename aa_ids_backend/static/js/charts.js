window.charts = {};

function renderReport(report) {
    const ds = report.dataset;
    const rule = report.rule_engine;
    const ml = report.ml_engine;
    const comp = report.comparison;

    // Destroy existing charts
    for (let c in window.charts) {
        if (window.charts[c]) {
            window.charts[c].destroy();
        }
    }

    // Populate DOM Basics
    document.getElementById('stat-csv-filename').textContent = ds.csv_filename;
    document.getElementById('stat-total-rows').textContent = ds.total_rows;
    document.getElementById('stat-processing-time').textContent = ds.processing_time_ms + ' ms';
    
    document.getElementById('card-stat-total-rows').textContent = ds.total_rows;
    document.getElementById('stat-rule-detections').textContent = rule.total_detections;
    document.getElementById('stat-ml-detections').textContent = ml.total_detections;
    document.getElementById('stat-agreement-rate').textContent = (comp.agreement_rate * 100).toFixed(1) + '%';
    document.getElementById('stat-rule-detection-rate').textContent = (rule.detection_rate * 100).toFixed(1) + '%';
    document.getElementById('stat-ml-detection-rate').textContent = (ml.detection_rate * 100).toFixed(1) + '%';

    document.getElementById('stat-both-flagged').textContent = comp.both_flagged;
    document.getElementById('stat-only-rule').textContent = comp.only_rule_flagged;
    document.getElementById('stat-only-ml').textContent = comp.only_ml_flagged;
    document.getElementById('stat-both-clean').textContent = comp.both_clean;

    if (ml.confidence_stats) {
        document.getElementById('stat-ml-conf-mean').textContent = ml.confidence_stats.mean.toFixed(3);
        document.getElementById('stat-ml-conf-min').textContent = ml.confidence_stats.min.toFixed(3);
        document.getElementById('stat-ml-conf-max').textContent = ml.confidence_stats.max.toFixed(3);
    }

    // Gauges
    const ruleGauge = document.getElementById('rule-detection-gauge');
    ruleGauge.style.background = `conic-gradient(var(--color-red) ${(rule.detection_rate * 180)}deg, #e2e8f0 0deg)`;
    const mlGauge = document.getElementById('ml-detection-gauge');
    mlGauge.style.background = `conic-gradient(var(--color-orange) ${(ml.detection_rate * 180)}deg, #e2e8f0 0deg)`;

    // Colors
    const colorMap = {
        'critical': '#EF4444',
        'high': '#F97316',
        'medium': '#EAB308',
        'low': '#3B82F6',
        'clean': '#10B981',
        'error': '#6B7280'
    };

    function renderChart(elementId, type, dataObj, keyLabel, valueLabel, isColors=false) {
        const ctx = document.getElementById(elementId).getContext('2d');
        const keys = Object.keys(dataObj);
        const values = Object.values(dataObj);
        const bgColors = isColors ? keys.map(k => colorMap[k] || '#EAB308') : '#6366f1';
        
        window.charts[elementId] = new Chart(ctx, {
            type: type,
            data: {
                labels: keys,
                datasets: [{
                    label: valueLabel,
                    data: values,
                    backgroundColor: bgColors
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    }

    renderChart('rule-attack-type-chart', 'doughnut', rule.attack_type_breakdown, 'Attack Type', 'Count');
    renderChart('rule-severity-chart', 'bar', rule.severity_breakdown, 'Severity', 'Count', true);
    
    // Check ml.severity_breakdown might be empty
    if (Object.keys(ml.severity_breakdown).length > 0) {
        renderChart('ml-severity-chart', 'bar', ml.severity_breakdown, 'Severity', 'Count', true);
    }

    // ML Histogram
    const histCtx = document.getElementById('ml-confidence-chart').getContext('2d');
    const histLabels = ml.confidence_histogram.map(b => b.bucket);
    const histData = ml.confidence_histogram.map(b => b.count);
    window.charts['ml-confidence-chart'] = new Chart(histCtx, {
        type: 'bar',
        data: {
            labels: histLabels,
            datasets: [{ label: 'Count', data: histData, backgroundColor: '#6366f1' }]
        },
        options: { responsive: true, maintainAspectRatio: false }
    });

    // Agreement Doughnut
    const agCtx = document.getElementById('agreement-doughnut').getContext('2d');
    window.charts['agreement-doughnut'] = new Chart(agCtx, {
        type: 'doughnut',
        data: {
            labels: ['Both Flagged', 'Only Rule', 'Only ML', 'Both Clean'],
            datasets: [{
                data: [comp.both_flagged, comp.only_rule_flagged, comp.only_ml_flagged, comp.both_clean],
                backgroundColor: ['#EF4444', '#F97316', '#EAB308', '#10B981']
            }]
        },
        options: { responsive: true, maintainAspectRatio: false }
    });

    // Lists
    function renderList(elementId, items, isDict=false) {
        const el = document.getElementById(elementId);
        el.innerHTML = '';
        if (isDict) {
            for (let [k, v] of Object.entries(items)) {
                el.innerHTML += `<li>${k} <span class="tag">${v}</span></li>`;
            }
        } else {
            for (let item of items) {
                el.innerHTML += `<li>${item.path} <span class="tag">${item.count}</span></li>`;
            }
        }
    }

    renderList('rule-top-rules-list', rule.rules_triggered, true);
    renderList('rule-top-paths-list', rule.top_attacked_paths, false);
    renderList('ml-top-paths-list', ml.top_attacked_paths, false);

    // Table
    const tbody = document.getElementById('comparison-table-body');
    tbody.innerHTML = '';
    report.row_details.forEach(r => {
        const tr = document.createElement('tr');
        
        let rowClass = 'row-clean';
        if (r.rule_verdict === 'ERROR' || r.ml_verdict === 'ERROR') {
            rowClass = 'row-error';
        } else if (r.rule_verdict === 'ATTACK' || r.ml_verdict === 'ANOMALY') {
            rowClass = 'row-flagged';
        } else if (!r.agreement) {
            rowClass = 'row-disagreement';
        }

        if (!r.agreement && rowClass !== 'row-flagged') {
            rowClass = 'row-disagreement';
        }

        tr.className = rowClass;
        tr.dataset.agreement = r.agreement;
        tr.dataset.flagged = (r.rule_verdict === 'ATTACK' || r.ml_verdict === 'ANOMALY');

        tr.innerHTML = `
            <td>${r.row_index}</td>
            <td>${r.method}</td>
            <td style="word-break: break-all;">${r.path}</td>
            <td>${r.rule_verdict}</td>
            <td>${r.rule_attack_type || '-'}</td>
            <td>${r.ml_verdict}</td>
            <td>${r.ml_confidence !== null ? parseFloat(r.ml_confidence).toFixed(3) : '-'}</td>
            <td>${r.agreement ? 'Yes' : 'No'}</td>
        `;
        tbody.appendChild(tr);
    });

    const notice = document.getElementById('table-notice');
    if (report.row_details.length < ds.total_rows) {
        notice.style.display = 'block';
        notice.textContent = `Showing first ${report.row_details.length} rows of ${ds.total_rows} total.`;
    } else {
        notice.style.display = 'none';
    }

    // Filters
    const filterBtns = document.querySelectorAll('.filter-btn');
    function applyFilter(filter) {
        document.querySelectorAll('#comparison-table-body tr').forEach(tr => {
            if (filter === 'all') {
                tr.classList.remove('hidden');
            } else if (filter === 'disagreements') {
                tr.classList.toggle('hidden', tr.dataset.agreement === 'true');
            } else if (filter === 'attacks') {
                tr.classList.toggle('hidden', tr.dataset.flagged === 'false');
            }
        });
    }

    filterBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            filterBtns.forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            applyFilter(e.target.dataset.filter);
        });
    });
}
