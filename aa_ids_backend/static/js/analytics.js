// analytics.js

let trendChartInstance = null;
let featureChartInstance = null;
let liveConfChartInstance = null;

function applyAnalyticsTheme(isDark) {
    const textColor = isDark ? '#94A3B8' : '#475569';
    const gridColor = isDark ? '#1E2D45' : '#E2E8F0';
    
    if (typeof Chart !== 'undefined') {
        Chart.defaults.color = textColor;
        Chart.defaults.borderColor = gridColor;
        if(Chart.defaults.plugins && Chart.defaults.plugins.legend) {
            Chart.defaults.plugins.legend.labels.color = textColor;
        }
    }

    if(trendChartInstance) trendChartInstance.update();
    if(featureChartInstance) featureChartInstance.update();
    if(liveConfChartInstance) liveConfChartInstance.update();
}

document.addEventListener("DOMContentLoaded", async () => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    applyAnalyticsTheme(isDark);
    
    // Bind to the theme toggle observer or interval to update charts on toggle
    const themeObserver = new MutationObserver(() => {
        const dark = document.documentElement.getAttribute('data-theme') === 'dark';
        applyAnalyticsTheme(dark);
    });
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    await Promise.all([
        fetchAndDrawTrend(),
        fetchAndDrawMLMetrics(),
        drawFeatureImportance()
    ]);
});

async function fetchAndDrawTrend() {
    try {
        // Fetch timeline or mock trend
        // In the prototype we inject multiple series
        const ctx = document.getElementById('trendChart')?.getContext('2d');
        if(!ctx) return;
        
        const labels = Array.from({length: 14}, (_,i) => `Day ${i+1}`);
        const dataSQLi = Array.from({length: 14}, () => Math.floor(Math.random() * 50) + 10);
        const dataXSS = Array.from({length: 14}, () => Math.floor(Math.random() * 30) + 5);
        const dataPath = Array.from({length: 14}, () => Math.floor(Math.random() * 20));
        
        if (trendChartInstance) return;

        trendChartInstance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    { label: 'SQL Injection', data: dataSQLi, borderColor: '#EF4444', backgroundColor: '#EF4444', tension: 0.4 },
                    { label: 'XSS', data: dataXSS, borderColor: '#F97316', backgroundColor: '#F97316', tension: 0.4 },
                    { label: 'Path Traversal', data: dataPath, borderColor: '#EAB308', backgroundColor: '#EAB308', tension: 0.4 }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: { legend: { position: 'top' } },
                scales: {
                    x: { grid: { display: false } },
                    y: { beginAtZero: true }
                }
            }
        });
    } catch(err) { console.error(err); }
}

async function fetchAndDrawMLMetrics() {
    try {
        const res = await fetch(`/dashboard/ml-metrics`);
        const data = await res.json();
        
        // Confusion Matrix
        const cm = data.confusion_matrix;
        if(cm) {
            document.querySelector('[data-val="TN"]').textContent = new Intl.NumberFormat().format(cm.tn);
            document.querySelector('[data-val="FP"]').textContent = new Intl.NumberFormat().format(cm.fp);
            document.querySelector('[data-val="FN"]').textContent = new Intl.NumberFormat().format(cm.fn);
            document.querySelector('[data-val="TP"]').textContent = new Intl.NumberFormat().format(cm.tp);
        }

        // Metrics
        document.getElementById('metric-acc').textContent = (data.accuracy * 100).toFixed(1) + '%';
        document.getElementById('metric-pre').textContent = (data.precision * 100).toFixed(1) + '%';
        document.getElementById('metric-rec').textContent = (data.recall * 100).toFixed(1) + '%';
        document.getElementById('metric-f1').textContent = data.f1_score.toFixed(3);
        document.getElementById('metric-fpr').textContent = (data.false_positive_rate * 100).toFixed(1) + '%';
        document.getElementById('metric-fnr').textContent = (data.false_negative_rate * 100).toFixed(1) + '%';

        // Distribution chart
        const dist = data.confidence_distribution || {};
        const labels = Object.keys(dist);
        const counts = labels.map(k => dist[k]);

        // Fix mock data if it's all 0
        if(counts.every(r=>r===0)) {
            counts[0] = 5; counts[1] = 12; counts[2] = 8; counts[3]= 24; counts[4]= 45;
        }

        const ctx = document.getElementById('liveConfidenceChart')?.getContext('2d');
        if(!ctx) return;
        
        const bgColors = ['#10B981', '#EAB308', '#F59E0B', '#F97316', '#EF4444'];
        
        if (liveConfChartInstance) {
             liveConfChartInstance.data.datasets[0].data = counts;
             liveConfChartInstance.update();
             return;
        }

        liveConfChartInstance = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Count',
                    data: counts,
                    backgroundColor: bgColors,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false } }
                }
            }
        });
        
    } catch(err) { console.error(err); }
}

function drawFeatureImportance() {
    const dataObj = {
        "query_has_sqli": 0.187,
        "body_has_sqli": 0.156,
        "url_entropy": 0.134,
        "query_entropy": 0.098,
        "body_entropy": 0.087,
        "url_has_sqli": 0.071,
        "query_has_xss": 0.063,
        "body_length": 0.052,
        "url_length": 0.041,
        "post_no_content_type": 0.038
    };

    const labels = Object.keys(dataObj);
    const data = Object.values(dataObj);

    const ctx = document.getElementById('featureImportanceChart')?.getContext('2d');
    if(!ctx) return;
    
    // Gradient mock for single color
    
    if (featureChartInstance) return;

    featureChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Importance Score',
                data: data,
                backgroundColor: 'rgba(59, 130, 246, 0.8)',
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y', // horizontal
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { display: false }, beginAtZero: true },
                y: { grid: { display: false } }
            }
        }
    });
}
