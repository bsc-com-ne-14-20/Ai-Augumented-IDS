// ingestion.js

document.addEventListener("DOMContentLoaded", () => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('csv-file-input');
    
    if(!dropZone || !fileInput) return;

    // Load initial session history
    fetchSessionHistory();

    // Drop zone interactions
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('border-[var(--accent-primary)]', 'bg-[var(--bg-elevated)]');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('border-[var(--accent-primary)]', 'bg-[var(--bg-elevated)]');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('border-[var(--accent-primary)]', 'bg-[var(--bg-elevated)]');
        const file = e.dataTransfer.files[0];
        if (file && file.name.endsWith('.csv')) {
            handleFileSelected(file);
        } else {
            showUploadError('Please upload a valid .csv file');
        }
    });

    dropZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if(file) handleFileSelected(file);
        fileInput.value = ''; // reset
    });
});

function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

function showUploadError(msg) {
    const errObj = document.getElementById('upload-error');
    const errTxt = document.getElementById('upload-error-text');
    if(errObj && errTxt) {
        errObj.classList.remove('hidden');
        errTxt.textContent = msg;
    }
}

function hideUploadError() {
    const errObj = document.getElementById('upload-error');
    if(errObj) errObj.classList.add('hidden');
}

function showStepper() {
    document.getElementById('stepper-empty').classList.add('hidden');
    document.getElementById('stepper-list').classList.remove('hidden');
    document.getElementById('stepper-spinner').classList.remove('hidden');
    document.getElementById('report-container').classList.add('hidden');
    
    // reset steps
    for(let i=0; i<=5; i++) {
        updateStep(i, 'pending');
    }
}

function updateStep(index, state) {
    const stepEl = document.getElementById(`step-${index}`);
    if(!stepEl) return;
    
    const iconSpan = stepEl.querySelector('.step-icon');
    const textSpan = stepEl.querySelector('.step-text');
    
    iconSpan.classList.remove('ring-[var(--bg-surface)]', 'ring-[var(--accent-primary)]/20', 'bg-[var(--bg-elevated)]', 'bg-[var(--accent-primary)]', 'bg-[var(--success)]', 'text-[var(--text-secondary)]', 'text-white');
    textSpan.classList.remove('text-[var(--text-secondary)]', 'text-[var(--text-primary)]', 'text-[var(--accent-primary)]');
    
    if (state === 'active') {
        iconSpan.classList.add('ring-[var(--accent-primary)]/20', 'bg-[var(--accent-primary)]', 'text-white');
        textSpan.classList.add('text-[var(--accent-primary)]');
    } else if (state === 'complete') {
        iconSpan.classList.add('ring-[var(--bg-surface)]', 'bg-[var(--success)]', 'text-white');
        textSpan.classList.add('text-[var(--text-primary)]');
        iconSpan.innerHTML = `<span class="material-symbols-outlined text-[14px]">check</span>`;
    } else {
        // pending
        iconSpan.classList.add('ring-[var(--bg-surface)]', 'bg-[var(--bg-elevated)]', 'text-[var(--text-secondary)]');
        textSpan.classList.add('text-[var(--text-secondary)]');
        // Restore original icon depends on index - kept simple here
    }
}

function setStepDetail(index, text) {
    const el = document.getElementById(`step-${index}-detail`);
    if(el) el.textContent = text;
}

async function handleFileSelected(file) {
    hideUploadError();
    showStepper();
    
    updateStep(0, 'active');
    setStepDetail(0, `${file.name} — ${formatBytes(file.size)}`);
    
    const formData = new FormData();
    formData.append('file', file);

    // Simulate stepping while awaiting response
    let currentDummyStep = 1;
    const stepTimer = setInterval(() => {
        if(currentDummyStep > 1) {
            updateStep(currentDummyStep - 1, 'complete');
        }
        if(currentDummyStep <= 4) {
             updateStep(currentDummyStep, 'active');
        }
        currentDummyStep++;
    }, 800);

    try {
        updateStep(0, 'complete');
        updateStep(1, 'active');
        
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });

        clearInterval(stepTimer);

        if (!response.ok) {
            const errData = await response.json().catch(()=>({}));
            throw new Error(errData.error || `Server error: ${response.status}`);
        }

        const report = await response.json();

        // Mark all steps complete
        [1, 2, 3, 4, 5].forEach(i => updateStep(i, 'complete'));
        document.getElementById('stepper-spinner').classList.add('hidden');

        renderReport(report, file.name);
        fetchSessionHistory(); // Refresh history table

        // Auto-scroll to report
        setTimeout(() => {
            document.getElementById('report-container')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 150);

    } catch (err) {
        clearInterval(stepTimer);
        document.getElementById('stepper-spinner').classList.add('hidden');
        showUploadError(err.message);
        updateStep(currentDummyStep > 5 ? 5 : currentDummyStep, 'pending');
    }
}

function renderReport(report, filename) {
    const container = document.getElementById('report-container');
    container.classList.remove('hidden');
    
    document.getElementById('report-filename').textContent = `(${filename})`;
    
    // report_builder.py returns: { dataset, rule_engine, ml_engine, comparison, row_details }
    const ds  = report.dataset    || {};
    const re  = report.rule_engine || {};
    const ml  = report.ml_engine   || {};
    const cmp = report.comparison  || {};

    const totalRows      = ds.total_rows || 0;
    const ruleDetections = re.total_detections || 0;
    const mlDetections   = ml.total_detections || 0;
    const ruleOnly       = cmp.only_rule_flagged || 0;
    const mlOnly         = cmp.only_ml_flagged   || 0;
    const agreementRate  = (cmp.agreement_rate || 0) * 100; // 0-1 → 0-100

    const kpisHtml = `
        <div class="card p-3 flex flex-col justify-between">
            <span class="text-[var(--text-secondary)] text-[10px] font-mono-label uppercase tracking-wider">Total Rows</span>
            <div class="text-[var(--text-primary)] font-mono-code text-lg font-semibold">${totalRows}</div>
        </div>
        <div class="card p-3 flex flex-col justify-between border-[var(--warning)]/50 bg-[var(--warning)]/5">
            <span class="text-[var(--warning)] text-[10px] font-mono-label uppercase tracking-wider">Detected Attacks</span>
            <div class="text-[var(--warning)] font-mono-code text-lg font-semibold">${ruleDetections + mlDetections}</div>
        </div>
        <div class="card p-3 flex flex-col justify-between">
            <span class="text-[var(--text-secondary)] text-[10px] font-mono-label uppercase tracking-wider">Rule Engine (SIG)</span>
            <div class="text-[var(--accent-primary)] font-mono-code text-lg font-semibold">${ruleDetections}</div>
        </div>
        <div class="card p-3 flex flex-col justify-between">
            <span class="text-[var(--text-secondary)] text-[10px] font-mono-label uppercase tracking-wider">ML Anomaly</span>
            <div class="text-[var(--info)] font-mono-code text-lg font-semibold">${mlDetections}</div>
        </div>
        <div class="card p-3 flex flex-col justify-between">
            <span class="text-[var(--text-secondary)] text-[10px] font-mono-label uppercase tracking-wider">Rule Only</span>
            <div class="text-[var(--text-primary)] font-mono-code text-lg font-semibold">${ruleOnly}</div>
        </div>
        <div class="card p-3 flex flex-col justify-between">
            <span class="text-[var(--text-secondary)] text-[10px] font-mono-label uppercase tracking-wider">ML Only</span>
            <div class="text-[var(--text-primary)] font-mono-code text-lg font-semibold">${mlOnly}</div>
        </div>
    `;
    document.getElementById('report-kpis').innerHTML = kpisHtml;
    
    // Agreement ring (0-100 scale)
    const agreeCircle = document.getElementById('report-agree-circle');
    const agreeVal    = document.getElementById('report-agree-val');
    setTimeout(() => {
        const offset = 251 - (251 * (agreementRate / 100));
        agreeCircle.style.strokeDashoffset = offset;
        agreeVal.textContent = agreementRate.toFixed(1) + '%';
    }, 100);
    
    // Top attacked paths — prefer rule_engine paths, fall back to ml_engine
    const pTbody   = document.getElementById('report-paths-table');
    const pathsData = (re.top_attacked_paths && re.top_attacked_paths.length)
        ? re.top_attacked_paths
        : (ml.top_attacked_paths || []);

    if (pathsData.length) {
        pTbody.innerHTML = pathsData.slice(0, 5).map(p => `
            <tr>
                <td class="py-2 pr-2 truncate max-w-[200px]" title="${p.path}">${p.path}</td>
                <td class="py-2">${p.count}</td>
            </tr>
        `).join('');
    } else {
        pTbody.innerHTML = `<tr><td colspan="2" class="py-4 text-center text-[var(--text-secondary)]">No attacks found</td></tr>`;
    }
    
    // Row details — report_builder returns row_details[]
    const rTbody  = document.getElementById('report-rows-body');
    const rowsList = report.row_details || [];
    const maxRows  = Math.min(500, rowsList.length);
    let rowsHtml   = '';
    
    for (let i = 0; i < maxRows; i++) {
        const row = rowsList[i];

        // Determine combined verdict for display
        const rVerdict = row.rule_verdict || 'CLEAN';
        const mVerdict = row.ml_verdict   || 'CLEAN';
        const isAttack = rVerdict === 'ATTACK' || mVerdict === 'ANOMALY';

        let verdictStyle = 'bg-[var(--success)]/10 text-[var(--success)]';
        let verdictTxt   = 'CLEAN';
        if (isAttack) {
            verdictStyle = 'bg-[var(--critical)]/10 text-[var(--critical)]';
            verdictTxt   = rVerdict === 'ATTACK' ? 'ATTACK' : 'ANOMALY';
        }

        // Source chip
        const bothFlagged = rVerdict === 'ATTACK' && mVerdict === 'ANOMALY';
        let srcTag = '';
        if (bothFlagged) {
            srcTag = '<span class="text-[9px] px-1 bg-[var(--warning)]/20 text-[var(--warning)] border border-[var(--warning)]/30 rounded">BOTH</span>';
        } else if (rVerdict === 'ATTACK') {
            srcTag = '<span class="text-[9px] px-1 bg-[var(--accent-primary)]/20 text-[var(--accent-primary)] border border-[var(--accent-primary)]/30 rounded">RULE</span>';
        } else if (mVerdict === 'ANOMALY') {
            srcTag = '<span class="text-[9px] px-1 bg-[var(--info)]/20 text-[var(--info)] border border-[var(--info)]/30 rounded">ML</span>';
        }

        const cf       = row.ml_confidence ? (row.ml_confidence * 100).toFixed(1) + '%' : '-';
        const matchDet = row.rule_attack_type || (mVerdict === 'ANOMALY' ? 'ML Anomaly' : '-');

        rowsHtml += `
        <tr class="hover:bg-[var(--bg-elevated)]">
            <td class="px-3 py-2 border-b border-[var(--border)] text-[var(--text-secondary)]">${row.row_index || i + 1}</td>
            <td class="px-3 py-2 border-b border-[var(--border)] text-[var(--text-secondary)]">-</td>
            <td class="px-3 py-2 border-b border-[var(--border)]">${row.method || '-'}</td>
            <td class="px-3 py-2 border-b border-[var(--border)] truncate max-w-[200px]" title="${row.path}">${row.path || '-'}</td>
            <td class="px-3 py-2 border-b border-[var(--border)]"><span class="px-1.5 py-0.5 rounded text-[10px] ${verdictStyle}">${verdictTxt}</span></td>
            <td class="px-3 py-2 border-b border-[var(--border)]">${srcTag}</td>
            <td class="px-3 py-2 border-b border-[var(--border)]">${cf}</td>
            <td class="px-3 py-2 border-b border-[var(--border)] truncate max-w-[150px]" title="${matchDet}">${isAttack ? matchDet : '<span class="text-[var(--text-muted)]">N/A</span>'}</td>
        </tr>`;
    }
    
    if (!rowsHtml) {
        rowsHtml = `<tr><td colspan="8" class="text-center py-8 text-[var(--text-secondary)]">No records detailed</td></tr>`;
    }
    rTbody.innerHTML = rowsHtml;
}

async function fetchSessionHistory() {
    try {
        const res = await fetch('/dashboard/sessions');
        const data = await res.json();
        
        const tbody = document.getElementById('session-history-body');
        if(!tbody) return;
        
        if(!data.sessions || data.sessions.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="p-6 text-center text-[var(--text-secondary)]">No history loaded</td></tr>`;
            return;
        }
        
        tbody.innerHTML = [...data.sessions].reverse().map(sess => {
            return `
            <tr class="hover:bg-[var(--bg-elevated)] transition">
                <td class="px-4 py-3 font-mono-code text-[11px]">${sess.session_id}</td>
                <td class="px-4 py-3 text-sm">${sess.filename}</td>
                <td class="px-4 py-3 text-xs text-[var(--text-secondary)]">${new Date(sess.timestamp).toLocaleString()}</td>
                <td class="px-4 py-3 font-mono-code">${new Intl.NumberFormat().format(sess.total_rows)}</td>
                <td class="px-4 py-3 font-mono-code text-[var(--critical)]">${new Intl.NumberFormat().format(sess.attacks_found)}</td>
                <td class="px-4 py-3 text-right">
                    <span class="px-2 py-1 rounded bg-[var(--success)]/10 text-[var(--success)] text-[10px] font-bold tracking-wider uppercase border border-[var(--success)]/20">${sess.status}</span>
                </td>
            </tr>`;
        }).join('');
    } catch(e) { console.error('Failed to load session history'); }
}
