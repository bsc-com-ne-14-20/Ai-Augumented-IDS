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
    
    // Support parsing output from dashboard/report_builder.py
    const s = report.summary;
    
    const kpisHtml = `
        <div class="card p-3 flex flex-col justify-between">
            <span class="text-[var(--text-secondary)] text-[10px] font-mono-label uppercase tracking-wider">Total Rows</span>
            <div class="text-[var(--text-primary)] font-mono-code text-lg font-semibold">${s.total_rows}</div>
        </div>
        <div class="card p-3 flex flex-col justify-between border-[var(--warning)]/50 bg-[var(--warning)]/5">
            <span class="text-[var(--warning)] text-[10px] font-mono-label uppercase tracking-wider">Detected Attacks</span>
            <div class="text-[var(--warning)] font-mono-code text-lg font-semibold">${s.rule_detections + s.ml_detections}</div>
        </div>
        <div class="card p-3 flex flex-col justify-between">
            <span class="text-[var(--text-secondary)] text-[10px] font-mono-label uppercase tracking-wider">Rule Engine (SIG)</span>
            <div class="text-[var(--accent-primary)] font-mono-code text-lg font-semibold">${s.rule_detections}</div>
        </div>
        <div class="card p-3 flex flex-col justify-between">
            <span class="text-[var(--text-secondary)] text-[10px] font-mono-label uppercase tracking-wider">ML Anomaly</span>
            <div class="text-[var(--info)] font-mono-code text-lg font-semibold">${s.ml_detections}</div>
        </div>
        <div class="card p-3 flex flex-col justify-between">
            <span class="text-[var(--text-secondary)] text-[10px] font-mono-label uppercase tracking-wider">Rule Only</span>
            <div class="text-[var(--text-primary)] font-mono-code text-lg font-semibold">${s.rule_only || 0}</div>
        </div>
        <div class="card p-3 flex flex-col justify-between">
            <span class="text-[var(--text-secondary)] text-[10px] font-mono-label uppercase tracking-wider">ML Only</span>
            <div class="text-[var(--text-primary)] font-mono-code text-lg font-semibold">${s.ml_only || 0}</div>
        </div>
    `;
    document.getElementById('report-kpis').innerHTML = kpisHtml;
    
    // Agreement ring
    const agreeCircle = document.getElementById('report-agree-circle');
    const agreeVal = document.getElementById('report-agree-val');
    const rate = s.agreement_rate || 0;
    
    setTimeout(() => {
        const offset = 251 - (251 * (rate / 100));
        agreeCircle.style.strokeDashoffset = offset;
        agreeVal.textContent = rate.toFixed(1) + '%';
    }, 100);
    
    // Paths Table
    const pTbody = document.getElementById('report-paths-table');
    const pathsData = report.top_attacked_paths || [];
    if(pathsData.length) {
        pTbody.innerHTML = pathsData.map(p => `
            <tr>
                <td class="py-2 pr-2 truncate max-w-[200px]" title="${p.path}">${p.path}</td>
                <td class="py-2">${p.count}</td>
            </tr>
        `).join('');
    } else {
        pTbody.innerHTML = `<tr><td colspan="2" class="py-4 text-center text-[var(--text-secondary)]">No attacks found</td></tr>`;
    }
    
    // Rows
    const rTbody = document.getElementById('report-rows-body');
    const rowsList = report.rows || [];
    
    // Render top 500 max
    const maxRows = Math.min(500, rowsList.length);
    let rowsHtml = '';
    
    for(let i=0; i<maxRows; i++) {
        const row = rowsList[i];
        
        let verdictStyle = 'bg-[var(--success)]/10 text-[var(--success)]';
        let verdictTxt = 'CLEAN';
        if(row.verdict === 'ATTACK' || row.verdict === 'ANOMALY') {
            verdictStyle = 'bg-[var(--critical)]/10 text-[var(--critical)]';
            verdictTxt = row.verdict;
        }
        
        let srcTag = '';
        if(row.source === 'RULE') srcTag = '<span class="text-[9px] px-1 bg-[var(--accent-primary)]/20 text-[var(--accent-primary)] border border-[var(--accent-primary)]/30 rounded">RULE</span>';
        if(row.source === 'ML') srcTag = '<span class="text-[9px] px-1 bg-[var(--info)]/20 text-[var(--info)] border border-[var(--info)]/30 rounded">ML</span>';
        if(row.source === 'BOTH') srcTag = '<span class="text-[9px] px-1 bg-[var(--warning)]/20 text-[var(--warning)] border border-[var(--warning)]/30 rounded">BOTH</span>';
        
        const cf = row.confidence ? (row.confidence*100).toFixed(1)+'%' : '-';
        const matchDet = row.matched_rules ? row.matched_rules.slice(0,2).join(', ') + (row.matched_rules.length>2? '...':'') : '-';
        
        rowsHtml += `
        <tr class="hover:bg-[var(--bg-elevated)]">
            <td class="px-3 py-2 border-b border-[var(--border)] text-[var(--text-secondary)]">${i+1}</td>
            <td class="px-3 py-2 border-b border-[var(--border)] text-[var(--text-secondary)]">${row.timestamp && row.timestamp!=="Unknown" ? new Date(row.timestamp).toLocaleTimeString() : '-'}</td>
            <td class="px-3 py-2 border-b border-[var(--border)]">${row.method}</td>
            <td class="px-3 py-2 border-b border-[var(--border)] truncate max-w-[200px]" title="${row.path}">${row.path}</td>
            <td class="px-3 py-2 border-b border-[var(--border)]"><span class="px-1.5 py-0.5 rounded text-[10px] ${verdictStyle}">${verdictTxt}</span></td>
            <td class="px-3 py-2 border-b border-[var(--border)]">${srcTag}</td>
            <td class="px-3 py-2 border-b border-[var(--border)]">${cf}</td>
            <td class="px-3 py-2 border-b border-[var(--border)] truncate max-w-[150px]" title="${matchDet}">${row.verdict !== 'CLEAN' ? matchDet : '<span class="text-[var(--text-muted)]">N/A</span>'}</td>
        </tr>`;
    }
    
    if(rowsHtml === '') {
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
