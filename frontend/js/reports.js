/**
 * Reports — Report listing and download
 */

async function loadReports() {
    try {
        const scans = await api.get('/api/scans');
        const completed = scans.filter(s => s.status === 'completed');
        const container = document.getElementById('reports-container');
        const noReports = document.getElementById('no-reports');

        if (completed.length === 0) {
            noReports.style.display = 'block';
            // Remove any existing report cards
            container.querySelectorAll('.report-card').forEach(c => c.remove());
            return;
        }

        noReports.style.display = 'none';

        // Only add new report cards
        const existing = container.querySelectorAll('.report-card');
        const existingIds = new Set(Array.from(existing).map(c => c.dataset.scanId));

        completed.forEach(scan => {
            if (existingIds.has(String(scan.id))) return;

            const card = document.createElement('div');
            card.className = 'report-card';
            card.dataset.scanId = scan.id;
            card.innerHTML = `
                <div class="report-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                        <polyline points="14 2 14 8 20 8"/>
                        <line x1="16" y1="13" x2="8" y2="13"/>
                        <line x1="16" y1="17" x2="8" y2="17"/>
                    </svg>
                </div>
                <div class="report-info">
                    <div class="report-target">${escapeHtml(scan.target)}</div>
                    <div class="report-meta">
                        Scan #${scan.id} · ${scan.scan_type} · ${scan.completed_at ? scan.completed_at.replace('T', ' ').substring(0, 19) : 'N/A'}
                        ${scan.summary ? ' · ' + escapeHtml(scan.summary.substring(0, 80)) : ''}
                    </div>
                </div>
                <div class="report-actions">
                    <button class="btn btn-primary btn-sm" onclick="window.open('/api/reports/${scan.id}?format=html', '_blank')">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                        View HTML
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="downloadJsonReport(${scan.id})">
                        JSON
                    </button>
                </div>
            `;
            container.insertBefore(card, noReports);
        });

    } catch (e) {
        console.error('Failed to load reports:', e);
    }
}

async function downloadJsonReport(scanId) {
    try {
        const report = await api.get(`/api/reports/${scanId}?format=json`);
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `pentest-report-scan-${scanId}.json`;
        a.click();
        URL.revokeObjectURL(url);
        showToast('JSON report downloaded', 'success');
    } catch (e) {
        showToast('Failed to download report: ' + e.message, 'error');
    }
}
