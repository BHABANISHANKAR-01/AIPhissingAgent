/**
 * Dashboard — Stats, Charts, Recent Activity
 */

async function loadDashboard() {
    try {
        const stats = await api.get('/api/dashboard');

        // Animate counters
        animateCounter('stat-total-scans', stats.total_scans || 0);
        animateCounter('stat-active-scans', stats.active_scans || 0);
        animateCounter('stat-completed-scans', stats.completed_scans || 0);
        animateCounter('stat-total-findings', stats.total_findings || 0);

        // Severity chart
        drawSeverityChart(stats.severity_breakdown || {});

        // Recent scans
        renderRecentScans(stats.recent_scans || []);

        // Update active badge
        const badge = document.getElementById('active-badge');
        if (stats.active_scans > 0) {
            badge.style.display = 'inline';
            badge.textContent = stats.active_scans;
        } else {
            badge.style.display = 'none';
        }
    } catch (e) {
        console.error('Dashboard load error:', e);
    }
}

function animateCounter(elementId, targetValue) {
    const el = document.getElementById(elementId);
    if (!el) return;

    const current = parseInt(el.textContent) || 0;
    if (current === targetValue) return;

    const duration = 600;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Ease out
        const eased = 1 - Math.pow(1 - progress, 3);
        const value = Math.round(current + (targetValue - current) * eased);

        el.textContent = value;

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

function drawSeverityChart(breakdown) {
    const canvas = document.getElementById('severity-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const size = 300;

    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = size + 'px';
    canvas.style.height = size + 'px';
    ctx.scale(dpr, dpr);

    const colors = {
        critical: '#ff3366',
        high: '#ff6b35',
        medium: '#ffc107',
        low: '#00d4ff',
        info: '#64748b'
    };

    const labels = ['critical', 'high', 'medium', 'low', 'info'];
    const values = labels.map(l => breakdown[l] || 0);
    const total = values.reduce((a, b) => a + b, 0);

    const cx = size / 2;
    const cy = size / 2;
    const radius = size / 2 - 30;
    const innerRadius = radius * 0.6;

    ctx.clearRect(0, 0, size, size);

    if (total === 0) {
        // Empty state donut
        ctx.beginPath();
        ctx.arc(cx, cy, radius, 0, Math.PI * 2);
        ctx.arc(cx, cy, innerRadius, 0, Math.PI * 2, true);
        ctx.fillStyle = 'rgba(100,116,139,0.1)';
        ctx.fill();

        ctx.fillStyle = '#64748b';
        ctx.font = '14px Inter';
        ctx.textAlign = 'center';
        ctx.fillText('No data yet', cx, cy + 5);

        renderChartLegend(labels, values, colors, total);
        return;
    }

    let startAngle = -Math.PI / 2;

    labels.forEach((label, i) => {
        if (values[i] === 0) return;
        const sliceAngle = (values[i] / total) * Math.PI * 2;

        ctx.beginPath();
        ctx.arc(cx, cy, radius, startAngle, startAngle + sliceAngle);
        ctx.arc(cx, cy, innerRadius, startAngle + sliceAngle, startAngle, true);
        ctx.closePath();
        ctx.fillStyle = colors[label];
        ctx.fill();

        // Slight gap between slices
        ctx.strokeStyle = '#060a14';
        ctx.lineWidth = 2;
        ctx.stroke();

        startAngle += sliceAngle;
    });

    // Center text
    ctx.fillStyle = '#e2e8f0';
    ctx.font = 'bold 36px Inter';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(total, cx, cy - 8);

    ctx.fillStyle = '#64748b';
    ctx.font = '12px Inter';
    ctx.fillText('TOTAL', cx, cy + 16);

    renderChartLegend(labels, values, colors, total);
}

function renderChartLegend(labels, values, colors, total) {
    const legend = document.getElementById('chart-legend');
    if (!legend) return;

    legend.innerHTML = labels.map((label, i) => `
        <div class="chart-legend-item">
            <div class="chart-legend-dot" style="background:${colors[label]}"></div>
            <span>${label.charAt(0).toUpperCase() + label.slice(1)}: ${values[i]}</span>
        </div>
    `).join('');
}

function renderRecentScans(scans) {
    const container = document.getElementById('recent-scans-list');
    if (!container) return;

    if (scans.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                <p>No scans yet. Launch your first scan!</p>
            </div>`;
        return;
    }

    container.innerHTML = scans.map(s => `
        <div class="activity-item" onclick="window.location.hash='active'">
            <div class="activity-status ${s.status}"></div>
            <div class="activity-info">
                <div class="activity-target">${escapeHtml(s.target)}</div>
                <div class="activity-meta">${s.scan_type} · ${s.status} · ${s.created_at ? s.created_at.replace('T', ' ').substring(0, 16) : ''}</div>
            </div>
            ${s.status === 'running' ? '<div class="spinner"></div>' : ''}
        </div>
    `).join('');
}
