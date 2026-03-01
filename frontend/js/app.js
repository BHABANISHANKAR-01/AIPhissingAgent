/**
 * AI PenTest Agent — Main Application Logic
 * SPA Router, API Client, SSE, Toast Notifications
 */

const API_BASE = '';

// ─── API Client ──────────────────────────────────────────────
const api = {
    async get(url) {
        const res = await fetch(`${API_BASE}${url}`);
        if (!res.ok) throw new Error(`API Error: ${res.statusText}`);
        return res.json();
    },

    async post(url, data) {
        const res = await fetch(`${API_BASE}${url}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || res.statusText);
        }
        return res.json();
    },

    async put(url, data) {
        const res = await fetch(`${API_BASE}${url}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        if (!res.ok) throw new Error(`API Error: ${res.statusText}`);
        return res.json();
    },

    async del(url) {
        const res = await fetch(`${API_BASE}${url}`, { method: 'DELETE' });
        if (!res.ok) throw new Error(`API Error: ${res.statusText}`);
        return res.json();
    }
};

// ─── Toast Notifications ─────────────────────────────────────
function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const icons = {
        success: '✓',
        error: '✕',
        info: 'ℹ',
        warning: '⚠'
    };

    toast.innerHTML = `<span style="font-size:16px">${icons[type] || 'ℹ'}</span> ${message}`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'toastOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// ─── SPA Router ──────────────────────────────────────────────
const pages = ['dashboard', 'scanner', 'active', 'findings', 'exploits', 'reports', 'settings'];
let currentPage = 'dashboard';

function navigate(page) {
    if (!pages.includes(page)) page = 'dashboard';
    currentPage = page;

    // Update pages
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    const pageEl = document.getElementById(`page-${page}`);
    if (pageEl) pageEl.classList.add('active');

    // Update nav
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const navEl = document.getElementById(`nav-${page}`);
    if (navEl) navEl.classList.add('active');

    // Load page data
    switch (page) {
        case 'dashboard': loadDashboard(); break;
        case 'active': loadActiveScans(); break;
        case 'findings': loadFindings(); break;
        case 'exploits': loadExploits(); break;
        case 'reports': loadReports(); break;
        case 'settings': loadSettings(); break;
    }
}

// Hash-based routing
window.addEventListener('hashchange', () => {
    const hash = window.location.hash.slice(1) || 'dashboard';
    navigate(hash);
});

// Nav click handlers
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        const page = item.dataset.page;
        window.location.hash = page;
    });
});

// ─── AI Status Check ─────────────────────────────────────────
async function checkAIStatus() {
    const statusEl = document.getElementById('ai-status');
    try {
        const settings = await api.get('/api/settings');
        const hasKey = settings.groq_api_key && settings.groq_api_key.length > 0;
        statusEl.innerHTML = hasKey
            ? '<div class="status-dot online"></div><span>AI: Connected</span>'
            : '<div class="status-dot offline"></div><span>AI: No API Key</span>';
    } catch {
        statusEl.innerHTML = '<div class="status-dot offline"></div><span>AI: Offline</span>';
    }
}

// ─── Settings ────────────────────────────────────────────────
async function loadSettings() {
    try {
        const settings = await api.get('/api/settings');
        document.getElementById('setting-api-key').value = settings.groq_api_key || '';
        document.getElementById('setting-scan-type').value = settings.default_scan_type || 'standard';
        document.getElementById('setting-threads').value = settings.max_threads || 50;
        document.getElementById('setting-timeout').value = settings.scan_timeout || 3;
    } catch (e) {
        console.log('Could not load settings:', e);
    }
}

document.getElementById('btn-save-settings').addEventListener('click', async () => {
    const data = {
        groq_api_key: document.getElementById('setting-api-key').value,
        default_scan_type: document.getElementById('setting-scan-type').value,
        max_threads: document.getElementById('setting-threads').value,
        scan_timeout: document.getElementById('setting-timeout').value,
    };

    try {
        await api.put('/api/settings', data);
        showToast('Settings saved successfully!', 'success');
        checkAIStatus();
    } catch (e) {
        showToast('Failed to save settings: ' + e.message, 'error');
    }
});

// ─── Findings Page ───────────────────────────────────────────
let allFindings = [];
let currentFilter = 'all';

async function loadFindings() {
    try {
        allFindings = await api.get('/api/findings');
        renderFindings();
    } catch (e) {
        console.error('Failed to load findings:', e);
    }
}

function renderFindings() {
    const container = document.getElementById('findings-list');
    const filtered = currentFilter === 'all'
        ? allFindings
        : allFindings.filter(f => f.severity === currentFilter);

    if (filtered.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                <p>${currentFilter === 'all' ? 'No findings yet. Run a scan to discover vulnerabilities.' : `No ${currentFilter} severity findings.`}</p>
            </div>`;
        return;
    }

    container.innerHTML = filtered.map((f, i) => `
        <div class="finding-card ${f.severity}" onclick="toggleFinding(${i})">
            <div class="finding-header">
                <span class="sev-badge ${f.severity}">${f.severity}</span>
                <span class="finding-title">${escapeHtml(f.title)}</span>
                ${f.cvss_score ? `<span style="color:var(--text-muted);font-size:12px;font-family:var(--font-mono)">CVSS ${f.cvss_score}</span>` : ''}
            </div>
            <div class="finding-detail">${escapeHtml(f.description || '')}</div>
            <div class="finding-meta">
                ${f.port ? `<span>Port: ${f.port}</span>` : ''}
                ${f.service ? `<span>Service: ${f.service}</span>` : ''}
                ${f.cve_id ? `<span>${f.cve_id}</span>` : ''}
                <span>Scan #${f.scan_id}</span>
            </div>
            <div class="finding-expanded" id="finding-detail-${i}">
                ${f.evidence ? `<div><strong style="color:var(--text-muted);font-size:12px">EVIDENCE</strong><div class="finding-evidence">${escapeHtml(f.evidence)}</div></div>` : ''}
                ${f.remediation ? `<div><strong style="color:var(--text-muted);font-size:12px">REMEDIATION</strong><div class="finding-remediation">${escapeHtml(f.remediation)}</div></div>` : ''}
            </div>
        </div>
    `).join('');
}

function toggleFinding(index) {
    const el = document.getElementById(`finding-detail-${index}`);
    if (el) el.classList.toggle('show');
}

// Filter chips
document.querySelectorAll('.chip').forEach(chip => {
    chip.addEventListener('click', () => {
        document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        currentFilter = chip.dataset.filter;
        renderFindings();
    });
});

// ─── Active Scans ────────────────────────────────────────────
let activeScanStreams = {};

async function loadActiveScans() {
    try {
        const scans = await api.get('/api/scans');
        renderScanHistory(scans);

        const running = scans.filter(s => s.status === 'running');
        const container = document.getElementById('active-scans-container');
        const noActive = document.getElementById('no-active-scans');

        if (running.length === 0) {
            noActive.style.display = 'block';
            // Clean up any stale scan cards
            container.querySelectorAll('.scan-active-card').forEach(c => c.remove());
        } else {
            noActive.style.display = 'none';
            running.forEach(scan => {
                if (!document.getElementById(`scan-card-${scan.id}`)) {
                    addActiveCard(scan);
                    startLogStream(scan.id);
                }
            });
        }

        // Update badge
        const badge = document.getElementById('active-badge');
        if (running.length > 0) {
            badge.style.display = 'inline';
            badge.textContent = running.length;
        } else {
            badge.style.display = 'none';
        }
    } catch (e) {
        console.error('Failed to load scans:', e);
    }
}

function addActiveCard(scan) {
    const container = document.getElementById('active-scans-container');
    const card = document.createElement('div');
    card.className = 'scan-active-card';
    card.id = `scan-card-${scan.id}`;
    card.innerHTML = `
        <div class="scan-active-header">
            <div>
                <div class="scan-active-target">${escapeHtml(scan.target)}</div>
                <div style="font-size:12px;color:var(--text-muted);margin-top:4px">
                    Scan #${scan.id} · ${scan.scan_type.charAt(0).toUpperCase() + scan.scan_type.slice(1)} · ${scan.ai_enabled ? '🤖 AI Enabled' : 'Manual'}
                </div>
            </div>
            <button class="btn btn-danger btn-sm" onclick="stopScan(${scan.id})">Stop</button>
        </div>
        <div class="scan-progress-bar"><div class="scan-progress-fill" style="width:5%" id="progress-${scan.id}"></div></div>
        <div class="terminal">
            <div class="terminal-header">
                <div class="terminal-dot red"></div>
                <div class="terminal-dot yellow"></div>
                <div class="terminal-dot green"></div>
                <span class="terminal-title">scan-${scan.id}.log</span>
            </div>
            <div class="terminal-body" id="terminal-${scan.id}"></div>
        </div>
    `;
    container.insertBefore(card, container.firstChild);
}

function startLogStream(scanId) {
    if (activeScanStreams[scanId]) return;

    const evtSource = new EventSource(`/api/scans/${scanId}/logs`);
    activeScanStreams[scanId] = evtSource;
    let logCount = 0;

    evtSource.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.type === 'complete') {
            evtSource.close();
            delete activeScanStreams[scanId];
            showToast(`Scan #${scanId} ${data.status}`, data.status === 'completed' ? 'success' : 'warning');

            // Update progress
            const progress = document.getElementById(`progress-${scanId}`);
            if (progress) progress.style.width = '100%';

            // Refresh after a moment
            setTimeout(() => {
                loadActiveScans();
                if (currentPage === 'dashboard') loadDashboard();
            }, 1000);
            return;
        }

        logCount++;
        const terminal = document.getElementById(`terminal-${scanId}`);
        if (terminal) {
            const entry = document.createElement('div');
            entry.className = `log-entry ${data.level}`;
            const time = data.timestamp ? data.timestamp.split('T')[1]?.substring(0, 8) || '' : '';
            entry.innerHTML = `
                <span class="log-time">${time}</span>
                <span class="log-module">[${data.module}]</span>
                <span class="log-msg">${escapeHtml(data.message)}</span>
            `;
            terminal.appendChild(entry);
            terminal.scrollTop = terminal.scrollHeight;
        }

        // Animate progress (rough estimate)
        const progress = document.getElementById(`progress-${scanId}`);
        if (progress) {
            const pct = Math.min(95, 5 + logCount * 2);
            progress.style.width = pct + '%';
        }
    };

    evtSource.onerror = () => {
        evtSource.close();
        delete activeScanStreams[scanId];
    };
}

async function stopScan(scanId) {
    try {
        await api.post(`/api/scans/${scanId}/stop`);
        showToast(`Stopping scan #${scanId}...`, 'warning');
    } catch (e) {
        showToast('Failed to stop scan: ' + e.message, 'error');
    }
}

function renderScanHistory(scans) {
    const tbody = document.getElementById('scan-history-body');
    if (!scans || scans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:30px">No scans yet</td></tr>';
        return;
    }

    tbody.innerHTML = scans.map(s => `
        <tr>
            <td style="font-family:var(--font-mono)">#${s.id}</td>
            <td style="font-weight:600;color:var(--text-primary)">${escapeHtml(s.target)}</td>
            <td>${s.scan_type}</td>
            <td><span class="status-badge ${s.status}">${s.status}</span></td>
            <td>${s.finding_count || '—'}</td>
            <td style="font-size:12px">${s.created_at ? s.created_at.replace('T', ' ').substring(0, 19) : '—'}</td>
            <td>
                <div style="display:flex;gap:6px">
                    ${s.status === 'completed' ? `<button class="btn btn-ghost btn-sm" onclick="viewScanReport(${s.id})">Report</button>` : ''}
                    ${s.status === 'running' ? `<button class="btn btn-danger btn-sm" onclick="stopScan(${s.id})">Stop</button>` : ''}
                    <button class="btn btn-ghost btn-sm" onclick="deleteScan(${s.id})" style="color:var(--accent-red)">Delete</button>
                </div>
            </td>
        </tr>
    `).join('');
}

async function deleteScan(scanId) {
    if (!confirm(`Delete scan #${scanId}?`)) return;
    try {
        await api.del(`/api/scans/${scanId}`);
        showToast(`Scan #${scanId} deleted`, 'info');
        loadActiveScans();
        if (currentPage === 'dashboard') loadDashboard();
    } catch (e) {
        showToast('Failed to delete: ' + e.message, 'error');
    }
}

function viewScanReport(scanId) {
    window.open(`/api/reports/${scanId}?format=html`, '_blank');
}

// Refresh button
document.getElementById('btn-refresh-scans').addEventListener('click', loadActiveScans);

// ─── Utility ─────────────────────────────────────────────────
function escapeHtml(text) {
    if (!text) return '';
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ─── Initialize ──────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const hash = window.location.hash.slice(1) || 'dashboard';
    navigate(hash);
    checkAIStatus();

    // Refresh dashboard every 15s
    setInterval(() => {
        if (currentPage === 'dashboard') loadDashboard();
        if (currentPage === 'active') loadActiveScans();
    }, 15000);
});
