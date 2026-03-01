/**
 * Scanner — Scan Configuration & Launch
 */

document.getElementById('btn-launch-scan').addEventListener('click', async () => {
    const target = document.getElementById('scan-target').value.trim();
    if (!target) {
        showToast('Please enter a target host or URL', 'warning');
        document.getElementById('scan-target').focus();
        return;
    }

    const profile = document.querySelector('input[name="scan-profile"]:checked');
    const scanType = profile ? profile.value : 'standard';
    const aiEnabled = document.getElementById('ai-toggle').checked;

    const btn = document.getElementById('btn-launch-scan');
    btn.disabled = true;
    btn.innerHTML = '<div class="spinner"></div> Launching...';

    try {
        const result = await api.post('/api/scans', {
            target: target,
            scan_type: scanType,
            ai_enabled: aiEnabled
        });

        showToast(`Scan #${result.id} started on ${target}`, 'success');

        // Clear input
        document.getElementById('scan-target').value = '';

        // Navigate to active scans
        setTimeout(() => {
            window.location.hash = 'active';
        }, 500);

    } catch (e) {
        showToast('Failed to launch scan: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            Launch Scan
        `;
    }
});

// Allow Enter key to launch scan
document.getElementById('scan-target').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        document.getElementById('btn-launch-scan').click();
    }
});
