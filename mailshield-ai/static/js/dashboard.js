document.addEventListener('DOMContentLoaded', function () {
    const params = new URLSearchParams(window.location.search);
    const caseId = params.get('case_id');

    if (!caseId) {
        window.location.href = '/';
        return;
    }

    loadDashboard(caseId);
});

async function loadDashboard(caseId) {
    const loading = document.getElementById('loadingOverlay');
    loading.style.display = 'flex';

    try {
        const response = await fetch(`/api/case/${caseId}`);
        if (!response.ok) throw new Error('Case not found');
        const data = await response.json();

        loading.style.display = 'none';
        document.getElementById('dashboardContent').style.display = 'block';
        renderDashboard(data, caseId);
    } catch (err) {
        loading.innerHTML = `<div class="loading-content"><h3>Case not found</h3><a href="/" class="btn btn-primary" style="margin-top:1rem;">Go Home</a></div>`;
    }
}

function renderDashboard(data, caseId) {
    const report = data;

    // Case badge
    document.getElementById('caseBadge').textContent = `Case: ${caseId.substring(0, 8)}`;

    // Threat Score
    const score = report.threat_score.score;
    const level = report.threat_score.threat_level;
    renderThreatScore(score, level, report.threat_score.breakdown);

    // Overview Cards
    document.getElementById('aiClassification').textContent = report.phishing_detection.classification;
    document.getElementById('aiClassification').className = `card-value classification-badge ${report.phishing_detection.classification.toLowerCase()}`;
    document.getElementById('aiConfidence').textContent = `${report.phishing_detection.confidence}% confidence`;

    const aiCard = document.getElementById('aiCard');
    if (['PHISHING', 'MALICIOUS'].includes(report.phishing_detection.classification)) {
        aiCard.style.borderColor = 'var(--threat-critical)';
    }

    document.getElementById('totalUrls').textContent = report.url_analysis.total_urls;
    document.getElementById('suspiciousUrls').textContent = `${report.url_analysis.suspicious_urls} suspicious`;
    document.getElementById('totalIps').textContent = report.ip_analysis.total_ips;
    document.getElementById('publicIps').textContent = `${report.ip_analysis.public_ips} public`;

    // Auth Status
    const auth = report.authentication;
    const authHtml = `
        <div class="auth-badge-mini ${auth.spf.status.toLowerCase()}">SPF: ${auth.spf.status}</div>
        <div class="auth-badge-mini ${auth.dkim.status.toLowerCase()}">DKIM: ${auth.dkim.status}</div>
        <div class="auth-badge-mini ${auth.dmarc.status.toLowerCase()}">DMARC: ${auth.dmarc.status}</div>
    `;
    document.getElementById('authStatus').innerHTML = authHtml;

    // Timeline
    renderTimeline(report.timeline);

    // Map
    renderMap(report.ip_analysis.ips);

    // Email Details
    renderEmailDetails(report.email_metadata);

    // URL Table
    renderUrlTable(report.url_analysis.urls);

    // IP Table
    renderIpTable(report.ip_analysis.ips);

    // AI Analysis
    renderAIAnalysis(report.phishing_detection);

    // Report Button
    document.getElementById('generateReport').addEventListener('click', () => {
        window.open(`/reports?case_id=${caseId}`, '_blank');
    });

    // Charts
    renderCharts(data);
}

function renderThreatScore(score, level, breakdown) {
    const circumference = 2 * Math.PI * 90;
    const offset = circumference - (score / 100) * circumference;

    const scoreFill = document.getElementById('scoreFill');
    scoreFill.style.strokeDashoffset = offset;

    const colors = {
        'LOW': 'var(--threat-low)',
        'MEDIUM': 'var(--threat-medium)',
        'HIGH': 'var(--threat-high)',
        'CRITICAL': 'var(--threat-critical)',
    };

    scoreFill.style.stroke = colors[level] || 'var(--accent-cyan)';

    const scoreNumber = document.getElementById('scoreNumber');
    animateNumber(scoreNumber, 0, score, 1500);

    const scoreLevel = document.getElementById('scoreLevel');
    scoreLevel.textContent = level;
    scoreLevel.style.color = colors[level];
    scoreLevel.style.background = `rgba(${level === 'CRITICAL' ? '239,68,68' : level === 'HIGH' ? '249,115,22' : level === 'MEDIUM' ? '245,158,11' : '16,185,129'}, 0.15)`;

    // Breakdown
    const breakdownEl = document.getElementById('scoreBreakdown');
    if (breakdown && breakdown.length > 0) {
        breakdownEl.innerHTML = `
            <h4 style="margin-bottom:0.75rem;color:var(--text-secondary);">Score Breakdown</h4>
            <div class="breakdown-list">
                ${breakdown.map(b => `
                    <div class="breakdown-entry">
                        <span class="factor">${b.factor}</span>
                        <span class="pts">+${b.points}</span>
                    </div>
                `).join('')}
            </div>
        `;
    }
}

function animateNumber(el, start, end, duration) {
    const startTime = performance.now();
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(start + (end - start) * eased);
        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
}

function renderTimeline(timeline) {
    const container = document.getElementById('timeline');
    container.innerHTML = timeline.map(step => `
        <div class="timeline-step">
            <div class="timeline-dot"></div>
            <div class="timeline-label">${step.action}</div>
        </div>
    `).join('');
}

function renderMap(ips) {
    if (!ips || ips.length === 0) {
        document.getElementById('map').innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--text-muted);">No IP addresses to display</div>';
        return;
    }

    const map = L.map('map').setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
        maxZoom: 19,
    }).addTo(map);

    const riskColors = {
        'LOW': '#10b981',
        'MEDIUM': '#f59e0b',
        'HIGH': '#f97316',
        'CRITICAL': '#ef4444',
        'UNKNOWN': '#64748b',
    };

    const legend = document.getElementById('ipLegend');
    legend.innerHTML = '';

    const hasCoords = ips.filter(ip => ip.latitude && ip.longitude);

    ips.forEach(ip => {
        if (ip.latitude && ip.longitude) {
            const color = riskColors[ip.risk_level] || '#64748b';
            const marker = L.circleMarker([ip.latitude, ip.longitude], {
                radius: 8,
                fillColor: color,
                color: '#fff',
                weight: 2,
                opacity: 1,
                fillOpacity: 0.8,
            }).addTo(map);

            marker.bindPopup(`
                <div style="font-family:Inter,sans-serif;min-width:200px;">
                    <strong style="color:${color};">${ip.ip_address}</strong><br>
                    <strong>Country:</strong> ${ip.country}<br>
                    <strong>City:</strong> ${ip.city}<br>
                    <strong>ISP:</strong> ${ip.isp}<br>
                    <strong>ASN:</strong> ${ip.asn}<br>
                    <strong>Risk:</strong> <span style="color:${color};">${ip.risk_level}</span>
                </div>
            `);
        }
    });

    if (hasCoords.length > 0) {
        const bounds = L.latLngBounds(hasCoords.map(ip => [ip.latitude, ip.longitude]));
        map.fitBounds(bounds, { padding: [50, 50] });
    }

    // Legend
    const levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    levels.forEach(level => {
        const count = ips.filter(ip => ip.risk_level === level).length;
        if (count > 0) {
            legend.innerHTML += `
                <div class="legend-item">
                    <div class="legend-dot" style="background:${riskColors[level]};"></div>
                    ${level} (${count})
                </div>
            `;
        }
    });
}

function renderEmailDetails(meta) {
    const fields = [
        ['From', meta.from],
        ['To', meta.to],
        ['CC', meta.cc],
        ['Subject', meta.subject],
        ['Date', meta.date],
        ['Reply-To', meta.reply_to],
        ['Return-Path', meta.return_path],
        ['Message-ID', meta.message_id],
        ['X-Mailer', meta.x_mailer],
    ];

    document.getElementById('emailDetails').innerHTML = fields
        .filter(([, val]) => val && val !== 'N/A')
        .map(([label, value]) => `
            <div class="field">
                <span class="field-label">${label}:</span>
                <span class="field-value mono">${value}</span>
            </div>
        `).join('');
}

function renderUrlTable(urls) {
    const tbody = document.getElementById('urlTableBody');
    if (!urls || urls.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);">No URLs found</td></tr>';
        return;
    }

    tbody.innerHTML = urls.map(u => `
        <tr>
            <td class="mono" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(u.url)}</td>
            <td>${escapeHtml(u.domain)}</td>
            <td>${u.risk_score}</td>
            <td><span class="risk-badge ${u.risk_level.toLowerCase()}">${u.risk_level}</span></td>
            <td class="url-flags">${(u.flags || []).join(', ')}</td>
        </tr>
    `).join('');
}

function renderIpTable(ips) {
    const tbody = document.getElementById('ipTableBody');
    if (!ips || ips.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);">No IP addresses found</td></tr>';
        return;
    }

    tbody.innerHTML = ips.map(ip => `
        <tr>
            <td class="mono">${ip.ip_address}</td>
            <td>${ip.country}</td>
            <td>${ip.city}</td>
            <td>${ip.isp}</td>
            <td class="mono">${ip.asn}</td>
            <td><span class="risk-badge ${ip.risk_level.toLowerCase()}">${ip.risk_level}</span></td>
        </tr>
    `).join('');
}

function renderAIAnalysis(detection) {
    const container = document.getElementById('aiDetails');
    container.innerHTML = `
        <div style="display:flex;gap:2rem;flex-wrap:wrap;margin-bottom:1rem;">
            <div>
                <span style="color:var(--text-muted);">Classification:</span>
                <span class="classification-badge ${detection.classification.toLowerCase()}" style="margin-left:0.5rem;">${detection.classification}</span>
            </div>
            <div>
                <span style="color:var(--text-muted);">Confidence:</span>
                <strong style="margin-left:0.5rem;">${detection.confidence}%</strong>
            </div>
            <div>
                <span style="color:var(--text-muted);">Model:</span>
                <span style="margin-left:0.5rem;">${detection.model_used}</span>
            </div>
        </div>
        <h4 style="color:var(--text-secondary);margin-bottom:0.5rem;">Detected Indicators</h4>
        <ul class="indicator-list">
            ${detection.indicators.map(i => `<li>${escapeHtml(i)}</li>`).join('')}
        </ul>
    `;
}

function renderCharts(data) {
    // Risk Distribution Doughnut
    const urlRiskCounts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    (data.url_analysis.urls || []).forEach(u => {
        urlRiskCounts[u.risk_level] = (urlRiskCounts[u.risk_level] || 0) + 1;
    });

    const riskCtx = document.getElementById('riskChart');
    if (riskCtx) {
        new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: ['Low', 'Medium', 'High', 'Critical'],
                datasets: [{
                    data: [urlRiskCounts.LOW, urlRiskCounts.MEDIUM, urlRiskCounts.HIGH, urlRiskCounts.CRITICAL],
                    backgroundColor: ['#10b981', '#f59e0b', '#f97316', '#ef4444'],
                    borderColor: '#1a1f35',
                    borderWidth: 3,
                }],
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#94a3b8', padding: 15 } },
                },
            },
        });
    }

    // Threat Factors Bar Chart
    const breakdown = data.threat_score.breakdown || [];
    const factorsCtx = document.getElementById('factorsChart');
    if (factorsCtx && breakdown.length > 0) {
        new Chart(factorsCtx, {
            type: 'bar',
            data: {
                labels: breakdown.map(b => b.factor.substring(0, 20)),
                datasets: [{
                    label: 'Points',
                    data: breakdown.map(b => b.points),
                    backgroundColor: breakdown.map(b => {
                        if (b.points >= 15) return 'rgba(239, 68, 68, 0.7)';
                        if (b.points >= 10) return 'rgba(249, 115, 22, 0.7)';
                        return 'rgba(245, 158, 11, 0.7)';
                    }),
                    borderColor: breakdown.map(b => {
                        if (b.points >= 15) return '#ef4444';
                        if (b.points >= 10) return '#f97316';
                        return '#f59e0b';
                    }),
                    borderWidth: 1,
                }],
            },
            options: {
                responsive: true,
                indexAxis: 'y',
                scales: {
                    x: { grid: { color: '#2a3050' }, ticks: { color: '#94a3b8' } },
                    y: { grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 11 } } },
                },
                plugins: {
                    legend: { display: false },
                },
            },
        });
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
