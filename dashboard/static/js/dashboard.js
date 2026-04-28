// Professional SOC Dashboard JavaScript

let socket = null;
let currentSeverityFilter = 'all';
let threatChart = null;
let pieChart = null;

// Initialize dashboard
$(document).ready(function() {
    initWebSocket();
    loadStatistics();
    loadAlerts();
    loadRecentPages();
    loadCharts();
    
    setInterval(refreshData, 30000);
    $('#severity-filter').change(function() {
        currentSeverityFilter = $(this).val();
        loadAlerts();
    });
});

// WebSocket connection
function initWebSocket() {
    socket = io();
    
    socket.on('connect', function() {
        $('#connection-status').text('CONNECTED').css('color', '#22c55e');
        socket.emit('subscribe_alerts');
    });
    
    socket.on('disconnect', function() {
        $('#connection-status').text('DISCONNECTED').css('color', '#ef4444');
    });
    
    socket.on('new_alert', function(alert) {
        refreshData();
        showToast('New alert received: ' + alert.title);
    });
}

// Load statistics
function loadStatistics() {
    $.get('/api/statistics', function(data) {
        $('#total-pages').text(data.total_pages || 0);
        $('#total-alerts').text(data.total_alerts || 0);
        $('#unacknowledged-alerts').text(data.unacknowledged_alerts || 0);
        $('#critical-alerts').text(data.critical_alerts || 0);
        $('#pages-24h').text(data.pages_last_24h || 0);
        $('#avg-threat').text(data.avg_threat_score || 0);
        
        // Show local time
        const now = new Date();
        $('#last-update').text(now.toLocaleTimeString());
    });
}

// Load charts
function loadCharts() {
    loadThreatTrendChart();
    loadAlertDistributionChart();
}

function loadThreatTrendChart() {
    $.get('/api/charts/threat-trend', function(data) {
        const ctx = document.getElementById('threat-trend-chart').getContext('2d');
        
        if (threatChart) threatChart.destroy();
        
        if (!data.labels || data.labels.length === 0) {
            // Show empty chart with message
            threatChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: ['No Data'],
                    datasets: [{
                        label: 'Threat Score',
                        data: [0],
                        borderColor: '#64748b',
                        backgroundColor: 'rgba(100, 116, 139, 0.1)',
                        borderWidth: 1,
                        pointRadius: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        tooltip: { enabled: false },
                        legend: { display: false }
                    },
                    scales: {
                        y: { min: 0, max: 100, title: { display: true, text: 'Threat Score' } },
                        x: { title: { display: true, text: 'Time' } }
                    }
                }
            });
            
            // Add annotation for no data
            console.log('No threat timeline data available');
            return;
        }
        
        threatChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.labels,
                datasets: [{
                    label: 'Threat Score',
                    data: data.scores,
                    borderColor: '#06b6d4',
                    backgroundColor: 'rgba(6, 182, 212, 0.05)',
                    borderWidth: 2,
                    pointRadius: 3,
                    pointBackgroundColor: '#06b6d4',
                    pointBorderColor: '#0f172a',
                    pointBorderWidth: 1,
                    fill: true,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'top', labels: { boxWidth: 12, font: { size: 11 } } },
                    tooltip: { 
                        callbacks: { 
                            label: (ctx) => `Threat Score: ${ctx.raw}`,
                            title: (ctx) => `Time: ${ctx[0].label}`
                        } 
                    }
                },
                scales: {
                    y: { 
                        beginAtZero: true, 
                        max: 100, 
                        title: { display: true, text: 'Threat Score (0-100)', font: { size: 11 } },
                        grid: { color: '#94a3b8' }
                    },
                    x: { 
                        title: { display: true, text: 'Date/Time', font: { size: 11 } },
                        ticks: { maxRotation: 45, minRotation: 45, font: { size: 9 } },
                        grid: { display: false }
                    }
                }
            }
        });
    }).fail(function() {
        console.log('Failed to load threat trend chart');
    });
}

function loadAlertDistributionChart() {
    $.get('/api/charts/alert-distribution', function(data) {
        if (pieChart) pieChart.destroy();
        
        const ctx = document.getElementById('alert-pie-chart').getContext('2d');
        pieChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: data.labels,
                datasets: [{
                    data: data.values,
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e'],
                    borderWidth: 0,
                    hoverOffset: 10
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { 
                        position: 'bottom', 
                        labels: { 
                            boxWidth: 12, 
                            font: { size: 11, weight: '500' },
                            color: '#94a3b8',
                            padding: 12
                        } 
                    },
                    tooltip: { 
                        callbacks: { 
                            label: (ctx) => `${ctx.label}: ${ctx.raw} alerts`,
                            title: (ctx) => ''
                        },
                        backgroundColor: '#1e293b',
                        bodyColor: '#94a3b8'
                    }
                },
                cutout: '65%'
            }
        });
    }).fail(function() {
        console.log('Failed to load alert distribution');
    });
}

// Load alerts
function loadAlerts() {
    let url = '/api/alerts?limit=50';
    if (currentSeverityFilter !== 'all') {
        url += '&severity=' + currentSeverityFilter;
    }
    
    $.get(url, function(alerts) {
        let html = '';
        if (alerts.length === 0) {
            html = '<tr><td colspan="6" class="loading"><i class="fas fa-inbox"></i> No alerts found</td></tr>';
        } else {
            alerts.forEach(function(alert) {
                const severityClass = 'severity-' + alert.alert_level.toLowerCase();
                const statusText = alert.acknowledged ? 'Acknowledged' : 'Pending';
                const timeAgo = formatTimeAgo(alert.generated_at);
                
                // Determine threat class for risk score coloring
                let riskClass = 'threat-low';
                if (alert.risk_score >= 85) riskClass = 'threat-critical';
                else if (alert.risk_score >= 70) riskClass = 'threat-high';
                else if (alert.risk_score >= 50) riskClass = 'threat-medium';
                
                html += `<tr>
                    <td><span class="${severityClass}">${alert.alert_level}</span></td>
                    <td style="max-width: 350px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(alert.title)}</td>
                    <td class="${riskClass}"><strong>${alert.risk_score}</strong></td>
                    <td>${timeAgo}</td>
                    <td>${statusText}</td>
                    <td>
                        <div class="action-buttons">
                            ${!alert.acknowledged ? `<button class="btn-action btn-acknowledge" onclick="acknowledgeAlert(${alert.id})"><i class="fas fa-check"></i> Ack</button>` : ''}
                            <button class="btn-action btn-tp" onclick="submitFeedback(${alert.id}, 'true_positive')"><i class="fas fa-thumbs-up"></i> TP</button>
                            <button class="btn-action btn-fp" onclick="submitFeedback(${alert.id}, 'false_positive')"><i class="fas fa-thumbs-down"></i> FP</button>
                            <button class="btn-action btn-fn" onclick="submitFeedback(${alert.id}, 'false_negative')"><i class="fas fa-eye-slash"></i> FN</button>
                        </div>
                    </td>
                </tr>`;
            });
        }
        $('#alerts-tbody').html(html);
    });
}

// Load recent pages
function loadRecentPages() {
    $.get('/api/recent-pages?limit=20', function(pages) {
        let html = '';
        if (pages.length === 0) {
            html = '<tr><td colspan="4" class="loading"><i class="fas fa-inbox"></i> No pages crawled yet</td></tr>';
        } else {
            pages.forEach(function(page) {
                let threatClass = 'threat-low';
                if (page.threat_score >= 85) threatClass = 'threat-critical';
                else if (page.threat_score >= 70) threatClass = 'threat-high';
                else if (page.threat_score >= 50) threatClass = 'threat-medium';
                
                // Format the crawled_at time
                const crawledDate = new Date(page.crawled_at);
                const timeString = crawledDate.toLocaleString(); // Local time
                
                html += `<tr>
                    <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                        <a href="${escapeHtml(page.url)}" target="_blank" class="url-link">${escapeHtml(page.url.substring(0, 60))}...</a>
                    </td>
                    <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(page.title)}</td>
                    <td>${timeString}</td>
                    <td class="${threatClass}">${page.threat_score}</td>
                </tr>`;
            });
        }
        $('#pages-tbody').html(html);
    });
}

// Format time ago
// Format time ago with correct timezone handling
// Format time ago with correct calculation
function formatTimeAgo(dateString) {
    if (!dateString) return 'Unknown';
    
    // Parse as UTC and convert to local
    let utcDate = new Date(dateString);
    
    // If the date doesn't have timezone info, assume UTC
    if (!dateString.includes('Z') && !dateString.includes('+')) {
        // Add 'Z' to indicate UTC
        utcDate = new Date(dateString + 'Z');
    }
    
    if (isNaN(utcDate.getTime())) {
        return 'Invalid date';
    }
    
    const now = new Date();
    const diffSeconds = Math.floor((now - utcDate) / 1000);
    
    if (diffSeconds < 0) {
        return utcDate.toLocaleString();
    }
    
    if (diffSeconds < 60) return 'Just now';
    
    const minutes = Math.floor(diffSeconds / 60);
    if (minutes < 60) return `${minutes} minute${minutes !== 1 ? 's' : ''} ago`;
    
    const hours = Math.floor(diffSeconds / 3600);
    if (hours < 24) return `${hours} hour${hours !== 1 ? 's' : ''} ago`;
    
    const days = Math.floor(diffSeconds / 86400);
    if (days < 7) return `${days} day${days !== 1 ? 's' : ''} ago`;
    
    return utcDate.toLocaleString();
}

// Acknowledge alert
function acknowledgeAlert(alertId) {
    $.ajax({
        url: '/api/alerts/' + alertId,
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify({action: 'acknowledge', acknowledged_by: 'soc_analyst'}),
        success: function(response) {
            if (response.success) {
                loadAlerts();
                loadStatistics();
                showToast('Alert acknowledged');
            }
        }
    });
}


// Submit feedback - No extra API call (uses data from table row)
function submitFeedback(alertId, feedbackType) {
    // Find the row containing this alert
    const row = $(`button[onclick*="submitFeedback(${alertId},"]`).closest('tr');
    
    if (!row || row.length === 0) {
        showToast('Could not find alert row', 'error');
        return;
    }
    
    // Extract data from the row
    const title = row.find('td:eq(1)').text().trim();
    const riskScoreText = row.find('td:eq(2)').text().trim();
    const riskScore = parseInt(riskScoreText) || 50;
    const severityText = row.find('td:eq(0)').text().trim();
    
    // Determine category based on severity/title
    let category = 'general';
    if (title.toLowerCase().includes('credential') || title.toLowerCase().includes('password')) {
        category = 'credential';
    } else if (title.toLowerCase().includes('ransomware')) {
        category = 'ransomware';
    } else if (title.toLowerCase().includes('marketplace')) {
        category = 'marketplace';
    } else if (title.toLowerCase().includes('breach')) {
        category = 'breach';
    }
    
    // Confirm with user
    const confirmMsg = `Alert: ${title}\nRisk Score: ${riskScore}\nSeverity: ${severityText}\n\nMark as ${feedbackType.replace('_', ' ').toUpperCase()}?`;
    
    if (!confirm(confirmMsg)) {
        return; // User cancelled
    }
    
    const feedbackData = {
        alert_id: alertId,
        feedback_type: feedbackType,
        keyword: title.split(' ').slice(0, 4).join(' '),
        category: category,
        original_confidence: riskScore / 100,
        source_url: window.location.href,
        feedback_from: 'soc_analyst',
        feedback_comment: ''
    };
    
    console.log('Submitting feedback:', feedbackData);
    
    $.ajax({
        url: '/api/feedback',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(feedbackData),
        success: function(response) {
            if (response.success) {
                const typeText = feedbackType.replace('_', ' ').toUpperCase();
                showToast(`✅ Feedback recorded: ${typeText}`, 'success');
                refreshData();
            } else {
                showToast('❌ Feedback failed: ' + (response.error || response.message || 'Unknown error'), 'error');
            }
        },
        error: function(xhr) {
            console.error('Feedback error:', xhr);
            let errorMsg = 'Failed to submit feedback';
            if (xhr.status === 404) {
                errorMsg = 'Feedback API not found. Make sure /api/feedback exists.';
            } else if (xhr.status === 415) {
                errorMsg = 'Content-Type not supported. Check server.';
            } else if (xhr.status === 500) {
                errorMsg = 'Server error. Check console.';
            }
            showToast('❌ ' + errorMsg, 'error');
        }
    });
}

// Refresh all data
function refreshData() {
    loadStatistics();
    loadAlerts();
    loadRecentPages();
    loadCharts();
}

// Show toast notification
function showToast(message, type = 'success') {
    $('.toast-notification').remove();
    const borderColor = type === 'error' ? '#ef4444' : '#22c55e';
    const toast = $(`<div class="toast-notification" style="border-left-color: ${borderColor};">${message}</div>`);
    $('body').append(toast);
    setTimeout(() => toast.fadeOut(300, () => toast.remove()), 3000);
}

// Escape HTML
function escapeHtml(text) {
    if (!text) return '';
    return text.replace(/[&<>]/g, function(m) {
        if (m === '&') return '&amp;';
        if (m === '<') return '&lt;';
        if (m === '>') return '&gt;';
        return m;
    });
}