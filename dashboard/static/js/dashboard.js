
// Dashboard JavaScript

let socket = null;
let currentSeverityFilter = 'all';

// Initialize dashboard
$(document).ready(function() {
    initWebSocket();
    loadStatistics();
    loadCharts();
    loadAlerts();
    loadRecentPages();
    
    // Set up auto-refresh
    setInterval(refreshData, 30000);
    
    // Set up filter change
    $('#severity-filter').change(function() {
        currentSeverityFilter = $(this).val();
        loadAlerts();
    });
});

// WebSocket connection
function initWebSocket() {
    socket = io();
    
    socket.on('connect', function() {
        console.log('WebSocket connected');
        $('#connection-status').text('Connected').removeClass('text-danger').addClass('text-success');
        socket.emit('subscribe_alerts');
    });
    
    socket.on('disconnect', function() {
        console.log('WebSocket disconnected');
        $('#connection-status').text('Disconnected').removeClass('text-success').addClass('text-danger');
    });
    
    socket.on('new_alert', function(alert) {
        console.log('New alert received:', alert);
        showNotification(alert);
        refreshData();
    });
    
    socket.on('alert_updated', function(data) {
        console.log('Alert updated:', data);
        loadAlerts(); // Refresh alerts table
    });
}

// Load statistics
function loadStatistics() {
    $.get('/api/statistics', function(data) {
        $('#total-pages').text(data.total_pages || 0);
        $('#total-alerts').text(data.total_alerts || 0);
        $('#unacknowledged-alerts').text(data.unacknowledged_alerts || 0);
        $('#avg-threat').text(data.avg_threat_score || 0);
    });
}

// Load charts
function loadCharts() {
    // Threat trend chart
    $.get('/api/charts/threat-trend', function(data) {
        Plotly.newPlot('threat-trend-chart', data.data, data.layout);
    });
    
    // Alert distribution chart
    $.get('/api/charts/alert-distribution', function(data) {
        Plotly.newPlot('alert-distribution-chart', data.data, data.layout);
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
            html = '<tr><td colspan="6" class="text-center">No alerts found</td></tr>';
        } else {
            alerts.forEach(function(alert) {
                let severityClass = 'badge-' + alert.alert_level.toLowerCase();
                let statusText = alert.acknowledged ? 'Acknowledged' : 'Pending';
                let statusClass = alert.acknowledged ? 'text-success' : 'text-warning';
                
                html += `<tr class="${!alert.acknowledged ? 'alert-animation' : ''}">
                    <td><span class="badge ${severityClass}">${alert.alert_level}</span></td>
                    <td>${escapeHtml(alert.title)}</td>
                    <td>${alert.risk_score}</td>
                    <td>${formatDate(alert.generated_at)}</td>
                    <td class="${statusClass}">${statusText}</td>
                    <td>
                        ${!alert.acknowledged ? 
                            `<button class="btn btn-sm btn-acknowledge" onclick="acknowledgeAlert(${alert.id})">
                                <i class="fas fa-check"></i> Acknowledge
                            </button>
                            <button class="btn btn-sm btn-investigate" onclick="investigateAlert(${alert.id})">
                                <i class="fas fa-search"></i> Investigate
                            </button>` : 
                            '<span class="text-muted">No actions</span>'
                        }
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
            html = '<tr><td colspan="4" class="text-center">No pages crawled yet</td></tr>';
        } else {
            pages.forEach(function(page) {
                let threatColor = page.threat_score >= 70 ? 'text-danger' : 
                                (page.threat_score >= 40 ? 'text-warning' : 'text-success');
                html += `<tr>
                    <td><a href="${escapeHtml(page.url)}" target="_blank" style="color: #66b0ff;">${escapeHtml(page.url.substring(0, 60))}</a></td>
                    <td>${escapeHtml(page.title)}</td>
                    <td>${formatDate(page.crawled_at)}</td>
                    <td class="${threatColor}">${page.threat_score}</td>
                </tr>`;
            });
        }
        $('#pages-tbody').html(html);
    });
}

// Acknowledge alert
function acknowledgeAlert(alertId) {
    $.ajax({
        url: '/api/alerts/' + alertId,
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify({action: 'acknowledge', acknowledged_by: 'dashboard_user'}),
        success: function(response) {
            if (response.success) {
                loadAlerts();
                loadStatistics();
                showToast('Alert acknowledged', 'success');
            }
        }
    });
}

// Investigate alert
function investigateAlert(alertId) {
    $.ajax({
        url: '/api/alerts/' + alertId,
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify({action: 'investigate'}),
        success: function(response) {
            if (response.success) {
                loadAlerts();
                showToast('Alert marked for investigation', 'info');
            }
        }
    });
}

// Refresh all data
function refreshData() {
    loadStatistics();
    loadAlerts();
    loadRecentPages();
}

// Show notification for new alert
function showNotification(alert) {
    if (Notification.permission === 'granted') {
        new Notification('Dark Web Alert', {
            body: `${alert.alert_level}: ${alert.title}`,
            icon: '/static/favicon.ico'
        });
    }
    
    // Also show toast
    showToast(`New ${alert.alert_level} alert: ${alert.title}`, 'danger');
}

// Show toast message
function showToast(message, type) {
    // Simple alert for now - can be enhanced with toast library
    console.log(`[${type.toUpperCase()}] ${message}`);
}

// Refresh charts
function refreshCharts() {
    loadCharts();
}

// Utility functions
function formatDate(dateString) {
    let date = new Date(dateString);
    let now = new Date();
    let diff = Math.floor((now - date) / 1000);
    
    if (diff < 60) return 'Just now';
    if (diff < 3600) return Math.floor(diff / 60) + ' minutes ago';
    if (diff < 86400) return Math.floor(diff / 3600) + ' hours ago';
    return date.toLocaleDateString();
}

function escapeHtml(text) {
    if (!text) return '';
    return text.replace(/[&<>]/g, function(m) {
        if (m === '&') return '&amp;';
        if (m === '<') return '&lt;';
        if (m === '>') return '&gt;';
        return m;
    });
}

// Request notification permission
if (Notification.permission === 'default') {
    Notification.requestPermission();
}
