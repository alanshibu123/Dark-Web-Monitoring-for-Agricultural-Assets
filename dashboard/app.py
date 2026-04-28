"""
Dashboard Module for Dark Web Agriculture Monitor
Web-based interface for visualization, alert management, and system monitoring
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import plotly.graph_objs as go
import plotly.utils
import pandas as pd
from collections import Counter
import threading
import time
from sqlalchemy import func
# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.database import DatabaseManager, DataStorageService
from config.settings import config_manager

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = 'dark-web-agri-monitor-secret-key'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize database connection
db_manager = DatabaseManager()
storage = DataStorageService(db_manager)

logger = logging.getLogger(__name__)


# ============================================================================
# Routes
# ============================================================================

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/statistics')
def get_statistics():
    """Get system statistics"""
    from sqlalchemy import func
    
    # Get raw statistics and convert to serializable format
    stats_raw = db_manager.get_statistics()
    
    # Convert any model objects to dictionaries or primitive types
    stats = {}
    for key, value in stats_raw.items():
        if hasattr(value, '__dict__'):  # It's a model object
            # Try to convert to dict, or extract id/name
            if hasattr(value, 'id'):
                stats[key] = value.id
            elif hasattr(value, 'name'):
                stats[key] = value.name
            else:
                stats[key] = str(value)
        elif isinstance(value, datetime):
            stats[key] = value.isoformat()
        else:
            stats[key] = value
    
    # Add time-based statistics
    now = datetime.now()
    week_ago = now - timedelta(days=7)
    
    with db_manager.get_session() as session:
        from storage.database import CrawledPageModel, AlertModel, NLPResultModel
        
        # Weekly trends
        weekly_pages = session.query(CrawledPageModel).filter(
            CrawledPageModel.crawled_at >= week_ago
        ).count()
        
        weekly_alerts = session.query(AlertModel).filter(
            AlertModel.generated_at >= week_ago
        ).count()
        
        # Average threat score
        avg_threat = session.query(
            func.avg(NLPResultModel.threat_score)
        ).filter(
            NLPResultModel.analyzed_at >= week_ago
        ).scalar()
    
    stats.update({
        'weekly_pages': weekly_pages,
        'weekly_alerts': weekly_alerts,
        'avg_threat_score': round(avg_threat or 0, 1),
        'system_status': 'healthy',
        'last_update': now.isoformat()
    })
    
    return jsonify(stats)

@app.route('/api/alerts')
def get_alerts():
    """Get alerts with filtering"""
    limit = request.args.get('limit', 50, type=int)
    severity = request.args.get('severity', None)
    acknowledged = request.args.get('acknowledged', None)
    
    with db_manager.get_session() as session:
        from storage.database import AlertModel, CrawledPageModel
        
        query = session.query(AlertModel)
        
        if severity:
            query = query.filter(AlertModel.alert_level == severity.upper())
        
        if acknowledged is not None:
            ack_bool = acknowledged.lower() == 'true'
            query = query.filter(AlertModel.acknowledged == ack_bool)
        
        alerts = query.order_by(
            AlertModel.risk_score.desc(),
            AlertModel.generated_at.desc()
        ).limit(limit).all()
        
        result = []
        for alert in alerts:
            result.append({
                'id': alert.id,
                'alert_level': alert.alert_level,
                'alert_type': alert.alert_type,
                'title': alert.title,
                'description': alert.description[:200],
                'risk_score': alert.risk_score,
                'generated_at': alert.generated_at.isoformat(),
                'acknowledged': alert.acknowledged,
                'page_url': alert.page.url if alert.page else None
            })
    
    return jsonify(result)


@app.route('/api/alerts/<int:alert_id>', methods=['PUT', 'POST'])
def update_alert(alert_id):
    """Update alert (acknowledge, resolve, etc.)"""
    data = request.json
    action = data.get('action')
    
    with db_manager.get_session() as session:
        from storage.database import AlertModel
        
        alert = session.query(AlertModel).filter(AlertModel.id == alert_id).first()
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        if action == 'acknowledge':
            alert.acknowledged = True
            alert.acknowledged_by = data.get('acknowledged_by', 'dashboard_user')
            alert.acknowledged_at = datetime.now()
            message = f"Alert {alert_id} acknowledged"
        elif action == 'resolve':
            alert.resolved = True
            message = f"Alert {alert_id} resolved"
        elif action == 'investigate':
            alert.status = 'investigating'
            message = f"Alert {alert_id} marked as investigating"
        else:
            return jsonify({'error': 'Invalid action'}), 400
        
        session.commit()
        
        # Emit socket event for real-time update
        socketio.emit('alert_updated', {'alert_id': alert_id, 'action': action})
        
        return jsonify({'success': True, 'message': message})



@app.route('/api/entity-stats')
def get_entity_stats():
    """Get entity statistics for visualization"""
    with db_manager.get_session() as session:
        from storage.database import EntityModel
        
        # Get top entity types
        entity_types = session.query(
            EntityModel.entity_type,
            func.count(EntityModel.id).label('count')
        ).group_by(EntityModel.entity_type).order_by(func.count(EntityModel.id).desc()).limit(10).all()
        
        # Get top entity values
        entity_values = session.query(
            EntityModel.value,
            func.count(EntityModel.id).label('count')
        ).group_by(EntityModel.value).order_by(func.count(EntityModel.id).desc()).limit(10).all()
        
        return jsonify({
            'entity_types': [{'type': t[0], 'count': t[1]} for t in entity_types],
            'entity_values': [{'value': v[0], 'count': v[1]} for v in entity_values]
        })


@app.route('/api/keyword-stats')
def get_keyword_stats():
    """Get keyword detection statistics"""
    with db_manager.get_session() as session:
        from storage.database import KeywordMatchModel
        
        # Top keywords
        top_keywords = session.query(
            KeywordMatchModel.keyword,
            func.count(KeywordMatchModel.id).label('count')
        ).group_by(KeywordMatchModel.keyword).order_by(
            func.count(KeywordMatchModel.id).desc()
        ).limit(20).all()
        
        # Matches by category
        category_stats = session.query(
            KeywordMatchModel.category,
            func.count(KeywordMatchModel.id).label('count')
        ).group_by(KeywordMatchModel.category).all()
        
        return jsonify({
            'top_keywords': [{'keyword': k[0], 'count': k[1]} for k in top_keywords],
            'category_stats': [{'category': c[0], 'count': c[1]} for c in category_stats]
        })


@app.route('/api/recent-pages')
def get_recent_pages():
    """Get recently crawled pages"""
    limit = request.args.get('limit', 20, type=int)
    
    with db_manager.get_session() as session:
        from storage.database import CrawledPageModel, NLPResultModel
        
        pages = session.query(CrawledPageModel).order_by(
            CrawledPageModel.crawled_at.desc()
        ).limit(limit).all()
        
        result = []
        for page in pages:
            # Get NLP result for threat score
            nlp = session.query(NLPResultModel).filter(
                NLPResultModel.page_id == page.id
            ).first()
            
            result.append({
                'id': page.id,
                'url': page.url,
                'title': page.title[:100] if page.title else 'No Title',
                'crawled_at': page.crawled_at.isoformat(),
                'status_code': page.status_code,
                'content_length': page.content_length,
                'threat_score': nlp.threat_score if nlp else 0
            })
    
    return jsonify(result)


@app.route('/api/search')
def search():
    """Search across alerts and pages"""
    query = request.args.get('q', '')
    search_type = request.args.get('type', 'all')
    
    if not query:
        return jsonify({'error': 'No search query'}), 400
    
    results = {'alerts': [], 'pages': [], 'keywords': []}
    
    with db_manager.get_session() as session:
        from storage.database import AlertModel, CrawledPageModel, KeywordMatchModel
        
        # Search alerts
        if search_type in ['all', 'alerts']:
            alerts = session.query(AlertModel).filter(
                AlertModel.title.contains(query) | AlertModel.description.contains(query)
            ).limit(20).all()
            
            results['alerts'] = [{
                'id': a.id,
                'title': a.title,
                'alert_level': a.alert_level,
                'generated_at': a.generated_at.isoformat()
            } for a in alerts]
        
        # Search pages
        if search_type in ['all', 'pages']:
            pages = session.query(CrawledPageModel).filter(
                CrawledPageModel.url.contains(query) | CrawledPageModel.title.contains(query)
            ).limit(20).all()
            
            results['pages'] = [{
                'id': p.id,
                'url': p.url,
                'title': p.title[:100] if p.title else 'No Title',
                'crawled_at': p.crawled_at.isoformat()
            } for p in pages]
        
        # Search keywords
        if search_type in ['all', 'keywords']:
            keywords = session.query(KeywordMatchModel).filter(
                KeywordMatchModel.keyword.contains(query)
            ).limit(20).all()
            
            results['keywords'] = [{
                'keyword': k.keyword,
                'category': k.category,
                'page_url': k.page.url if k.page else None
            } for k in keywords]
    
    return jsonify(results)


@app.route('/api/charts/threat-trend')
def chart_threat_trend():
    """Generate threat trend data for Chart.js"""
    hours = request.args.get('hours', 168, type=int)
    
    with db_manager.get_session() as session:
        from storage.database import NLPResultModel, CrawledPageModel
        
        since = datetime.now() - timedelta(hours=hours)
        
        results = session.query(
            CrawledPageModel.crawled_at,
            NLPResultModel.threat_score
        ).join(
            NLPResultModel, CrawledPageModel.id == NLPResultModel.page_id
        ).filter(
            CrawledPageModel.crawled_at >= since
        ).order_by(
            CrawledPageModel.crawled_at
        ).all()
        
        if not results:
            return jsonify({
                'labels': [],
                'scores': [],
                'message': 'No data available. Run a crawl first.'
            })
        
        # Format for Chart.js
        labels = []
        scores = []
        for r in results:
            labels.append(r[0].strftime('%Y-%m-%d %H:%M'))
            scores.append(float(r[1]) if r[1] else 0)
        
        return jsonify({
            'labels': labels,
            'scores': scores
        })
    
@app.route('/api/threat-timeline')
def get_threat_timeline():
    """Get real threat score timeline from database"""
    hours = request.args.get('hours', 168, type=int)
    
    with db_manager.get_session() as session:
        from storage.database import NLPResultModel, CrawledPageModel
        
        since = datetime.now() - timedelta(hours=hours)
        
        # Join to get threat scores with timestamps
        results = session.query(
            CrawledPageModel.crawled_at,
            NLPResultModel.threat_score
        ).join(
            NLPResultModel, CrawledPageModel.id == NLPResultModel.page_id
        ).filter(
            CrawledPageModel.crawled_at >= since
        ).order_by(
            CrawledPageModel.crawled_at
        ).all()
        
        if not results:
            # Return empty array, not mock data
            return jsonify([])
        
        timeline = [
            {
                'timestamp': r[0].isoformat(),
                'threat_score': float(r[1]) if r[1] else 0
            }
            for r in results
        ]
        
        return jsonify(timeline)

@app.route('/api/charts/alert-distribution')
def chart_alert_distribution():
    """Get real alert distribution for Chart.js"""
    with db_manager.get_session() as session:
        from storage.database import AlertModel
        from sqlalchemy import func
        
        severity_counts = session.query(
            AlertModel.alert_level,
            func.count(AlertModel.id).label('count')
        ).group_by(AlertModel.alert_level).all()
        
        if not severity_counts:
            return jsonify({
                'labels': ['Critical', 'High', 'Medium', 'Low'],
                'values': [0, 0, 0, 0]
            })
        
        # Map severity to consistent order
        severity_map = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for severity, count in severity_counts:
            if severity in severity_map:
                severity_map[severity] = count
        
        return jsonify({
            'labels': ['Critical', 'High', 'Medium', 'Low'],
            'values': [severity_map['CRITICAL'], severity_map['HIGH'], 
                      severity_map['MEDIUM'], severity_map['LOW']]
        })

@app.route('/api/charts/entity-wordcloud')
def chart_entity_wordcloud():
    """Generate entity word cloud data"""
    with db_manager.get_session() as session:
        from storage.database import NamedEntityModel
        
        entities = session.query(
            NamedEntityModel.text,
            func.count(NamedEntityModel.id).label('count')
        ).group_by(NamedEntityModel.text).order_by(
            func.count(NamedEntityModel.id).desc()
        ).limit(50).all()
        
        wordcloud_data = [{'text': e[0], 'value': e[1]} for e in entities]
        
        return jsonify(wordcloud_data)


@app.route('/api/feedback', methods=['POST'])
def submit_feedback():
    """Submit feedback for an alert or match"""
    data = request.json
    
    with db_manager.get_session() as session:
        from storage.database import KeywordMatchModel, AlertModel
        
        feedback_data = {
            'alert_id': data.get('alert_id'),
            'match_id': data.get('match_id'),
            'feedback_type': data.get('feedback_type'),
            'keyword': data.get('keyword'),
            'category': data.get('category'),
            'original_confidence': data.get('original_confidence'),
            'source_url': data.get('source_url'),
            'feedback_from': data.get('feedback_from', 'dashboard_user'),
            'feedback_comment': data.get('feedback_comment', '')
        }
        
        # Calculate adjusted confidence
        if feedback_data['feedback_type'] == 'false_positive':
            # Reduce confidence for future matches
            feedback_data['adjusted_confidence'] = max(0.1, feedback_data['original_confidence'] * 0.5)
        elif feedback_data['feedback_type'] == 'true_positive':
            # Boost confidence slightly
            feedback_data['adjusted_confidence'] = min(0.95, feedback_data['original_confidence'] * 1.1)
        else:
            feedback_data['adjusted_confidence'] = feedback_data['original_confidence']
        
        feedback_id = storage.save_feedback(feedback_data)
        
        # Also update the alert status
        if data.get('alert_id'):
            alert = session.query(AlertModel).filter(AlertModel.id == data['alert_id']).first()
            if alert:
                if data['feedback_type'] == 'false_positive':
                    alert.status = 'false_positive'
                elif data['feedback_type'] == 'true_positive':
                    alert.status = 'confirmed'
        
        session.commit()
        
        # Notify connected clients
        socketio.emit('feedback_received', {
            'feedback_id': feedback_id,
            'feedback_type': data['feedback_type'],
            'keyword': data.get('keyword')
        })
        
        return jsonify({'success': True, 'feedback_id': feedback_id})


@app.route('/api/feedback/stats')
def get_feedback_stats():
    """Get feedback statistics for dashboard"""
    keyword = request.args.get('keyword')
    category = request.args.get('category')
    
    stats = storage.get_feedback_stats(keyword=keyword, category=category)
    return jsonify(stats)


@app.route('/api/feedback/history')
def get_feedback_history():
    """Get recent feedback history"""
    limit = request.args.get('limit', 50, type=int)
    
    with db_manager.get_session() as session:
        from storage.database import FeedbackModel
        
        feedbacks = session.query(FeedbackModel).order_by(
            FeedbackModel.created_at.desc()
        ).limit(limit).all()
        
        result = []
        for f in feedbacks:
            result.append({
                'id': f.id,
                'feedback_type': f.feedback_type,
                'keyword': f.keyword,
                'category': f.category,
                'original_confidence': f.original_confidence,
                'adjusted_confidence': f.adjusted_confidence,
                'created_at': f.created_at.isoformat(),
                'feedback_from': f.feedback_from,
                'comment': f.feedback_comment
            })
        
        return jsonify(result)


# ============================================================================
# WebSocket Events for Real-time Updates
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('connected', {'message': 'Connected to dashboard'})


@socketio.on('subscribe_alerts')
def handle_subscribe_alerts():
    """Subscribe to real-time alert updates"""
    logger.info(f"Client {request.sid} subscribed to alerts")
    emit('subscribed', {'channel': 'alerts'})


def broadcast_new_alert(alert_data):
    """Broadcast new alert to all connected clients"""
    socketio.emit('new_alert', alert_data)


# ============================================================================
# Static Files
# ============================================================================

@app.route('/static/<path:path>')
def serve_static(path):
    """Serve static files"""
    return send_from_directory('static', path)


# ============================================================================
# Dashboard HTML Template
# ============================================================================

def create_template_files():
    """Create HTML template files if they don't exist"""
    os.makedirs('dashboard/templates', exist_ok=True)
    os.makedirs('dashboard/static/css', exist_ok=True)
    os.makedirs('dashboard/static/js', exist_ok=True)
    
    # Create main dashboard template
    template_path = 'dashboard/templates/dashboard.html'
    if not os.path.exists(template_path):
        with open(template_path, 'w') as f:
            f.write(DASHBOARD_HTML)
    
    # Create CSS file
    css_path = 'dashboard/static/css/style.css'
    if not os.path.exists(css_path):
        with open(css_path, 'w') as f:
            f.write(CSS_STYLES)
    
    # Create JS file
    js_path = 'dashboard/static/js/dashboard.js'
    if not os.path.exists(js_path):
        with open(js_path, 'w') as f:
            f.write(JAVASCRIPT_CODE)


# ============================================================================
# HTML/CSS/JS Templates (Embedded for completeness)
# ============================================================================

DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dark Web Agriculture Monitor - Dashboard</title>
    <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
    <script src="https://cdn.plot.ly/plotly-2.27.1.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="/static/css/style.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container-fluid">
            <span class="navbar-brand">
                <i class="fas fa-shield-alt"></i>
                Dark Web Agriculture Monitor
            </span>
            <div class="text-white">
                <i class="fas fa-circle text-success" style="font-size: 10px;"></i>
                <span id="connection-status">Connected</span>
            </div>
        </div>
    </nav>

    <div class="container-fluid mt-3">
        <!-- Statistics Cards -->
        <div class="row" id="stats-cards">
            <div class="col-md-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <h5 class="card-title">Total Pages</h5>
                        <h2 id="total-pages">0</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <h5 class="card-title">Total Alerts</h5>
                        <h2 id="total-alerts">0</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <h5 class="card-title">Unacknowledged</h5>
                        <h2 id="unacknowledged-alerts">0</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <h5 class="card-title">Avg Threat Score</h5>
                        <h2 id="avg-threat">0</h2>
                    </div>
                </div>
            </div>
        </div>

        <!-- Charts Row -->
        <div class="row mt-3">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-chart-line"></i> Threat Trend
                    </div>
                    <div class="card-body">
                        <div id="threat-trend-chart"></div>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-chart-pie"></i> Alert Distribution
                    </div>
                    <div class="card-body">
                        <div id="alert-distribution-chart"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Alerts Table -->
        <div class="row mt-3">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-bell"></i> Recent Alerts
                        <div class="float-right">
                            <select id="severity-filter" class="form-select form-select-sm" style="width: auto; display: inline-block;">
                                <option value="all">All Severities</option>
                                <option value="CRITICAL">Critical</option>
                                <option value="HIGH">High</option>
                                <option value="MEDIUM">Medium</option>
                                <option value="LOW">Low</option>
                            </select>
                            <button class="btn btn-sm btn-primary" onclick="refreshAlerts()">
                                <i class="fas fa-sync-alt"></i> Refresh
                            </button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover" id="alerts-table">
                                <thead>
                                    <tr>
                                        <th>Severity</th>
                                        <th>Title</th>
                                        <th>Risk Score</th>
                                        <th>Time</th>
                                        <th>Status</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody id="alerts-tbody">
                                    <tr><td colspan="6" class="text-center">Loading alerts...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Recent Pages -->
        <div class="row mt-3 mb-5">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-globe"></i> Recently Crawled Pages
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-sm" id="pages-table">
                                <thead>
                                    <tr>
                                        <th>URL</th>
                                        <th>Title</th>
                                        <th>Crawled At</th>
                                        <th>Threat Score</th>
                                    </tr>
                                </thead>
                                <tbody id="pages-tbody">
                                    <tr><td colspan="4" class="text-center">Loading pages...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="/static/js/dashboard.js"></script>
</body>
</html>
'''

CSS_STYLES = '''
body {
    background-color: #1a1a2e;
    color: #eee;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

.navbar {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.stat-card {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    border: none;
    border-radius: 10px;
    transition: transform 0.3s;
}

.stat-card:hover {
    transform: translateY(-5px);
}

.stat-card h2 {
    font-size: 2.5rem;
    font-weight: bold;
    margin-bottom: 0;
}

.card {
    background-color: #2d2d44;
    border: none;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.3);
}

.card-header {
    background-color: rgba(0,0,0,0.3);
    border-bottom: 1px solid rgba(255,255,255,0.1);
    font-weight: bold;
}

.table {
    color: #eee;
}

.table thead th {
    border-bottom: 2px solid rgba(255,255,255,0.2);
}

.table-hover tbody tr:hover {
    background-color: rgba(255,255,255,0.1);
}

.badge-critical {
    background-color: #dc3545;
}

.badge-high {
    background-color: #fd7e14;
}

.badge-medium {
    background-color: #ffc107;
    color: #000;
}

.badge-low {
    background-color: #17a2b8;
}

.btn-acknowledge {
    background-color: #28a745;
    border: none;
    padding: 2px 10px;
    font-size: 12px;
}

.btn-investigate {
    background-color: #17a2b8;
    border: none;
    padding: 2px 10px;
    font-size: 12px;
}

.alert-animation {
    animation: pulse 1s;
}

@keyframes pulse {
    0% { background-color: rgba(220, 53, 69, 0); }
    50% { background-color: rgba(220, 53, 69, 0.3); }
    100% { background-color: rgba(220, 53, 69, 0); }
}
'''

JAVASCRIPT_CODE = '''
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
'''

# Create template files on module load
create_template_files()


# ============================================================================
# Main Entry Point
# ============================================================================

def run_dashboard(host='0.0.0.0', port=5000, debug=False):
    """Run the dashboard server"""
    logger.info(f"Starting dashboard on {host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    run_dashboard(debug=True)