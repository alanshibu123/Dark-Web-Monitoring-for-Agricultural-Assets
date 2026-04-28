"""
Alert Generation Module for Dark Web Agriculture Monitor
Handles multi-channel alerts, severity classification, escalation, and notification delivery
"""

import os
import sys
import json
import smtplib
import logging
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import hashlib
import time

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import config_manager
from storage.database import DatabaseManager, DataStorageService
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0
    
    def __str__(self):
        return self.name
    
    @classmethod
    def from_risk_score(cls, risk_score: float) -> 'AlertSeverity':
        if risk_score >= 90:
            return cls.CRITICAL
        elif risk_score >= 65: 
            return cls.HIGH
        elif risk_score >= 40: 
            return cls.MEDIUM
        elif risk_score >= 20:  
            return cls.LOW
        else:
            return cls.INFO 


class AlertChannel(Enum):
    """Alert delivery channels"""
    EMAIL = "email"
    WEBHOOK = "webhook"
    LOG = "log"
    DASHBOARD = "dashboard"
    SMS = "sms"  # Future implementation
    SLACK = "slack"  # Future implementation


class AlertStatus(Enum):
    """Alert lifecycle status"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    ESCALATED = "escalated"


@dataclass
class Alert:
    """Alert data structure"""
    id: Optional[int]
    title: str
    description: str
    severity: AlertSeverity
    alert_type: str
    source_url: str
    risk_score: float
    matched_keywords: List[str]
    affected_assets: List[str]
    recommendations: List[str]
    created_at: datetime
    status: AlertStatus
    assigned_to: Optional[str] = None
    escalation_level: int = 0
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['severity_name'] = self.severity.name
        data['status'] = self.status.value
        data['created_at'] = self.created_at.isoformat()
        return data
    
    def to_email_html(self) -> str:
        """Generate professional HTML email content"""
        
        # Severity colors
        severity_colors = {
            AlertSeverity.CRITICAL: '#dc3545',
            AlertSeverity.HIGH: '#fd7e14',
            AlertSeverity.MEDIUM: '#ffc107',
            AlertSeverity.LOW: '#17a2b8',
            AlertSeverity.INFO: '#6c757d'
        }
        
        severity_icons = {
            AlertSeverity.CRITICAL: '🔴',
            AlertSeverity.HIGH: '🟠',
            AlertSeverity.MEDIUM: '🟡',
            AlertSeverity.LOW: '🔵',
            AlertSeverity.INFO: '⚪'
        }
        
        color = severity_colors.get(self.severity, '#6c757d')
        icon = severity_icons.get(self.severity, '⚠️')
        
        # Format keywords
        keywords_html = ''
        for kw in self.matched_keywords[:10]:
            keywords_html += f'<span style="display: inline-block; background: #e9ecef; padding: 4px 10px; border-radius: 20px; font-size: 12px; margin: 2px;">{kw}</span> '
        
        if not keywords_html:
            keywords_html = '<span style="color: #6c757d;">No keywords matched</span>'
        
        # Format assets
        assets_html = ''
        for asset in self.affected_assets[:5]:
            assets_html += f'<li style="margin: 5px 0;">🔹 {asset}</li>'
        
        if not assets_html:
            assets_html = '<li style="color: #6c757d;">No specific assets identified</li>'
        
        # Format recommendations
        recs_html = ''
        for rec in self.recommendations[:5]:
            recs_html += f'<li style="margin: 8px 0; color: #28a745;">✓ {rec}</li>'
        
        if not recs_html:
            recs_html = '<li style="color: #6c757d;">Review the alert for details</li>'
        
        # Build HTML email
        html = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dark Web Alert: {self.title[:50]}</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f4f6f9;
                margin: 0;
                padding: 20px;
            }}
            .container {{
                max-width: 600px;
                margin: 0 auto;
                background: white;
                border-radius: 16px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                color: white;
                padding: 30px;
                text-align: center;
            }}
            .header h1 {{
                margin: 0;
                font-size: 24px;
                font-weight: 600;
            }}
            .header p {{
                margin: 10px 0 0;
                opacity: 0.8;
                font-size: 14px;
            }}
            .severity-badge {{
                display: inline-block;
                background: {color};
                color: white;
                padding: 6px 16px;
                border-radius: 30px;
                font-size: 14px;
                font-weight: bold;
                margin-top: 15px;
            }}
            .content {{
                padding: 30px;
            }}
            .section {{
                margin-bottom: 25px;
                border-bottom: 1px solid #eef2f6;
                padding-bottom: 20px;
            }}
            .section-title {{
                font-size: 16px;
                font-weight: 600;
                color: #1a1a2e;
                margin-bottom: 15px;
                display: flex;
                align-items: center;
                gap: 8px;
            }}
            .section-title i {{
                font-size: 20px;
            }}
            .info-row {{
                display: flex;
                margin-bottom: 12px;
            }}
            .info-label {{
                width: 120px;
                font-weight: 600;
                color: #6c757d;
            }}
            .info-value {{
                flex: 1;
                color: #333;
                word-break: break-all;
            }}
            .risk-score {{
                font-size: 28px;
                font-weight: bold;
                color: {color};
            }}
            .keywords {{
                margin-top: 10px;
            }}
            .footer {{
                background: #f8f9fa;
                padding: 20px 30px;
                text-align: center;
                font-size: 12px;
                color: #6c757d;
                border-top: 1px solid #eef2f6;
            }}
            .button {{
                display: inline-block;
                background: {color};
                color: white;
                text-decoration: none;
                padding: 10px 20px;
                border-radius: 8px;
                margin-top: 10px;
                font-weight: 500;
            }}
            @media (max-width: 600px) {{
                .content {{
                    padding: 20px;
                }}
                .info-row {{
                    flex-direction: column;
                }}
                .info-label {{
                    width: auto;
                    margin-bottom: 4px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>{icon} Dark Web Agriculture Monitor</h1>
                <p>Automated Threat Detection Alert</p>
                <div class="severity-badge">{self.severity.name} SEVERITY</div>
            </div>
            
            <div class="content">
                <div class="section">
                    <div class="section-title">
                        <span>⚠️</span> Alert Summary
                    </div>
                    <div class="info-row">
                        <div class="info-label">Alert Title:</div>
                        <div class="info-value"><strong>{self.title}</strong></div>
                    </div>
                    <div class="info-row">
                        <div class="info-label">Risk Score:</div>
                        <div class="info-value"><span class="risk-score">{self.risk_score:.0f}</span>/100</div>
                    </div>
                    <div class="info-row">
                        <div class="info-label">Alert Type:</div>
                        <div class="info-value">{self.alert_type.replace('_', ' ').title()}</div>
                    </div>
                    <div class="info-row">
                        <div class="info-label">Detected At:</div>
                        <div class="info-value">{self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
                    </div>
                </div>
                
                <div class="section">
                    <div class="section-title">
                        <span>🔗</span> Source Information
                    </div>
                    <div class="info-row">
                        <div class="info-label">Dark Web Source:</div>
                        <div class="info-value"><a href="{self.source_url}" style="color: {color};">{self.source_url[:80]}</a></div>
                    </div>
                </div>
                
                <div class="section">
                    <div class="section-title">
                        <span>📝</span> Description
                    </div>
                    <p style="margin: 0; line-height: 1.6;">{self.description}</p>
                </div>
                
                <div class="section">
                    <div class="section-title">
                        <span>🔑</span> Matched Keywords
                    </div>
                    <div class="keywords">
                        {keywords_html}
                    </div>
                </div>
                
                <div class="section">
                    <div class="section-title">
                        <span>🏢</span> Affected Assets
                    </div>
                    <ul style="margin: 0; padding-left: 20px;">
                        {assets_html}
                    </ul>
                </div>
                
                <div class="section">
                    <div class="section-title">
                        <span>📋</span> Remediation Recommendations
                    </div>
                    <ul style="margin: 0; padding-left: 20px;">
                        {recs_html}
                    </ul>
                </div>
                
                <div style="text-align: center;">
                    <a href="{self.source_url}" class="button">View Full Alert</a>
                </div>
            </div>
            
            <div class="footer">
                <p>This is an automated alert from your Dark Web Agriculture Monitor.</p>
                <p>For questions or to configure alert settings, contact your security team.</p>
                <p style="margin-top: 10px; font-size: 11px;">Dark Web Agriculture Monitor v1.0 | SOC Dashboard</p>
            </div>
        </div>
    </body>
    </html>
    """
        return html
    
    def to_slack_payload(self) -> Dict:
        """Generate Slack webhook payload with rich formatting"""
        
        # Color mapping for severity
        color_map = {
            AlertSeverity.CRITICAL: '#dc3545',  # Red
            AlertSeverity.HIGH: '#fd7e14',      # Orange
            AlertSeverity.MEDIUM: '#ffc107',    # Yellow
            AlertSeverity.LOW: '#17a2b8',       # Blue
            AlertSeverity.INFO: '#6c757d'       # Gray
        }
        
        # Emoji mapping
        emoji_map = {
            AlertSeverity.CRITICAL: '🔴 CRITICAL',
            AlertSeverity.HIGH: '🟠 HIGH',
            AlertSeverity.MEDIUM: '🟡 MEDIUM',
            AlertSeverity.LOW: '🔵 LOW',
            AlertSeverity.INFO: '⚪ INFO'
        }
        
        # Format matched keywords nicely
        keywords_text = ''
        if self.matched_keywords:
            keywords_list = self.matched_keywords[:10]
            keywords_text = '\n'.join([f'• `{kw}`' for kw in keywords_list])
        else:
            keywords_text = 'None'
        
        # Format affected assets
        assets_text = ''
        if self.affected_assets:
            assets_text = '\n'.join([f'• {asset}' for asset in self.affected_assets[:5]])
        else:
            assets_text = 'None'
        
        # Format recommendations
        recs_text = ''
        if self.recommendations:
            recs_text = '\n'.join([f'• {rec}' for rec in self.recommendations[:5]])
        else:
            recs_text = 'None'
        
        return {
            'attachments': [{
                'color': color_map.get(self.severity, '#6c757d'),
                'title': f"{emoji_map.get(self.severity, '⚠️')} {self.title}",
                'title_link': self.source_url,
                'fields': [
                    {
                        'title': '📊 Risk Score',
                        'value': f"{self.risk_score:.0f}/100",
                        'short': True
                    },
                    {
                        'title': '📂 Alert Type',
                        'value': self.alert_type.replace('_', ' ').title(),
                        'short': True
                    },
                    {
                        'title': '🔑 Matched Keywords',
                        'value': keywords_text,
                        'short': False
                    },
                    {
                        'title': '🏢 Affected Assets',
                        'value': assets_text,
                        'short': False
                    },
                    {
                        'title': '📋 Recommendations',
                        'value': recs_text,
                        'short': False
                    }
                ],
                'footer': '🌾 Dark Web Agriculture Monitor',
                'footer_icon': 'https://www.agriculture.com/favicon.ico',
                'ts': int(self.created_at.timestamp())
            }]
        }
class AlertDeduplicator:
    """
    Prevents duplicate alerts for the same incident
    """
    
    def __init__(self, window_minutes: int = 60):
        """
        Initialize deduplicator
        
        Args:
            window_minutes: Time window for considering duplicates
        """
        self.window_minutes = window_minutes
        self.recent_alerts = deque(maxlen=1000)  # Store recent alert hashes
        self.logger = logging.getLogger(__name__)
    
    def _generate_hash(self, alert: Alert) -> str:
        """Generate unique hash for alert deduplication"""
        # Combine key fields that identify unique incidents
        key_fields = f"{alert.alert_type}_{alert.source_url}_{'_'.join(sorted(alert.matched_keywords[:3]))}"
        return hashlib.md5(key_fields.encode()).hexdigest()
    
    def is_duplicate(self, alert: Alert) -> bool:
        """
        Check if alert is a duplicate of a recent alert
        
        Args:
            alert: Alert to check
        
        Returns:
            True if duplicate, False otherwise
        """
        alert_hash = self._generate_hash(alert)
        
        # Check if hash exists in recent alerts
        for recent_hash, timestamp in self.recent_alerts:
            if recent_hash == alert_hash:
                # Check if within time window
                if (datetime.now() - timestamp).total_seconds() < self.window_minutes * 60:
                    self.logger.debug(f"Duplicate alert suppressed: {alert.title}")
                    return True
        
        # Add to recent alerts
        self.recent_alerts.append((alert_hash, datetime.now()))
        return False


class EscalationPolicy:
    """
    Handles alert escalation based on severity and duration
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Escalation rules
        self.escalation_rules = {
            AlertSeverity.CRITICAL: {
                'initial_delay_minutes': 5,
                'escalation_interval_minutes': 15,
                'max_escalations': 3,
                'targets': ['security_lead', 'it_director', 'ciso']
            },
            AlertSeverity.HIGH: {
                'initial_delay_minutes': 15,
                'escalation_interval_minutes': 30,
                'max_escalations': 2,
                'targets': ['security_analyst', 'security_lead']
            },
            AlertSeverity.MEDIUM: {
                'initial_delay_minutes': 60,
                'escalation_interval_minutes': 120,
                'max_escalations': 1,
                'targets': ['security_analyst']
            },
            AlertSeverity.LOW: {
                'initial_delay_minutes': 240,
                'escalation_interval_minutes': 0,
                'max_escalations': 0,
                'targets': []
            },
            AlertSeverity.INFO: {
                'initial_delay_minutes': 0,
                'escalation_interval_minutes': 0,
                'max_escalations': 0,
                'targets': []
            }
        }
    
    def should_escalate(self, alert: Alert, time_since_creation: timedelta) -> bool:
        """
        Determine if alert should be escalated
        
        Args:
            alert: Alert to check
            time_since_creation: Time since alert was created
        
        Returns:
            True if escalation needed
        """
        if alert.status != AlertStatus.NEW and alert.status != AlertStatus.ACKNOWLEDGED:
            return False
        
        rules = self.escalation_rules.get(alert.severity)
        if not rules or rules['max_escalations'] == 0:
            return False
        
        if alert.escalation_level >= rules['max_escalations']:
            return False
        
        # Calculate next escalation time
        if alert.escalation_level == 0:
            delay = rules['initial_delay_minutes']
        else:
            delay = rules['escalation_interval_minutes']
        
        return time_since_creation.total_seconds() > delay * 60
    
    def get_next_escalation_target(self, alert: Alert) -> Optional[str]:
        """
        Get next escalation target based on current level
        
        Args:
            alert: Alert to escalate
        
        Returns:
            Target role or None
        """
        rules = self.escalation_rules.get(alert.severity)
        if not rules or not rules['targets']:
            return None
        
        if alert.escalation_level < len(rules['targets']):
            return rules['targets'][alert.escalation_level]
        
        return None


class AlertChannelManager:
    """
    Manages multiple alert delivery channels
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Load channel configurations
        self.email_enabled = config_manager.get('alerting.email_enabled', False)
        self.webhook_enabled = config_manager.get('alerting.webhook_enabled', False)
        self.log_alerts = config_manager.get('alerting.log_alerts', True)
        
        # Email configuration
        self.smtp_server = config_manager.get('alerting.smtp_server', '')
        self.smtp_port = config_manager.get('alerting.smtp_port', 587)
        self.from_email = config_manager.get('alerting.from_email', '')
        self.to_emails = config_manager.get('alerting.to_emails', [])
        
        # Webhook configuration
        self.webhook_url = config_manager.get('alerting.webhook_url', '')
        
        # Rate limiting
        self.last_send_time = defaultdict(float)
        self.rate_limit_seconds = 10  # Minimum seconds between sends to same channel
    
    def _check_rate_limit(self, channel: str) -> bool:
        """Check if channel is rate limited"""
        now = time.time()
        if now - self.last_send_time[channel] < self.rate_limit_seconds:
            return False
        self.last_send_time[channel] = now
        return True
    
    def send_email(self, alert: Alert) -> bool:
        """
        Send alert via email
        
        Args:
            alert: Alert to send
        
        Returns:
            True if successful, False otherwise
        """
        if not self.email_enabled or not self.smtp_server or not self.to_emails:
            return False
        
        if not self._check_rate_limit('email'):
            self.logger.warning("Email rate limit hit, skipping")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{alert.severity.name}] Dark Web Alert: {alert.title[:80]}"
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.to_emails)
            
            # HTML content
            html_content = alert.to_email_html()
            msg.attach(MIMEText(html_content, 'html'))
            
            # Also add plain text version
            text_content = f"""
            {alert.severity.name} ALERT: {alert.title}
            
            Risk Score: {alert.risk_score}/100
            Source: {alert.source_url}
            Time: {alert.created_at}
            
            Description: {alert.description}
            
            Matched Keywords: {', '.join(alert.matched_keywords[:5])}
            
            Recommendations:
            {chr(10).join('- ' + r for r in alert.recommendations)}
            """
            msg.attach(MIMEText(text_content, 'plain'))
            
            # ============================================================
            # FIXED: Add authentication for email
            # ============================================================
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                # Use credentials from config
                username = config_manager.get('alerting.email_username', self.from_email)
                password = config_manager.get('alerting.email_password', '')
                
                if username and password:
                    server.login(username, password)
                    self.logger.debug("Email authentication successful")
                else:
                    self.logger.warning("No email credentials provided, sending without auth")
                
                server.send_message(msg)
            
            self.logger.info(f"Email alert sent to {', '.join(self.to_emails)}: {alert.title}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {str(e)}")
            return False
    
    def send_webhook(self, alert: Alert) -> bool:
        """
        Send alert via webhook (Slack, Teams, etc.)
        
        Args:
            alert: Alert to send
        
        Returns:
            True if successful, False otherwise
        """
        if not self.webhook_enabled or not self.webhook_url:
            return False
        
        if not self._check_rate_limit('webhook'):
            self.logger.warning("Webhook rate limit hit, skipping")
            return False
        
        try:
            # Detect webhook type
            if 'slack.com' in self.webhook_url:
                payload = alert.to_slack_payload()
            else:
                # Generic webhook
                payload = {
                    'alert': alert.to_dict(),
                    'timestamp': datetime.now().isoformat()
                }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code in [200, 201, 204]:
                self.logger.info(f"Webhook alert sent: {alert.title}")
                return True
            else:
                self.logger.warning(f"Webhook returned {response.status_code}: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to send webhook alert: {str(e)}")
            return False
    
    def log_alert(self, alert: Alert):
        """Log alert to standard logging"""
        if self.log_alerts:
            log_message = f"ALERT [{alert.severity.name}] {alert.title} - Risk: {alert.risk_score:.1f} - Source: {alert.source_url}"
            
            if alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
                logger.error(log_message)
            elif alert.severity == AlertSeverity.MEDIUM:
                logger.warning(log_message)
            else:
                logger.info(log_message)
    
    def send_alert(self, alert: Alert, channels: List[AlertChannel] = None) -> Dict[str, bool]:
        """
        Send alert through specified channels
        
        Args:
            alert: Alert to send
            channels: List of channels to use (None = all enabled)
        
        Returns:
            Dictionary of channel -> success status
        """
        if channels is None:
            channels = [AlertChannel.LOG]
            if self.email_enabled:
                channels.append(AlertChannel.EMAIL)
            if self.webhook_enabled:
                channels.append(AlertChannel.WEBHOOK)
        
        results = {}
        
        for channel in channels:
            if channel == AlertChannel.EMAIL:
                results['email'] = self.send_email(alert)
            elif channel == AlertChannel.WEBHOOK:
                results['webhook'] = self.send_webhook(alert)
            elif channel == AlertChannel.LOG:
                self.log_alert(alert)
                results['log'] = True
        
        return results


class AlertGenerator:
    """
    Main alert generation orchestrator
    """
    
    def __init__(self, storage_service: DataStorageService):
        """
        Initialize alert generator
        
        Args:
            storage_service: Data storage service for saving alerts
        """
        self.storage = storage_service
        self.channel_manager = AlertChannelManager()
        self.deduplicator = AlertDeduplicator()
        self.escalation = EscalationPolicy()
        self.logger = logging.getLogger(__name__)
        
        # Alert thresholds
        self.thresholds = {
            'credential_leak': 70,
            'proprietary_data': 60,
            'domain_match': 50,
            'sensitive_data': 65
        }
    
    def generate_alert_from_detection(self, detection_result: Dict[str, Any], 
                                      source_url: str, marketplace_indicators: bool = False) -> Optional[Alert]:
        """
        Generate alert from keyword detection results
        
        Args:
            detection_result: Keyword detection result dictionary
            source_url: Source URL of the content
        
        Returns:
            Alert object or None if below threshold
        """
        risk_score = detection_result.get('overall_risk_score', 0)
        severity = AlertSeverity.from_risk_score(risk_score)
        
        # Check if meets minimum threshold
        if risk_score < 30:
            return None
        
        # Determine alert type
        alert_type = self._determine_alert_type(detection_result, marketplace_indicators)
        
        # Extract matched keywords
        matched_keywords = []
        for match in detection_result.get('high_confidence_matches', [])[:10]:
            matched_keywords.append(match.get('keyword', ''))
        
        # Extract affected assets
        affected_assets = self._extract_affected_assets(detection_result)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(alert_type, severity)
        
        # Create alert
        alert = Alert(
            id=None,
            title=self._generate_title(alert_type, severity, risk_score),
            description=self._generate_description(detection_result, source_url),
            severity=severity,
            alert_type=alert_type,
            source_url=source_url,
            risk_score=risk_score,
            matched_keywords=matched_keywords,
            affected_assets=affected_assets,
            recommendations=recommendations,
            created_at=datetime.now(),
            status=AlertStatus.NEW,
            escalation_level=0
        )
        
        # Check for duplicates
        if self.deduplicator.is_duplicate(alert):
            self.logger.info(f"Duplicate alert suppressed: {alert.title}")
            return None
        
        return alert
    
    def generate_alert_from_nlp(self, nlp_result: Dict, 
                           source_url: str) -> Optional[Alert]:
        """
        Generate alert from NLP analysis results
        """
        threat_score = nlp_result.get('threat_score', 0)
        
        # ============================================================
        # FIXED: Use intent classification instead of sentiment
        # ============================================================
        intent_data = nlp_result.get('intent', {})
        intent = intent_data.get('intent', '')
        intent_confidence = intent_data.get('confidence', 0)
        
        # Boost threat score based on high-risk intent
        high_risk_intents = ['credential_dump', 'data_breach_announcement', 'proprietary_data_sale']
        medium_risk_intents = ['ransomware_threat', 'marketplace_listing']
        
        if intent in high_risk_intents:
            # Significant boost for high-risk intent
            boost = 25 * intent_confidence
            threat_score = min(100, threat_score + boost)
            self.logger.info(f"Intent boost: {intent} (+{boost:.0f})")
        elif intent in medium_risk_intents:
            # Moderate boost for medium-risk intent
            boost = 15 * intent_confidence
            threat_score = min(100, threat_score + boost)
            self.logger.info(f"Intent boost: {intent} (+{boost:.0f})")
        
        # Also check for threat keywords in NLP result
        threat_keywords = nlp_result.get('threat_keywords', [])
        if threat_keywords:
            # Small boost for having threat keywords
            threat_score = min(100, threat_score + 5)
        
        severity = AlertSeverity.from_risk_score(threat_score)
        
        # Lower threshold for NLP alerts (catch more threats)
        if threat_score < 25:  # Reduced from 30
            return None
        
        # Extract key phrases as keywords
        key_phrases = nlp_result.get('key_phrases', [])[:5]
        
        # Extract entities as affected assets
        affected_assets = []
        for entity in nlp_result.get('named_entities', [])[:5]:
            if entity.get('label') in ['ORG', 'PERSON', 'PRODUCT', 'CROP']:
                affected_assets.append(entity.get('text', ''))
        
        # Generate recommendations based on intent
        if intent in high_risk_intents:
            recommendations = [
                "Immediate investigation required",
                "Verify if credentials are valid",
                "Check for unauthorized access",
                "Reset affected credentials"
            ]
        else:
            recommendations = self._generate_recommendations('nlp_threat', severity)
        
        alert = Alert(
            id=None,
            title=f"NLP Detection: {intent.replace('_', ' ').title() if intent else 'Suspicious Content'}",
            description=f"NLP analysis detected {intent.replace('_', ' ')} with {intent_confidence:.0%} confidence. "
                    f"Threat score: {threat_score:.0f}. Key concerns: {', '.join(key_phrases[:3])}",
            severity=severity,
            alert_type='nlp_threat',
            source_url=source_url,
            risk_score=threat_score,
            matched_keywords=key_phrases,
            affected_assets=affected_assets,
            recommendations=recommendations,
            created_at=datetime.now(),
            status=AlertStatus.NEW,
            escalation_level=0
        )
        
        if self.deduplicator.is_duplicate(alert):
            return None
        
        return alert
    
    def _determine_alert_type(self, detection_result: Dict, marketplace_indicators: bool = False) -> str:
        matches_by_category = detection_result.get('matches_by_category', {})
        
        # Get matched keywords
        matched_keywords = []
        for match in detection_result.get('high_confidence_matches', []):
            matched_keywords.append(match.get('keyword', '').lower())
        keyword_text = ' '.join(matched_keywords).lower()
        
        # 1. Ransomware (HIGHEST PRIORITY)
        if any(kw in keyword_text for kw in ['ransom', 'encrypted', 'decryption', 'pay btc', 'bitcoin']):
            return 'ransomware_threat'
        
        # 2. Data Breach
        if any(kw in keyword_text for kw in ['breach', 'hacked', 'compromised', 'stolen', 'breach alert']):
            return 'data_breach_announcement'
        
        # 3. Credential Leak
        if matches_by_category.get('credential', 0) > 0:
            return 'credential_leak'
        
        # 4. Marketplace Listing
        marketplace_keywords = ['for sale', 'selling', 'price:', 'btc', 'bitcoin', 'access to']
        if marketplace_indicators or any(kw in keyword_text for kw in marketplace_keywords):
            return 'marketplace_listing'
        
        # 5. Proprietary Data
        if matches_by_category.get('proprietary', 0) > 0:
            return 'proprietary_data_exposure'
        
        # 6. Agriculture Research
        if any(kw in keyword_text for kw in ['research', 'paper', 'study', 'journal']):
            return 'agriculture_research'
        
        # 7. Technical Discussion (Default)
        return 'technical_discussion'
   
    def _extract_affected_assets(self, detection_result: Dict) -> List[str]:
        """Extract affected assets from detection results"""
        assets = []
        
        # Check for domain matches
        for match in detection_result.get('high_confidence_matches', []):
            if match.get('category') == 'domain':
                assets.append(f"Domain: {match.get('keyword')}")
            elif match.get('category') == 'proprietary':
                assets.append(f"Proprietary Asset: {match.get('keyword')}")
        
        return list(set(assets))[:5]
    
    def _generate_title(self, alert_type: str, severity: AlertSeverity, risk_score: float) -> str:
        """Generate alert title"""
        titles = {
            'credential_leak': "Credentials Leaked on Dark Web",
            'data_breach_announcement': "Data Breach Announcement Detected",
            'ransomware_threat': "Ransomware Threat Detected",
            'proprietary_data_exposure': "Proprietary Agriculture Data Exposed",
            'marketplace_listing': "Dark Web Marketplace for Agricultural Leaks",
            'agriculture_data_exposure': "Agricultural Data Found on Dark Web",
            'agriculture_research': "Agriculture Research Document (Low Risk)",
            'domain_monitoring_match': "Monitored Domain References Found",
            'sensitive_data_exposure': "Sensitive Data Exposure Detected",
            'technical_discussion': "Technical Discussion (No Threat)",
            'general_threat': "Security Threat Detected"
        }
        
        title = titles.get(alert_type, "Security Alert")
        
        # Add risk indicator based on severity
        if severity == AlertSeverity.CRITICAL:
            return f"[CRITICAL] {title} (Urgent Action Required)"
        elif severity == AlertSeverity.HIGH:
            return f"[HIGH] {title} (Immediate Review Needed)"
        elif severity == AlertSeverity.MEDIUM:
            return f"[MEDIUM] {title} (Monitor)"
        elif severity == AlertSeverity.LOW:
            return f"[LOW] {title} (Informational)"
        else:
            return f"[INFO] {title}"
        
    def _generate_description(self, detection_result: Dict, source_url: str) -> str:
        """Generate detailed alert description"""
        matches_by_category = detection_result.get('matches_by_category', {})
        total_matches = detection_result.get('total_matches', 0)
        high_confidence = len(detection_result.get('high_confidence_matches', []))
        
        description = f"Dark web monitoring detected potential security threat at {source_url}\n\n"
        description += f"Summary:\n"
        description += f"- Total matches: {total_matches}\n"
        description += f"- High confidence matches: {high_confidence}\n"
        
        if matches_by_category:
            description += f"- Categories: {', '.join([f'{k}:{v}' for k, v in matches_by_category.items()])}\n"
        
        # Add sample matches
        sample_matches = detection_result.get('high_confidence_matches', [])[:3]
        if sample_matches:
            description += f"\nSample matches:\n"
            for match in sample_matches:
                description += f"  * {match.get('keyword')} ({match.get('category')}) - Confidence: {match.get('confidence', 0):.0%}\n"
        
        return description
    
    def _generate_recommendations(self, alert_type: str, severity: AlertSeverity) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []
        
        if alert_type == 'credential_leak':
            recommendations.append("Immediately rotate all affected credentials")
            recommendations.append("Enable multi-factor authentication for affected accounts")
            recommendations.append("Review access logs for suspicious activity")
        
        if alert_type == 'proprietary_data_exposure':
            recommendations.append("Identify scope of proprietary data exposure")
            recommendations.append("Review data access controls and permissions")
            recommendations.append("Consider legal notification requirements")
        
        if alert_type == 'agriculture_data_exposure':  # NEW
            recommendations.append("Verify if agricultural data is legitimate or test data")
            recommendations.append("Identify which farm/assets are affected")
            recommendations.append("Review data sharing agreements with partners")
            recommendations.append("Consider impact on crop yield predictions")
        
        if alert_type == 'domain_monitoring_match':
            recommendations.append("Verify if the domain reference is legitimate")
            recommendations.append("Check for typosquatting or impersonation")
            recommendations.append("Consider brand protection measures")
        
        if severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
            recommendations.insert(0, "Immediate investigation required")
            recommendations.append("Escalate to security leadership")
            recommendations.append("Document incident for compliance")
        
        if severity == AlertSeverity.CRITICAL:
            recommendations.append("Consider activating incident response plan")
            recommendations.append("Notify affected stakeholders")
        
        return recommendations
    
    def process_and_send_alert(self, detection_result: Dict, 
                           nlp_result: Dict,
                           source_url: str,
                           page_id: int = None,
                           marketplace_indicators: bool = False) -> Optional[int]:
        # Generate alerts from both sources
        alert1 = self.generate_alert_from_detection(detection_result, source_url, marketplace_indicators)
        alert2 = self.generate_alert_from_nlp(nlp_result, source_url)
        
        # ============================================================
        # FIXED: Combine both alerts into one with merged risk score
        # ============================================================
        
        if not alert1 and not alert2:
            return None
        
        # If only one alert exists, use it
        if alert1 and not alert2:
            alert = alert1
        elif alert2 and not alert1:
            alert = alert2
        else:
            # Both alerts exist - merge them
            # Take the higher risk score from either source
            combined_risk = max(alert1.risk_score, alert2.risk_score)
            
            # Combine matched keywords (deduplicate)
            combined_keywords = list(set(alert1.matched_keywords + alert2.matched_keywords))
            
            # Combine affected assets
            combined_assets = list(set(alert1.affected_assets + alert2.affected_assets))
            
            # Use the more severe alert type
            severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
            if severity_order[alert1.severity.name] >= severity_order[alert2.severity.name]:
                base_alert = alert1
            else:
                base_alert = alert2
            
            # Create merged alert
            alert = Alert(
                id=None,
                title=base_alert.title,
                description=f"Combined detection from keyword analysis (risk: {alert1.risk_score:.0f}) and NLP analysis (risk: {alert2.risk_score:.0f}).\n\n{base_alert.description}",
                severity=base_alert.severity,
                alert_type=base_alert.alert_type,
                source_url=source_url,
                risk_score=combined_risk,  # Use the higher score
                matched_keywords=combined_keywords[:10],
                affected_assets=combined_assets[:5],
                recommendations=base_alert.recommendations,
                created_at=datetime.now(),
                status=AlertStatus.NEW,
                escalation_level=0
            )
        
        if not alert:
            return None
        
        # Save to database
        alert_data = {
            'page_id': page_id,
            'alert_level': alert.severity.name,
            'alert_type': alert.alert_type,
            'title': alert.title,
            'description': alert.description[:500],
            'risk_score': alert.risk_score
        }
        
        alert_id = self.storage.save_alert(alert_data)
        alert.id = alert_id
        
        # Send through channels
        channels = [AlertChannel.LOG]
        if alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
            channels.extend([AlertChannel.EMAIL, AlertChannel.WEBHOOK])
        elif alert.severity == AlertSeverity.MEDIUM:
            channels.append(AlertChannel.EMAIL)
        
        self.channel_manager.send_alert(alert, channels)
        
        self.logger.info(f"Alert generated and sent (ID: {alert_id}, Severity: {alert.severity.name}, Risk: {alert.risk_score:.0f})")
        return alert_id

class AlertEscalationService:
    """
    Background service for handling alert escalations
    """
    
    def __init__(self, storage_service: DataStorageService):
        self.storage = storage_service
        self.escalation = EscalationPolicy()
        self.channel_manager = AlertChannelManager()
        self.logger = logging.getLogger(__name__)
    
    def check_and_escalate(self):
        """
        Check for alerts that need escalation and process them
        """
        # Get unacknowledged alerts
        unacknowledged = self.storage.get_unacknowledged_alerts(limit=50)
        
        for alert_data in unacknowledged:
            # Convert to Alert object
            alert = self._dict_to_alert(alert_data)
            
            if not alert:
                continue
            
            # Check if escalation needed
            time_since = datetime.now() - alert.created_at
            
            if self.escalation.should_escalate(alert, time_since):
                # Get escalation target
                target = self.escalation.get_next_escalation_target(alert)
                
                if target:
                    # Send escalation alert
                    escalation_alert = self._create_escalation_alert(alert, target)
                    self.channel_manager.send_alert(escalation_alert, [AlertChannel.EMAIL, AlertChannel.WEBHOOK])
                    
                    # Update alert in database
                    alert.escalation_level += 1
                    alert.status = AlertStatus.ESCALATED
                    
                    self.logger.info(f"Alert {alert.id} escalated to {target} (Level {alert.escalation_level})")
    
    def _dict_to_alert(self, alert_dict: Dict) -> Optional[Alert]:
        """Convert dictionary to Alert object"""
        try:
            return Alert(
                id=alert_dict.get('id'),
                title=alert_dict.get('title', ''),
                description=alert_dict.get('description', ''),
                severity=AlertSeverity[alert_dict.get('alert_level', 'INFO')],
                alert_type=alert_dict.get('alert_type', 'general'),
                source_url=alert_dict.get('page_url', ''),
                risk_score=alert_dict.get('risk_score', 0),
                matched_keywords=[],
                affected_assets=[],
                recommendations=[],
                created_at=datetime.fromisoformat(alert_dict.get('generated_at', datetime.now().isoformat())),
                status=AlertStatus.NEW,
                escalation_level=0
            )
        except Exception as e:
            self.logger.error(f"Failed to convert alert dict: {str(e)}")
            return None
    
    def _create_escalation_alert(self, original_alert: Alert, target: str) -> Alert:
        """Create escalation notification alert"""
        return Alert(
            id=None,
            title=f"ESCALATION: {original_alert.title}",
            description=f"Alert has been escalated to {target} as it has not been acknowledged within the required timeframe.\n\n"
                       f"Original Alert:\n{original_alert.description}",
            severity=original_alert.severity,
            alert_type='escalation',
            source_url=original_alert.source_url,
            risk_score=original_alert.risk_score,
            matched_keywords=original_alert.matched_keywords,
            affected_assets=original_alert.affected_assets,
            recommendations=original_alert.recommendations + ["Acknowledge this alert to stop further escalation"],
            created_at=datetime.now(),
            status=AlertStatus.NEW,
            escalation_level=original_alert.escalation_level + 1
        )


# ============================================================================
# Standalone Test
# ============================================================================

def test_alert_module():
    """Test the alert generation module"""
    print("\n" + "="*60)
    print("TESTING ALERT GENERATION MODULE")
    print("="*60)
    
    from storage.database import DatabaseManager
    
    # Initialize storage
    print("\n[1] Initializing storage...")
    db_manager = DatabaseManager('sqlite:///test_alerts.db')
    storage = DataStorageService(db_manager)
    
    # Initialize alert generator
    print("[2] Initializing alert generator...")
    alert_gen = AlertGenerator(storage)
    
    # Test detection result
    print("\n[3] Testing alert from detection results...")
    detection_result = {
        'overall_risk_score': 85.5,
        'total_matches': 12,
        'matches_by_category': {'credential': 3, 'proprietary': 2},
        'high_confidence_matches': [
            {'keyword': 'password', 'category': 'credential', 'confidence': 0.95},
            {'keyword': 'YieldPredict v2', 'category': 'proprietary', 'confidence': 0.92},
            {'keyword': 'admin@agrifarm.com', 'category': 'email', 'confidence': 0.98}
        ]
    }
    
    alert = alert_gen.generate_alert_from_detection(detection_result, "http://test.onion/breach")
    
    if alert:
        print(f"   Alert created: {alert.title}")
        print(f"   Severity: {alert.severity.name}")
        print(f"   Risk Score: {alert.risk_score:.1f}")
        print(f"   Matched Keywords: {', '.join(alert.matched_keywords[:3])}")
        print(f"   Recommendations: {alert.recommendations[:2]}")
    
    # Test NLP result
    print("\n[4] Testing alert from NLP results...")
    nlp_result = {
        'threat_score': 78.0,
        'sentiment_label': 'negative',
        'key_phrases': ['data breach', 'agrifarm', 'credentials leaked'],
        'named_entities': [
            {'text': 'AgriFarm', 'label': 'ORG'},
            {'text': 'DarkHarvester', 'label': 'PERSON'}
        ]
    }
    
    alert2 = alert_gen.generate_alert_from_nlp(nlp_result, "http://test.onion/analysis")
    
    if alert2:
        print(f"   Alert created: {alert2.title}")
        print(f"   Severity: {alert2.severity.name}")
        print(f"   Risk Score: {alert2.risk_score:.1f}")
    
    # Test email formatting
    print("\n[5] Testing email formatting...")
    if alert:
        email_html = alert.to_email_html()
        print(f"   Email HTML length: {len(email_html)} chars")
        print(f"   Preview: {email_html[:200]}...")
    
    # Test Slack formatting
    print("\n[6] Testing Slack formatting...")
    if alert:
        slack_payload = alert.to_slack_payload()
        print(f"   Slack payload: {json.dumps(slack_payload, indent=2)[:300]}...")
    
    # Test deduplication
    print("\n[7] Testing deduplication...")
    alert3 = alert_gen.generate_alert_from_detection(detection_result, "http://test.onion/breach")
    if alert3 is None:
        print("    Duplicate alert correctly suppressed")
    else:
        print("    Duplicate alert not suppressed")
    
    # Test escalation
    print("\n[8] Testing escalation policy...")
    escalation_service = AlertEscalationService(storage)
    print(f"   Escalation service initialized")
    
    print("\n" + "="*60)
    print("ALERT MODULE TEST COMPLETE")
    print("="*60)
    
    return True


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    test_alert_module()