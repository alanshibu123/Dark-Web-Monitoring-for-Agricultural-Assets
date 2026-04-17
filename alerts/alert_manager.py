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
        """Convert risk score to severity"""
        if risk_score >= 85:
            return cls.CRITICAL
        elif risk_score >= 70:
            return cls.HIGH
        elif risk_score >= 50:
            return cls.MEDIUM
        elif risk_score >= 30:
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
        """Generate HTML email content"""
        severity_colors = {
            AlertSeverity.CRITICAL: '#dc3545',
            AlertSeverity.HIGH: '#fd7e14',
            AlertSeverity.MEDIUM: '#ffc107',
            AlertSeverity.LOW: '#17a2b8',
            AlertSeverity.INFO: '#6c757d'
        }
        
        color = severity_colors.get(self.severity, '#6c757d')
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .alert {{ border-left: 4px solid {color}; padding: 15px; margin: 20px 0; background: #f8f9fa; }}
                .severity-{self.severity.name.lower()} {{ color: {color}; font-weight: bold; }}
                .section {{ margin: 15px 0; }}
                .keyword {{ background: #e9ecef; padding: 3px 8px; border-radius: 3px; margin: 2px; display: inline-block; }}
                .recommendation {{ color: #28a745; }}
            </style>
        </head>
        <body>
            <div class="alert">
                <h2 class="severity-{self.severity.name.lower()}">[{self.severity.name}] {self.title}</h2>
                <p><strong>Time:</strong> {self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <p><strong>Source:</strong> <a href="{self.source_url}">{self.source_url}</a></p>
                <p><strong>Risk Score:</strong> {self.risk_score:.1f}/100</p>
                
                <div class="section">
                    <strong>Description:</strong>
                    <p>{self.description}</p>
                </div>
                
                <div class="section">
                    <strong>Matched Keywords:</strong>
                    {''.join(f'<span class="keyword">{kw}</span>' for kw in self.matched_keywords[:10])}
                </div>
                
                <div class="section">
                    <strong>Affected Assets:</strong>
                    <ul>
                        {''.join(f'<li>{asset}</li>' for asset in self.affected_assets[:5])}
                    </ul>
                </div>
                
                <div class="section">
                    <strong>Recommendations:</strong>
                    <ul>
                        {''.join(f'<li class="recommendation">{rec}</li>' for rec in self.recommendations)}
                    </ul>
                </div>
                
                <hr>
                <p><small>Dark Web Agriculture Monitor - Automated Alert System</small></p>
            </div>
        </body>
        </html>
        """
        return html
    
    def to_slack_payload(self) -> Dict:
        """Generate Slack webhook payload"""
        color_map = {
            AlertSeverity.CRITICAL: 'danger',
            AlertSeverity.HIGH: 'warning',
            AlertSeverity.MEDIUM: 'good',
            AlertSeverity.LOW: '#17a2b8',
            AlertSeverity.INFO: '#6c757d'
        }
        
        return {
            'attachments': [{
                'color': color_map.get(self.severity, '#6c757d'),
                'title': f'[{self.severity.name}] {self.title}',
                'title_link': self.source_url,
                'fields': [
                    {'title': 'Risk Score', 'value': f'{self.risk_score:.1f}/100', 'short': True},
                    {'title': 'Type', 'value': self.alert_type, 'short': True},
                    {'title': 'Matched Keywords', 'value': ', '.join(self.matched_keywords[:5]), 'short': False},
                    {'title': 'Recommendations', 'value': '\n'.join(self.recommendations[:3]), 'short': False}
                ],
                'footer': 'Dark Web Agriculture Monitor',
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
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                # If authentication needed, add credentials here
                # server.login(username, password)
                server.send_message(msg)
            
            self.logger.info(f"Email alert sent: {alert.title}")
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
                                      source_url: str) -> Optional[Alert]:
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
        alert_type = self._determine_alert_type(detection_result)
        
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
    
    def generate_alert_from_nlp(self, nlp_result: Dict[str, Any], 
                               source_url: str) -> Optional[Alert]:
        """
        Generate alert from NLP analysis results
        
        Args:
            nlp_result: NLP analysis result dictionary
            source_url: Source URL of the content
        
        Returns:
            Alert object or None if below threshold
        """
        threat_score = nlp_result.get('threat_score', 0)
        sentiment_label = nlp_result.get('sentiment_label', 'neutral')
        
        # Boost score for negative sentiment
        if sentiment_label == 'negative':
            threat_score = min(100, threat_score + 10)
        
        severity = AlertSeverity.from_risk_score(threat_score)
        
        if threat_score < 30:
            return None
        
        # Extract key phrases as keywords
        key_phrases = nlp_result.get('key_phrases', [])[:5]
        
        # Extract entities as affected assets
        affected_assets = []
        for entity in nlp_result.get('named_entities', [])[:5]:
            if entity.get('label') in ['ORG', 'PERSON', 'PRODUCT']:
                affected_assets.append(entity.get('text', ''))
        
        # Generate recommendations
        recommendations = self._generate_recommendations('nlp_threat', severity)
        
        alert = Alert(
            id=None,
            title=f"NLP Threat Detection: {key_phrases[0] if key_phrases else 'Suspicious Content'}",
            description=f"NLP analysis detected threatening content with {threat_score:.0f}% threat score. "
                       f"Sentiment: {sentiment_label}. Key concerns: {', '.join(key_phrases[:3])}",
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
    
    def _determine_alert_type(self, detection_result: Dict) -> str:
        """Determine alert type based on detection results"""
        matches_by_category = detection_result.get('matches_by_category', {})
        
        if matches_by_category.get('credential', 0) > 0:
            return 'credential_leak'
        elif matches_by_category.get('proprietary', 0) > 0:
            return 'proprietary_data_exposure'
        elif matches_by_category.get('domain', 0) > 0:
            return 'domain_monitoring_match'
        elif matches_by_category.get('sensitive', 0) > 0:
            return 'sensitive_data_exposure'
        else:
            return 'general_threat'
    
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
            'credential_leak': f"Credentials Leaked on Dark Web",
            'proprietary_data_exposure': f"Proprietary Agriculture Data Exposed",
            'domain_monitoring_match': f"Monitored Domain References Found",
            'sensitive_data_exposure': f"Sensitive Data Exposure Detected",
            'nlp_threat': f"Threatening Content Detected",
            'general_threat': f"Security Threat Detected"
        }
        
        title = titles.get(alert_type, "Security Alert")
        return f"[{severity.name}] {title} (Risk: {risk_score:.0f}%)"
    
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
                               source_url: str) -> Optional[int]:
        """
        Complete alert processing pipeline
        
        Args:
            detection_result: Keyword detection results
            nlp_result: NLP analysis results
            source_url: Source URL
        
        Returns:
            Alert ID if created, None otherwise
        """
        # Generate alerts from both sources
        alert1 = self.generate_alert_from_detection(detection_result, source_url)
        alert2 = self.generate_alert_from_nlp(nlp_result, source_url)
        
        # Use the more severe alert
        alert = None
        if alert1 and alert2:
            alert = alert1 if alert1.risk_score >= alert2.risk_score else alert2
        elif alert1:
            alert = alert1
        elif alert2:
            alert = alert2
        
        if not alert:
            return None
        
        # Save to database
        alert_data = {
            'page_id': None,  # Would need page_id mapping
            'alert_level': alert.severity.name,
            'alert_type': alert.alert_type,
            'title': alert.title,
            'description': alert.description,
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
        
        self.logger.info(f"Alert generated and sent (ID: {alert_id}, Severity: {alert.severity.name})")
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