#!/usr/bin/env python3
"""
Dark Web Agriculture Asset Monitor - Main Entry Point with Alerts
"""

from config.settings import config_manager
from tor_network.tor_manager import TorManager
from crawler.web_crawler import DarkWebCrawler
from preprocessor.data_cleaner import DocumentProcessor
from detector.keyword_detector import KeywordDetector
from nlp_analysis.analyzer import NLPAnalyzer
from storage.database import DatabaseManager, DataStorageService
from alerts.alert_manager import AlertGenerator, AlertEscalationService
import logging
import sys
import json
import hashlib
from datetime import datetime
import threading
import time

def escalation_monitor(storage, interval_seconds=300):
    """Background thread for escalation monitoring"""
    escalation_service = AlertEscalationService(storage)
    while True:
        try:
            escalation_service.check_and_escalate()
            time.sleep(interval_seconds)
        except Exception as e:
            logging.error(f"Escalation monitor error: {str(e)}")


def train_models_periodically(storage, interval_hours=24):
    """Background thread to retrain ML models"""
    from detector.ml_classifier import KeywordMLClassifier
    
    classifier = KeywordMLClassifier(storage, min_samples=10)
    classifier.initialize()
    
    while True:
        try:
            classifier.train_all_keywords()
            time.sleep(interval_hours * 3600)
        except Exception as e:
            logging.error(f"Model training error: {e}")
            time.sleep(3600)  # Retry after 1 hour

def main():
    """Main application entry point"""
    print("=" * 60)
    print("DARK WEB AGRICULTURE ASSET MONITOR")
    print("=" * 60)
    print(f"Version: {config_manager.get('app.version')}")
    print("=" * 60)
    
    # Validate configuration
    if not config_manager.validate_config():
        print(" Configuration validation failed.")
        return
    
    print(" Configuration loaded")
    
    # Initialize Database
    print("\n Initializing database...")
    db_manager = DatabaseManager()
    storage = DataStorageService(db_manager)
    print(" Database ready")
    
    # Start escalation monitor thread
    print(" Starting escalation monitor...")
    escalation_thread = threading.Thread(
        target=escalation_monitor,
        args=(storage,),
        daemon=True
    )
    escalation_thread.start()
    print(" Escalation monitor running")
    
    # Initialize components
    print("\n Initializing components...")
    tor_manager = TorManager()
    crawler = DarkWebCrawler(tor_manager)
    processor = DocumentProcessor()
    detector = KeywordDetector(storage_service=storage)
    nlp_analyzer = NLPAnalyzer()
    alert_generator = AlertGenerator(storage)
    
    # Setup Tor
    if not tor_manager.setup_tor_connection():
        print(" Tor connection failed!")
        sys.exit(1)
    
    print(" Tor connected")
    
    # Start scan session
    scan_id = storage.start_scan({
        'target_sites': config_manager.get('monitoring.target_sites', []),
        'max_depth': config_manager.get('crawler.max_depth')
    })
    print(f" Scan session started (ID: {scan_id})")
    
    # Get target sites
    target_sites = config_manager.get('monitoring.target_sites', [])
    
    # Run crawl
    print(f"\n Crawling {len(target_sites)} sites...")
    pages = crawler.start_crawl(target_sites)
    print(f" Crawled {len(pages)} pages")
    
    # Process, detect, analyze, alert, and store
    print("\n Analyzing content and generating alerts...")
    alerts_generated = 0
    
    for i, page in enumerate(pages, 1):
        print(f"\n   [{i}/{len(pages)}] Processing: {page.url[:60]}...")
        
        # Save crawled page
        page_id = storage.save_crawled_page({
            'url': page.url,
            'title': page.title,
            'content_hash': hashlib.sha256(page.content.encode()).hexdigest(),
            'crawl_depth': page.crawl_depth,
            'status_code': page.status_code,
            'content_type': page.content_type,
            'content_length': page.content_length,
            'crawled_at': page.crawled_at,
            'found_at_url': page.found_at
        })
        
        # Preprocess
        processed = processor.process_document(
            raw_text=page.content,
            source_url=page.url,
            original_metadata={'title': page.title}
        )
        
        # Save processed content (abbreviated for demo)
        storage.save_processed_content(page_id, {
            'cleaned_text': processed.cleaned_text[:1000],
            'cleaned_length': processed.cleaned_length,
            'word_count': processed.word_count,
            'unique_word_count': processed.unique_word_count,
            'avg_word_length': processed.avg_word_length,
            'special_char_ratio': processed.special_char_ratio,
            'detected_language': processed.detected_language,
            'entities': []
        })
        
        # Keyword detection
        keyword_result = detector.detect_matches(processed)
        
        # Save keyword matches (abbreviated)
        matches_data = []
        for match in keyword_result.high_confidence_matches[:5] + keyword_result.medium_confidence_matches[:5]:
            matches_data.append({
                'keyword': match.keyword,
                'matched_text': match.matched_text[:100],
                'match_type': match.match_type,
                'confidence': match.confidence,
                'category': match.category,
                'context': match.context[:200],
                'position': match.position
            })
        storage.save_keyword_matches(page_id, matches_data)
        
        # NLP Analysis
        nlp_result = nlp_analyzer.analyze_document(processed, keyword_result.high_confidence_matches)
        
        # Save NLP results (abbreviated)
        storage.save_nlp_results(page_id, {
            'threat_score': nlp_result.threat_score,
            'threat_level': 'HIGH' if nlp_result.threat_score >= 70 else 'MEDIUM' if nlp_result.threat_score >= 40 else 'LOW',
            'readability_score': nlp_result.readability_score,
            'summary': nlp_result.summary[:500],
            'key_phrases': nlp_result.key_phrases[:5],
            'threat_keywords': nlp_result.threat_keywords[:5],
            'named_entities': [],
            'relationships': []
        })
        
        marketplace_indicators = getattr(keyword_result, 'marketplace_indicators', False)

        # Generate and send alerts
        alert_id = alert_generator.process_and_send_alert(
            detection_result=keyword_result.to_dict(),
            nlp_result=nlp_result.to_dict(),
            source_url=page.url,
            page_id = page_id,
            marketplace_indicators = marketplace_indicators
        )
        
        if alert_id:
            alerts_generated += 1
            print(f"    ALERT GENERATED (ID: {alert_id})")
            
            # Show critical details
            if keyword_result.overall_risk_score >= 85:
                print(f"    CRITICAL: {keyword_result.overall_risk_score:.0f}% risk")
                for match in keyword_result.high_confidence_matches[:2]:
                    print(f"      - {match.category}: {match.keyword}")
    
    # End scan session
    storage.end_scan(scan_id, {
        'pages_crawled': len(pages),
        'pages_failed': len(crawler.failed_urls),
        'alerts_generated': alerts_generated
    })
    
    # Display final statistics
    print("\n" + "="*60)
    print("MONITORING COMPLETE")
    print("="*60)
    
    db_stats = db_manager.get_statistics()
    print(f"\n Database Statistics:")
    print(f"   • Total pages crawled: {db_stats['total_pages']}")
    print(f"   • Total alerts: {db_stats['total_alerts']}")
    print(f"   • Unacknowledged alerts: {db_stats['unacknowledged_alerts']}")
    print(f"   • Critical alerts: {db_stats['critical_alerts']}")
    
    # Show unacknowledged alerts
    unacknowledged = storage.get_unacknowledged_alerts(5)
    if unacknowledged:
        print(f"\n  PENDING ALERTS (Require acknowledgment):")
        for alert in unacknowledged:
            print(f"   • [{alert['alert_level']}] {alert['title'][:60]}")
            print(f"     Risk: {alert['risk_score']:.0f} | ID: {alert['id']}")
    
    # Show alert configuration
    print(f"\n Alert Channels:")
    if config_manager.get('alerting.email_enabled'):
        print(f"   • Email: Enabled ({config_manager.get('alerting.smtp_server')})")
    else:
        print(f"   • Email: Disabled")
    
    if config_manager.get('alerting.webhook_enabled'):
        print(f"   • Webhook: Enabled")
    else:
        print(f"   • Webhook: Disabled")
    
    print(f"   • Logging: Enabled")
    
    # Cleanup
    tor_manager.close_connection()
    print("\n Monitoring session complete!")
    print(f" All data saved to database")
    print(f" {alerts_generated} alerts generated")

if __name__ == "__main__":
    main()