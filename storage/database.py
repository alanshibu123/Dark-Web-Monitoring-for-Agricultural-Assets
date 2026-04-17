"""
Data Storage Module for Dark Web Agriculture Monitor
Handles database connections, ORM models, and data persistence
"""

import os
import sys
import json
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Tuple
from contextlib import contextmanager
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text, Boolean, ForeignKey, Index, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.pool import QueuePool
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
import logging
from typing import Generator

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import config_manager

# Create base class for ORM models
Base = declarative_base()

# Setup logging
logger = logging.getLogger(__name__)


# ============================================================================
# SQLAlchemy ORM Models
# ============================================================================

class CrawledPageModel(Base):
    """Model for crawled pages"""
    __tablename__ = 'crawled_pages'
    
    id = Column(Integer, primary_key=True)
    url = Column(String(500), nullable=False, unique=True)
    title = Column(String(500))
    content_hash = Column(String(64), nullable=False, index=True)
    crawl_depth = Column(Integer, default=0)
    status_code = Column(Integer)
    content_type = Column(String(100))
    content_length = Column(Integer)
    crawled_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    found_at_url = Column(String(500))
    
    # Relationships
    processed_contents = relationship("ProcessedContentModel", back_populates="page", cascade="all, delete-orphan")
    keyword_matches = relationship("KeywordMatchModel", back_populates="page", cascade="all, delete-orphan")
    nlp_results = relationship("NLPResultModel", back_populates="page", cascade="all, delete-orphan")
    alerts = relationship("AlertModel", back_populates="page")
    
    # Indexes
    __table_args__ = (
        Index('idx_crawled_at_url', 'crawled_at', 'url'),
        Index('idx_content_hash', 'content_hash'),
    )


class ProcessedContentModel(Base):
    """Model for preprocessed content"""
    __tablename__ = 'processed_contents'
    
    id = Column(Integer, primary_key=True)
    page_id = Column(Integer, ForeignKey('crawled_pages.id', ondelete='CASCADE'), nullable=False)
    cleaned_text = Column(Text)
    cleaned_length = Column(Integer)
    word_count = Column(Integer)
    unique_word_count = Column(Integer)
    avg_word_length = Column(Float)
    special_char_ratio = Column(Float)
    detected_language = Column(String(10))
    processed_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    page = relationship("CrawledPageModel", back_populates="processed_contents")
    entities = relationship("EntityModel", back_populates="processed_content", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_processed_page', 'page_id'),
    )


class EntityModel(Base):
    """Model for extracted entities"""
    __tablename__ = 'entities'
    
    id = Column(Integer, primary_key=True)
    processed_content_id = Column(Integer, ForeignKey('processed_contents.id', ondelete='CASCADE'), nullable=False)
    entity_type = Column(String(50), nullable=False, index=True)
    value = Column(String(500), nullable=False, index=True)
    confidence = Column(Float, default=0.0)
    context = Column(Text)
    position = Column(Integer)
    
    # Relationships
    processed_content = relationship("ProcessedContentModel", back_populates="entities")
    
    __table_args__ = (
        Index('idx_entity_type_value', 'entity_type', 'value'),
        Index('idx_entity_confidence', 'confidence'),
    )


class KeywordMatchModel(Base):
    """Model for keyword detection matches"""
    __tablename__ = 'keyword_matches'
    
    id = Column(Integer, primary_key=True)
    page_id = Column(Integer, ForeignKey('crawled_pages.id', ondelete='CASCADE'), nullable=False)
    keyword = Column(String(200), nullable=False, index=True)
    matched_text = Column(String(500))
    match_type = Column(String(50), index=True)  # exact, fuzzy, regex, contextual
    confidence = Column(Float, default=0.0, index=True)
    category = Column(String(50), index=True)
    similarity_score = Column(Float)
    context = Column(Text)
    position = Column(Integer)
    
    # Relationships
    page = relationship("CrawledPageModel", back_populates="keyword_matches")
    
    __table_args__ = (
        Index('idx_match_category_confidence', 'category', 'confidence'),
        Index('idx_keyword_category', 'keyword', 'category'),
    )


class NLPResultModel(Base):
    """Model for NLP analysis results"""
    __tablename__ = 'nlp_results'
    
    id = Column(Integer, primary_key=True)
    page_id = Column(Integer, ForeignKey('crawled_pages.id', ondelete='CASCADE'), nullable=False)
    
    # Threat assessment
    threat_score = Column(Float, index=True)
    threat_level = Column(String(20), index=True)
    
    # Readability
    readability_score = Column(Float)
    
    # Summary and key phrases (stored as JSON)
    summary = Column(Text)
    key_phrases = Column(JSON)  # List of strings
    threat_keywords = Column(JSON)  # List of strings
    
    # Topic modeling (stored as JSON)
    topics = Column(JSON)  # List of topic dicts
    dominant_topic = Column(Integer)
    
    # Analysis timestamp
    analyzed_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    page = relationship("CrawledPageModel", back_populates="nlp_results")
    named_entities = relationship("NamedEntityModel", back_populates="nlp_result", cascade="all, delete-orphan")
    relationships = relationship("RelationshipModel", back_populates="nlp_result", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_threat_score_time', 'threat_score', 'analyzed_at'),
    )


class NamedEntityModel(Base):
    """Model for named entities from NLP"""
    __tablename__ = 'named_entities'
    
    id = Column(Integer, primary_key=True)
    nlp_result_id = Column(Integer, ForeignKey('nlp_results.id', ondelete='CASCADE'), nullable=False)
    text = Column(String(200), nullable=False, index=True)
    label = Column(String(50), nullable=False, index=True)
    confidence = Column(Float)
    start_char = Column(Integer)
    end_char = Column(Integer)
    context = Column(Text)
    
    # Relationships
    nlp_result = relationship("NLPResultModel", back_populates="named_entities")
    
    __table_args__ = (
        Index('idx_entity_label_text', 'label', 'text'),
    )


class RelationshipModel(Base):
    """Model for entity relationships"""
    __tablename__ = 'relationships'
    
    id = Column(Integer, primary_key=True)
    nlp_result_id = Column(Integer, ForeignKey('nlp_results.id', ondelete='CASCADE'), nullable=False)
    source_entity = Column(String(200), nullable=False)
    source_type = Column(String(50))
    target_entity = Column(String(200), nullable=False)
    target_type = Column(String(50))
    relationship_type = Column(String(50), index=True)
    confidence = Column(Float)
    evidence = Column(Text)
    
    # Relationships
    nlp_result = relationship("NLPResultModel", back_populates="relationships")
    
    __table_args__ = (
        Index('idx_relationship_type', 'relationship_type'),
        Index('idx_source_target', 'source_entity', 'target_entity'),
    )


class AlertModel(Base):
    """Model for generated alerts"""
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True)
    page_id = Column(Integer, ForeignKey('crawled_pages.id', ondelete='CASCADE'))
    alert_level = Column(String(20), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    alert_type = Column(String(50), nullable=False, index=True)  # credential_leak, proprietary_data, etc.
    title = Column(String(500))
    description = Column(Text)
    risk_score = Column(Float, index=True)
    generated_at = Column(DateTime, default=datetime.utcnow, index=True)
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(100))
    acknowledged_at = Column(DateTime)
    resolved = Column(Boolean, default=False)
    
    # Relationships
    page = relationship("CrawledPageModel", back_populates="alerts")
    
    __table_args__ = (
        Index('idx_alerts_level_time', 'alert_level', 'generated_at'),
        Index('idx_alerts_unacknowledged', 'acknowledged', 'generated_at'),
    )


class ScanHistoryModel(Base):
    """Model for tracking scan history"""
    __tablename__ = 'scan_history'
    
    id = Column(Integer, primary_key=True)
    scan_started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    scan_ended_at = Column(DateTime)
    pages_crawled = Column(Integer, default=0)
    pages_failed = Column(Integer, default=0)
    alerts_generated = Column(Integer, default=0)
    scan_status = Column(String(50), default='running')  # running, completed, failed
    scan_metadata = Column(JSON)  # Additional scan info
    
    __table_args__ = (
        Index('idx_scan_status_time', 'scan_status', 'scan_started_at'),
    )


# ============================================================================
# Database Manager
# ============================================================================

class DatabaseManager:
    """
    Manages database connections and operations
    """
    
    def __init__(self, connection_string: str = None):
        """
        Initialize database manager
        
        Args:
            connection_string: SQLAlchemy connection string
        """
        if not connection_string:
            # Use SQLite by default, but support PostgreSQL
            db_type = config_manager.get('database.type', 'sqlite')
            db_path = config_manager.get('database.path', 'data/monitoring.db')
            
            if db_type == 'sqlite':
                # Ensure directory exists
                os.makedirs(os.path.dirname(db_path), exist_ok=True)
                connection_string = f'sqlite:///{db_path}'
            elif db_type == 'postgresql':
                # PostgreSQL connection (read from env or config)
                host = os.getenv('DB_HOST', 'localhost')
                port = os.getenv('DB_PORT', '5432')
                database = os.getenv('DB_NAME', 'agri_monitor')
                user = os.getenv('DB_USER', 'agri_user')
                password = os.getenv('DB_PASSWORD', '')
                connection_string = f'postgresql://{user}:{password}@{host}:{port}/{database}'
        
        self.connection_string = connection_string
        self.logger = logging.getLogger(__name__)
        
        # Create engine with connection pooling
        self.engine = create_engine(
            connection_string,
            poolclass=QueuePool,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,  # Verify connections before using
            echo=False  # Set to True for SQL debugging
        )
        
        # Create session factory
        self.SessionLocal = sessionmaker(bind=self.engine)
        
        # Create tables if they don't exist
        self.create_tables()
        
        self.logger.info(f"Database initialized: {db_type if 'db_type' in locals() else 'custom'}")
    
    def create_tables(self):
        """Create all tables if they don't exist"""
        Base.metadata.create_all(self.engine)
        self.logger.info("Database tables created/verified")
    
    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """
        Context manager for database sessions
        
        Usage:
            with db.get_session() as session:
                session.query(CrawledPageModel).all()
        """
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            self.logger.error(f"Database error: {str(e)}")
            raise
        finally:
            session.close()
    
    def get_statistics(self):
        """Get system statistics as JSON-serializable dict"""
        from sqlalchemy import func
        from datetime import datetime, timedelta
        
        with self.get_session() as session:
            from storage.database import CrawledPageModel, AlertModel, ScanHistoryModel
            
            # Total pages
            total_pages = session.query(func.count(CrawledPageModel.id)).scalar() or 0
            
            # Total alerts
            total_alerts = session.query(func.count(AlertModel.id)).scalar() or 0
            
            # Unacknowledged alerts
            unacknowledged_alerts = session.query(func.count(AlertModel.id)).filter(
                AlertModel.acknowledged == False
            ).scalar() or 0
            
            # Critical alerts
            critical_alerts = session.query(func.count(AlertModel.id)).filter(
                AlertModel.alert_level == 'CRITICAL'
            ).scalar() or 0
            
            # Pages last 24h
            yesterday = datetime.now() - timedelta(days=1)
            pages_last_24h = session.query(func.count(CrawledPageModel.id)).filter(
                CrawledPageModel.crawled_at >= yesterday
            ).scalar() or 0
            
            # Alerts last 24h
            alerts_last_24h = session.query(func.count(AlertModel.id)).filter(
                AlertModel.generated_at >= yesterday
            ).scalar() or 0
            
            # Last scan - USING CORRECT COLUMN NAME
            last_scan = session.query(ScanHistoryModel).order_by(
                ScanHistoryModel.scan_started_at.desc()  # ✅ Fixed
            ).first()
            
            last_scan_dict = None
            if last_scan:
                last_scan_dict = {
                    'id': last_scan.id,
                    'scan_started_at': last_scan.scan_started_at.isoformat() if last_scan.scan_started_at else None,
                    'scan_ended_at': last_scan.scan_ended_at.isoformat() if last_scan.scan_ended_at else None,
                    'pages_crawled': last_scan.pages_crawled,
                    'pages_failed': last_scan.pages_failed,
                    'alerts_generated': last_scan.alerts_generated,
                    'scan_status': last_scan.scan_status
                }
            
            return {
                'total_pages': total_pages,
                'total_alerts': total_alerts,
                'unacknowledged_alerts': unacknowledged_alerts,
                'critical_alerts': critical_alerts,
                'pages_last_24h': pages_last_24h,
                'alerts_last_24h': alerts_last_24h,
                'last_scan': last_scan_dict
            }
# ============================================================================
# Data Storage Service
# ============================================================================

class DataStorageService:
    """
    High-level service for storing and retrieving monitoring data
    """
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.logger = logging.getLogger(__name__)
    
    def save_crawled_page(self, page_data: Dict[str, Any]) -> int:
        """
        Save crawled page to database
        
        Args:
            page_data: Dictionary with page information
        
        Returns:
            Page ID
        """
        with self.db.get_session() as session:
            # Check if page already exists
            existing = session.query(CrawledPageModel).filter(
                CrawledPageModel.url == page_data['url']
            ).first()
            
            if existing:
                self.logger.debug(f"Page already exists: {page_data['url']}")
                return existing.id
            
            # Create new page
            page = CrawledPageModel(
                url=page_data['url'],
                title=page_data.get('title', ''),
                content_hash=page_data.get('content_hash', ''),
                crawl_depth=page_data.get('crawl_depth', 0),
                status_code=page_data.get('status_code', 200),
                content_type=page_data.get('content_type', ''),
                content_length=page_data.get('content_length', 0),
                crawled_at=page_data.get('crawled_at', datetime.utcnow()),
                found_at_url=page_data.get('found_at_url', '')
            )
            
            session.add(page)
            session.flush()  # Get the ID
            
            self.logger.info(f"Saved crawled page: {page_data['url']} (ID: {page.id})")
            return page.id
    
    def save_processed_content(self, page_id: int, processed_data: Dict[str, Any]) -> int:
        """
        Save preprocessed content
        
        Args:
            page_id: ID of the crawled page
            processed_data: Processed document data
        
        Returns:
            Processed content ID
        """
        with self.db.get_session() as session:
            processed = ProcessedContentModel(
                page_id=page_id,
                cleaned_text=processed_data.get('cleaned_text', '')[:10000],  # Limit size
                cleaned_length=processed_data.get('cleaned_length', 0),
                word_count=processed_data.get('word_count', 0),
                unique_word_count=processed_data.get('unique_word_count', 0),
                avg_word_length=processed_data.get('avg_word_length', 0),
                special_char_ratio=processed_data.get('special_char_ratio', 0),
                detected_language=processed_data.get('detected_language', 'en'),
                processed_at=datetime.utcnow()
            )
            
            session.add(processed)
            session.flush()
            
            # Save entities
            for entity in processed_data.get('entities', []):
                entity_model = EntityModel(
                    processed_content_id=processed.id,
                    entity_type=entity.get('type', 'unknown'),
                    value=entity.get('value', ''),
                    confidence=entity.get('confidence', 0.0),
                    context=entity.get('context', '')[:500],
                    position=entity.get('position', 0)
                )
                session.add(entity_model)
            
            self.logger.info(f"Saved processed content for page {page_id} (ID: {processed.id})")
            return processed.id
    
    def save_keyword_matches(self, page_id: int, matches: List[Dict[str, Any]]):
        """
        Save keyword detection matches
        
        Args:
            page_id: ID of the crawled page
            matches: List of keyword match dictionaries
        """
        with self.db.get_session() as session:
            for match in matches:
                keyword_match = KeywordMatchModel(
                    page_id=page_id,
                    keyword=match.get('keyword', ''),
                    matched_text=match.get('matched_text', '')[:500],
                    match_type=match.get('match_type', 'exact'),
                    confidence=match.get('confidence', 0.0),
                    category=match.get('category', 'unknown'),
                    similarity_score=match.get('similarity_score', 1.0),
                    context=match.get('context', '')[:500],
                    position=match.get('position', 0)
                )
                session.add(keyword_match)
            
            self.logger.info(f"Saved {len(matches)} keyword matches for page {page_id}")
    
    def save_nlp_results(self, page_id: int, nlp_data: Dict[str, Any]) -> int:
        """
        Save NLP analysis results
        
        Args:
            page_id: ID of the crawled page
            nlp_data: NLP analysis results
        
        Returns:
            NLP result ID
        """
        with self.db.get_session() as session:
            nlp_result = NLPResultModel(
                page_id=page_id,
                threat_score=nlp_data.get('threat_score', 0.0),
                threat_level=nlp_data.get('threat_level', 'LOW'),
                readability_score=nlp_data.get('readability_score', 0.0),
                summary=nlp_data.get('summary', '')[:2000],
                key_phrases=json.dumps(nlp_data.get('key_phrases', [])),
                threat_keywords=json.dumps(nlp_data.get('threat_keywords', [])),
                topics=json.dumps(nlp_data.get('topics', [])),
                dominant_topic=nlp_data.get('dominant_topic', -1),
                analyzed_at=datetime.utcnow()
            )
            
            session.add(nlp_result)
            session.flush()
            
            # Save named entities
            for entity in nlp_data.get('named_entities', []):
                entity_model = NamedEntityModel(
                    nlp_result_id=nlp_result.id,
                    text=entity.get('text', '')[:200],
                    label=entity.get('label', ''),
                    confidence=entity.get('confidence', 0.0),
                    start_char=entity.get('start_char', 0),
                    end_char=entity.get('end_char', 0),
                    context=entity.get('context', '')[:500]
                )
                session.add(entity_model)
            
            # Save relationships
            for rel in nlp_data.get('relationships', []):
                rel_model = RelationshipModel(
                    nlp_result_id=nlp_result.id,
                    source_entity=rel.get('source_entity', '')[:200],
                    source_type=rel.get('source_type', ''),
                    target_entity=rel.get('target_entity', '')[:200],
                    target_type=rel.get('target_type', ''),
                    relationship_type=rel.get('relationship_type', ''),
                    confidence=rel.get('confidence', 0.0),
                    evidence=rel.get('evidence', '')[:500]
                )
                session.add(rel_model)
            
            self.logger.info(f"Saved NLP results for page {page_id} (ID: {nlp_result.id})")
            return nlp_result.id
    
    def save_alert(self, alert_data: Dict[str, Any]) -> int:
        """
        Save alert to database
        
        Args:
            alert_data: Alert information
        
        Returns:
            Alert ID
        """
        with self.db.get_session() as session:
            alert = AlertModel(
                page_id=alert_data.get('page_id'),
                alert_level=alert_data.get('alert_level', 'MEDIUM'),
                alert_type=alert_data.get('alert_type', 'general'),
                title=alert_data.get('title', ''),
                description=alert_data.get('description', ''),
                risk_score=alert_data.get('risk_score', 0.0),
                generated_at=datetime.utcnow(),
                acknowledged=False,
                resolved=False
            )
            
            session.add(alert)
            session.flush()
            
            self.logger.info(f"Saved alert (ID: {alert.id}, Level: {alert.alert_level})")
            return alert.id
    
    def start_scan(self, metadata: Dict[str, Any] = None) -> int:
        """
        Start a new scan session
        
        Args:
            metadata: Additional scan metadata
        
        Returns:
            Scan ID
        """
        with self.db.get_session() as session:
            scan = ScanHistoryModel(
                scan_started_at=datetime.utcnow(),
                scan_status='running',
                scan_metadata=json.dumps(metadata or {})
            )
            session.add(scan)
            session.flush()
            
            self.logger.info(f"Started scan (ID: {scan.id})")
            return scan.id
    
    def end_scan(self, scan_id: int, stats: Dict[str, int]):
        """
        End a scan session with statistics
        
        Args:
            scan_id: Scan ID to end
            stats: Statistics from the scan
        """
        with self.db.get_session() as session:
            scan = session.query(ScanHistoryModel).filter(
                ScanHistoryModel.id == scan_id
            ).first()
            
            if scan:
                scan.scan_ended_at = datetime.utcnow()
                scan.pages_crawled = stats.get('pages_crawled', 0)
                scan.pages_failed = stats.get('pages_failed', 0)
                scan.alerts_generated = stats.get('alerts_generated', 0)
                scan.scan_status = 'completed'
                
                self.logger.info(f"Ended scan {scan_id}: {stats}")
    
    def get_unacknowledged_alerts(self, limit: int = 100) -> List[Dict]:
        """Get unacknowledged alerts"""
        with self.db.get_session() as session:
            alerts = session.query(AlertModel).filter(
                AlertModel.acknowledged == False
            ).order_by(
                AlertModel.risk_score.desc(),
                AlertModel.generated_at.desc()
            ).limit(limit).all()
            
            return [
                {
                    'id': a.id,
                    'alert_level': a.alert_level,
                    'alert_type': a.alert_type,
                    'title': a.title,
                    'description': a.description,
                    'risk_score': a.risk_score,
                    'generated_at': a.generated_at.isoformat(),
                    'page_url': a.page.url if a.page else None
                }
                for a in alerts
            ]
    
    def acknowledge_alert(self, alert_id: int, acknowledged_by: str = 'system'):
        """Mark alert as acknowledged"""
        with self.db.get_session() as session:
            alert = session.query(AlertModel).filter(AlertModel.id == alert_id).first()
            if alert:
                alert.acknowledged = True
                alert.acknowledged_by = acknowledged_by
                alert.acknowledged_at = datetime.utcnow()
                self.logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
                return True
        return False
    
    def search_by_keyword(self, keyword: str, limit: int = 50) -> List[Dict]:
        """Search for pages containing specific keyword"""
        with self.db.get_session() as session:
            matches = session.query(KeywordMatchModel).filter(
                KeywordMatchModel.keyword.ilike(f'%{keyword}%')
            ).order_by(
                KeywordMatchModel.confidence.desc()
            ).limit(limit).all()
            
            results = []
            for match in matches:
                results.append({
                    'page_url': match.page.url,
                    'keyword': match.keyword,
                    'confidence': match.confidence,
                    'context': match.context,
                    'crawled_at': match.page.crawled_at.isoformat() if match.page else None
                })
            
            return results
    
    def get_threat_timeline(self, hours: int = 168) -> List[Dict]:
        """Get threat score timeline for the last N hours"""
        with self.db.get_session() as session:
            since = datetime.utcnow() - timedelta(hours=hours)
            
            results = session.query(
                NLPResultModel.analyzed_at,
                NLPResultModel.threat_score
            ).filter(
                NLPResultModel.analyzed_at >= since
            ).order_by(
                NLPResultModel.analyzed_at
            ).all()
            
            return [
                {
                    'timestamp': r[0].isoformat(),
                    'threat_score': r[1]
                }
                for r in results
            ]


# ============================================================================
# Standalone Test
# ============================================================================

def test_storage_module():
    """Test the data storage module"""
    print("\n" + "="*60)
    print("TESTING DATA STORAGE MODULE")
    print("="*60)
    
    # Initialize database
    print("\n[1] Initializing database...")
    db_manager = DatabaseManager('sqlite:///test_monitoring.db')
    storage = DataStorageService(db_manager)
    
    # Test data
    print("\n[2] Saving test data...")
    
    # Save crawled page
    page_id = storage.save_crawled_page({
        'url': 'http://test.onion/breach_data',
        'title': 'Test Breach Data',
        'content_hash': hashlib.sha256(b'test content').hexdigest(),
        'crawl_depth': 1,
        'status_code': 200,
        'content_type': 'text/html',
        'content_length': 1000,
        'crawled_at': datetime.utcnow()
    })
    print(f"   Saved page ID: {page_id}")
    
    # Save processed content
    processed_id = storage.save_processed_content(page_id, {
        'cleaned_text': 'This is test content about AgriFarm data breach',
        'cleaned_length': 50,
        'word_count': 8,
        'unique_word_count': 7,
        'avg_word_length': 4.5,
        'special_char_ratio': 0.1,
        'detected_language': 'en',
        'entities': [
            {'type': 'ORG', 'value': 'AgriFarm', 'confidence': 0.95, 'context': 'AgriFarm data breach', 'position': 20}
        ]
    })
    print(f"   Saved processed content ID: {processed_id}")
    
    # Save keyword matches
    storage.save_keyword_matches(page_id, [
        {
            'keyword': 'password',
            'matched_text': 'password: secret123',
            'match_type': 'exact',
            'confidence': 0.9,
            'category': 'credential',
            'similarity_score': 1.0,
            'context': 'Found password: secret123',
            'position': 100
        }
    ])
    print(f"   Saved keyword matches")
    
    # Save NLP results (without sentiment)
    nlp_id = storage.save_nlp_results(page_id, {
        'threat_score': 85.0,
        'threat_level': 'HIGH',
        'readability_score': 8.5,
        'summary': 'This is a test summary of the breach data.',
        'key_phrases': ['data breach', 'AgriFarm', 'credentials'],
        'threat_keywords': ['breach', 'leak'],
        'topics': [],
        'dominant_topic': 0,
        'named_entities': [
            {'text': 'AgriFarm', 'label': 'ORG', 'confidence': 0.95, 'start_char': 10, 'end_char': 18, 'context': 'AgriFarm breach'}
        ],
        'relationships': [
            {
                'source_entity': 'AgriFarm',
                'source_type': 'ORG',
                'target_entity': 'breach',
                'target_type': 'EVENT',
                'relationship_type': 'experienced',
                'confidence': 0.85,
                'evidence': 'AgriFarm experienced a breach'
            }
        ]
    })
    print(f"   Saved NLP results ID: {nlp_id}")
    
    # Save alert
    alert_id = storage.save_alert({
        'page_id': page_id,
        'alert_level': 'HIGH',
        'alert_type': 'credential_leak',
        'title': 'Credentials Found in Dark Web',
        'description': 'Password credentials detected in dark web content',
        'risk_score': 85.0
    })
    print(f"   Saved alert ID: {alert_id}")
    
    # Start and end scan
    scan_id = storage.start_scan({'test': True})
    storage.end_scan(scan_id, {'pages_crawled': 1, 'pages_failed': 0, 'alerts_generated': 1})
    print(f"   Completed scan ID: {scan_id}")
    
    # Test queries
    print("\n[3] Testing queries...")
    
    stats = db_manager.get_statistics()
    print(f"   Database stats: {stats}")
    
    unacknowledged = storage.get_unacknowledged_alerts()
    print(f"   Unacknowledged alerts: {len(unacknowledged)}")
    
    search_results = storage.search_by_keyword('password')
    print(f"   Search results for 'password': {len(search_results)}")
    
    timeline = storage.get_threat_timeline(24)
    print(f"   Threat timeline points: {len(timeline)}")
    
    print("\n[4] Test completed successfully!")
    print("="*60)
    
    return True


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    test_storage_module()