"""
NLP Analysis Module for Dark Web Agriculture Monitor
Handles semantic analysis, named entity recognition, intent classification, and relationship extraction
"""

import os
import sys
import re
import json
import logging
from datetime import datetime
from typing import List, Dict, Set, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from collections import Counter, defaultdict
from string import punctuation

import spacy
from spacy import displacy
import numpy as np

# Hugging Face imports for modern NLP
try:
    from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
    import torch
    HF_AVAILABLE = True
except ImportError:
    HF_AVAILABLE = False
    print("Warning: transformers not installed. Install with: pip install transformers torch")

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import config_manager
from preprocessor.data_cleaner import ProcessedDocument, ExtractedEntity
from detector.keyword_detector import KeywordMatch

# Suppress warnings
import warnings
warnings.filterwarnings('ignore')

# Load spaCy models
try:
    nlp_small = spacy.load("en_core_web_sm")
    nlp_large = nlp_small
except OSError:
    print("Downloading spaCy models...")
    os.system("python -m spacy download en_core_web_sm")
    nlp_small = spacy.load("en_core_web_sm")
    nlp_large = nlp_small


@dataclass
class NamedEntity:
    """Data structure for named entities"""
    text: str
    label: str  # PERSON, ORG, GPE, DATE, CROP, FERTILIZER, etc.
    confidence: float
    start_char: int
    end_char: int
    context: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Relationship:
    """Data structure for entity relationships"""
    source_entity: str
    source_type: str
    target_entity: str
    target_type: str
    relationship_type: str  # owned_by, contains, leaked_from, etc.
    confidence: float
    evidence: str  # Text that indicates the relationship
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class IntentClassification:
    """Data structure for intent classification results"""
    intent: str  # data_breach, credential_dump, sales_offering, technical_discussion, false_positive
    confidence: float
    all_scores: Dict[str, float]
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class NLPResult:
    """Complete NLP analysis result for a document"""
    document_url: str
    analyzed_at: datetime
    
    # Named entities
    entities: List[NamedEntity]
    entities_by_type: Dict[str, int]
    
    # Relationships
    relationships: List[Relationship]
    
    # Intent classification (replaces sentiment analysis)
    intent: IntentClassification
    
    # Language and readability
    detected_language: str
    readability_score: float  # Flesch-Kincaid score
    average_word_length: float
    sentence_count: int
    
    # Threat indicators
    threat_keywords: List[str]
    threat_score: float  # 0-100
    
    # Summarization
    summary: str  # Extractive summary
    key_phrases: List[str]
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        data['analyzed_at'] = self.analyzed_at.isoformat()
        data['entities'] = [e.to_dict() for e in self.entities]
        data['relationships'] = [r.to_dict() for r in self.relationships]
        data['intent'] = self.intent.to_dict()
        return data


class AgricultureNER:
    """Custom agriculture entity recognition using spaCy + custom patterns"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.nlp = nlp_small
        
        # Add agriculture-specific entity patterns
        self._add_agriculture_patterns()
    
    def _add_agriculture_patterns(self):
        """Add agriculture-specific entity patterns"""
        
        agriculture_patterns = [
            # Crop varieties
            {"label": "CROP", "pattern": [{"LOWER": {"IN": ["corn", "wheat", "soybean", "rice", "cotton", "barley", "oat", "sorghum", "canola"]}}]},
            {"label": "CROP", "pattern": [{"LOWER": {"REGEX": r".*(?:corn|wheat|soy|rice|cotton).*"}}]},
            
            # Fertilizers and nutrients
            {"label": "FERTILIZER", "pattern": [{"LOWER": {"IN": ["nitrogen", "phosphorus", "potassium", "npk", "urea", "ammonium", "nitrate", "phosphate"]}}]},
            {"label": "FERTILIZER", "pattern": [{"LOWER": {"REGEX": r"\d+-\d+-\d+"}}]},  # NPK ratios like 20-10-10
            
            # Pesticides and herbicides
            {"label": "PESTICIDE", "pattern": [{"LOWER": {"IN": ["glyphosate", "atrazine", "chlorpyrifos", "imidacloprid", "roundup"]}}]},
            
            # Agricultural data types
            {"label": "YIELD_DATA", "pattern": [{"LIKE_NUM": True}, {"LOWER": {"IN": ["bu/acre", "tons/ha", "kg/ha", "mt/ha"]}}]},
            {"label": "YIELD_DATA", "pattern": [{"LOWER": {"REGEX": r"\d+(?:\.\d+)?\s*(?:bushels?|tons?|kg|mt)\s*per\s*(?:acre|hectare)"}}]},
            
            # Irrigation systems
            {"label": "IRRIGATION", "pattern": [{"LOWER": {"IN": ["drip", "sprinkler", "center pivot", "flood", "furrow", "subsurface"]}}]},
            
            # Soil properties
            {"label": "SOIL_PROPERTY", "pattern": [{"LOWER": {"IN": ["ph", "salinity", "organic matter", "cation exchange", "soil moisture"]}}]},
            
            # Dark web indicators
            {"label": "DARK_WEB_SITE", "pattern": [{"LOWER": {"REGEX": r".*\.onion"}}]},
            
            # Credential indicators
            {"label": "CREDENTIAL", "pattern": [{"LOWER": {"IN": ["password", "api_key", "secret", "token", "private key"]}}]},
        ]
        
        # Add patterns to pipeline
        if "entity_ruler" not in self.nlp.pipe_names:
            ruler = self.nlp.add_pipe("entity_ruler", before="ner")
            ruler.add_patterns(agriculture_patterns)
            self.logger.info(f"Added {len(agriculture_patterns)} agriculture entity patterns")
    
    def extract_entities(self, text: str, source_url: str = "") -> List[NamedEntity]:
        """
        Extract named entities including agriculture-specific ones
        
        Args:
            text: Text to analyze
            source_url: Source URL for reference
        
        Returns:
            List of named entities
        """
        self.logger.debug(f"Extracting named entities from {source_url}")
        
        # Process with spaCy (limit for performance)
        doc = self.nlp(text[:500000])
        
        entities = []
        
        for ent in doc.ents:
            # Filter out very short entities
            if len(ent.text) < 2:
                continue
            
            # Get context (50 chars around entity)
            start = max(0, ent.start_char - 50)
            end = min(len(text), ent.end_char + 50)
            context = text[start:end]
            
            # Calculate confidence based on entity type and length
            confidence = self._estimate_confidence(ent)
            
            entity = NamedEntity(
                text=ent.text,
                label=ent.label_,
                confidence=confidence,
                start_char=ent.start_char,
                end_char=ent.end_char,
                context=context
            )
            entities.append(entity)
        
        self.logger.info(f"Found {len(entities)} named entities in {source_url}")
        return entities
    
    def _estimate_confidence(self, ent) -> float:
        """Estimate confidence for extracted entity"""
        # Base confidence by entity type
        type_confidence = {
            'DATE': 0.95,
            'PERCENT': 0.95,
            'MONEY': 0.90,
            'CROP': 0.85,
            'FERTILIZER': 0.85,
            'YIELD_DATA': 0.90,
            'PERSON': 0.80,
            'ORG': 0.80,
            'GPE': 0.85,
            'DARK_WEB_SITE': 0.95,
            'CREDENTIAL': 0.90,
        }.get(ent.label_, 0.75)
        
        # Length boost (longer entities more reliable)
        length_boost = min(0.10, len(ent.text) / 200)
        
        return min(0.99, type_confidence + length_boost)
    
    def get_entity_statistics(self, entities: List[NamedEntity]) -> Dict[str, int]:
        """Get statistics about entity types"""
        stats = Counter()
        for entity in entities:
            stats[entity.label] += 1
        return dict(stats)


class IntentClassifier:
    """
    Intent classification using Hugging Face zero-shot models
    Replaces sentiment analysis for dark web content
    """

    THREAT_LEVELS = {
        'credential_dump': 90,
        'data_breach_announcement': 85,
        'ransomware_threat': 80,
        'proprietary_data_sale': 75,
        'marketplace_listing': 60,
        'technical_discussion': 30,
        'agriculture_research': 20,
        'false_positive_sample': 5
    }


    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.classifier = None
        self.model_name = "facebook/bart-large-mnli"
        
        # Intent categories for dark web agriculture content
        self.intent_categories = [
            "data_breach_announcement",      # Announcing a successful breach
            "credential_dump",               # Sharing usernames/passwords
            "proprietary_data_sale",         # Selling trade secrets or algorithms
            "technical_discussion",          # Normal technical conversation
            "ransomware_threat",             # Extortion or ransomware claims
            "false_positive_sample",         # Test/sample data, not real
            "agriculture_research",          # Legitimate research discussion
            "marketplace_listing"            # Selling access or data
        ]
        
        # Initialize model if available
        if HF_AVAILABLE:
            try:
                self.classifier = pipeline(
                    "zero-shot-classification",
                    model=self.model_name,
                    device=0 if torch.cuda.is_available() else -1
                )
                self.logger.info(f"Loaded zero-shot classifier: {self.model_name}")
            except Exception as e:
                self.logger.error(f"Failed to load classifier: {e}")
                self.classifier = None
        else:
            self.logger.warning("Transformers not available - intent classification disabled")
    
    def classify(self, text: str) -> IntentClassification:
        """
        Classify the intent of the document
        
        Args:
            text: Document text to classify
        
        Returns:
            IntentClassification object
        """
        if not self.classifier:
            # Fallback: rule-based classification
            return self._rule_based_classify(text)
        
        # Limit text length for performance
        text_sample = text[:2000]
        
        try:
            result = self.classifier(text_sample, self.intent_categories)
            
            return IntentClassification(
                intent=result['labels'][0],
                confidence=result['scores'][0],
                all_scores=dict(zip(result['labels'], result['scores']))
            )
        except Exception as e:
            self.logger.error(f"Classification failed: {e}")
            return self._rule_based_classify(text)
    
    def _rule_based_classify(self, text: str) -> IntentClassification:
        """Fallback rule-based classification"""
        text_lower = text.lower()
        
        # Simple keyword-based classification
        if any(word in text_lower for word in ['breach', 'leak', 'dump', 'exfiltrated']):
            intent = "data_breach_announcement"
            confidence = 0.7
        elif any(word in text_lower for word in ['password', 'credential', 'login', 'api_key']):
            intent = "credential_dump"
            confidence = 0.7
        elif any(word in text_lower for word in ['sample', 'example', 'test', 'demo']):
            intent = "false_positive_sample"
            confidence = 0.8
        elif any(word in text_lower for word in ['ransom', 'bitcoin', 'extortion']):
            intent = "ransomware_threat"
            confidence = 0.7
        else:
            intent = "technical_discussion"
            confidence = 0.5
        
        return IntentClassification(
            intent=intent,
            confidence=confidence,
            all_scores={intent: confidence}
        )
    
    def calculate_threat_score(self, intent: IntentClassification, entities: List[NamedEntity]) -> float:
        """Combine intent + entities for better threat scoring"""
        base_score = self.THREAT_LEVELS.get(intent.intent, 50)
        
        # Boost based on sensitive entities found
        if any(e.label == 'CREDENTIAL' for e in entities):
            base_score += 20
        if any(e.label == 'ORG' for e in entities):
            base_score += 10
        if any(e.label == 'DARK_WEB_SITE' for e in entities):
            base_score += 15
            
        return min(100, base_score * intent.confidence)


class RelationshipExtractor:
    """
    Extracts relationships between entities using dependency parsing
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.nlp = nlp_large
        
        # Relationship patterns based on dependency parsing
        self.relationship_patterns = {
            'leaked_from': [
                ('leak', 'nsubj', 'pobj'),
                ('breach', 'nsubj', 'pobj'),
                ('exposed', 'nsubj', 'pobj'),
                ('dump', 'nsubj', 'pobj')
            ],
            'contains': [
                ('contain', 'nsubj', 'dobj'),
                ('include', 'nsubj', 'dobj'),
                ('has', 'nsubj', 'dobj')
            ],
            'owned_by': [
                ('owned', 'nsubj', 'pobj'),
                ('belongs', 'nsubj', 'pobj'),
                ('property', 'nsubj', 'pobj')
            ],
            'accessed_by': [
                ('accessed', 'nsubj', 'pobj'),
                ('used_by', 'nsubj', 'pobj'),
                ('login', 'nsubj', 'pobj')
            ]
        }
    
    def extract_relationships(self, text: str, entities: List[NamedEntity]) -> List[Relationship]:
        """
        Extract relationships between entities in text
        
        Args:
            text: Text to analyze
            entities: Previously extracted named entities
        
        Returns:
            List of relationships
        """
        self.logger.debug(f"Extracting relationships from text")
        
        doc = self.nlp(text[:300000])  # Limit for performance
        relationships = []
        
        # Create a mapping of entity spans for quick lookup
        entity_spans = self._create_entity_spans(entities, text)
        
        # Analyze each sentence
        for sent in doc.sents:
            sent_entities = self._get_entities_in_span(sent.start_char, sent.end_char, entity_spans)
            
            # Look for relationship patterns
            for token in sent:
                if token.dep_ in ['nsubj', 'dobj', 'pobj'] and token.head.pos_ == 'VERB':
                    relationship = self._extract_from_verb(token, sent_entities, sent.text)
                    if relationship:
                        relationships.append(relationship)
        
        # Remove duplicates
        unique_relationships = self._deduplicate_relationships(relationships)
        
        self.logger.info(f"Extracted {len(unique_relationships)} relationships")
        return unique_relationships
    
    def _create_entity_spans(self, entities: List[NamedEntity], text: str) -> List[Tuple[int, int, NamedEntity]]:
        """Create sorted list of entity spans for efficient lookup"""
        spans = []
        for entity in entities:
            spans.append((entity.start_char, entity.end_char, entity))
        return sorted(spans, key=lambda x: x[0])
    
    def _get_entities_in_span(self, start: int, end: int, 
                              entity_spans: List[Tuple[int, int, NamedEntity]]) -> List[NamedEntity]:
        """Get all entities within a character span"""
        entities = []
        for e_start, e_end, entity in entity_spans:
            if start <= e_start <= end or start <= e_end <= end:
                entities.append(entity)
        return entities
    
    def _extract_from_verb(self, token, entities: List[NamedEntity], sentence: str) -> Optional[Relationship]:
        """Extract relationship from a verb and its arguments"""
        verb = token.head.lemma_.lower()

        if token.dep_ != "nsubj":
            return None

        subject = token.text
        obj = None

        for child in token.head.children:
            if child.dep_ in ("dobj", "pobj"):
                obj = child.text

        if not obj:
            return None

        source_entity = self._find_matching_entity(subject, entities)
        target_entity = self._find_matching_entity(obj, entities)

        if source_entity and target_entity:
            return Relationship(
                source_entity=source_entity.text,
                source_type=source_entity.label,
                target_entity=target_entity.text,
                target_type=target_entity.label,
                relationship_type=verb,
                confidence=0.75,
                evidence=sentence[:200]
            )
        return None
    
    def _find_matching_entity(self, text: str, entities: List[NamedEntity]) -> Optional[NamedEntity]:
        """Find entity that matches or contains the given text"""
        text_lower = text.lower()
        for entity in entities:
            if text_lower in entity.text.lower() or entity.text.lower() in text_lower:
                return entity
        return None
    
    def _deduplicate_relationships(self, relationships: List[Relationship]) -> List[Relationship]:
        """Remove duplicate relationships"""
        seen = set()
        unique = []
        
        for rel in relationships:
            key = (rel.source_entity, rel.target_entity, rel.relationship_type)
            if key not in seen:
                seen.add(key)
                unique.append(rel)
        
        return unique


class TextSummarizer:
    """
    Extractive text summarization using TextRank algorithm
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.nlp = nlp_small
    
    def summarize(self, text: str, num_sentences: int = 5) -> str:
        """
        Generate extractive summary of text
        
        Args:
            text: Text to summarize
            num_sentences: Number of sentences in summary
        
        Returns:
            Summary text
        """
        if len(text) < 500:
            return text
        
        # Process with spaCy
        doc = self.nlp(text)
        
        # Extract sentences
        sentences = list(doc.sents)
        
        if len(sentences) <= num_sentences:
            return text
        
        # Calculate sentence scores based on word frequency
        word_freq = self._calculate_word_frequency(doc)
        sentence_scores = self._score_sentences(sentences, word_freq)
        
        # Select top sentences
        top_sentences = sorted(sentence_scores.items(), key=lambda x: x[1], reverse=True)[:num_sentences]
        top_sentences = sorted(top_sentences, key=lambda x: x[0])  # Sort by original order
        
        # Build summary
        summary = ' '.join([sentences[idx].text for idx, _ in top_sentences])
        
        return summary
    
    def _calculate_word_frequency(self, doc) -> Dict[str, float]:
        """Calculate normalized word frequencies"""
        word_freq = Counter()
        
        for token in doc:
            if not token.is_stop and not token.is_punct and token.is_alpha:
                word_freq[token.lemma_.lower()] += 1
        
        # Normalize
        max_freq = max(word_freq.values()) if word_freq else 1
        for word in word_freq:
            word_freq[word] /= max_freq
        
        return dict(word_freq)
    
    def _score_sentences(self, sentences, word_freq: Dict[str, float]) -> Dict[int, float]:
        """Score sentences based on word frequency"""
        scores = {}
        
        for idx, sent in enumerate(sentences):
            score = 0
            for token in sent:
                if token.lemma_.lower() in word_freq:
                    score += word_freq[token.lemma_.lower()]
            scores[idx] = score / max(len(sent.text.split()), 1)
        
        return scores
    
    def extract_key_phrases(self, text: str, num_phrases: int = 10) -> List[str]:
        """
        Extract key phrases using noun chunks and named entities
        
        Args:
            text: Text to analyze
            num_phrases: Number of phrases to extract
        
        Returns:
            List of key phrases
        """
        doc = self.nlp(text)
        
        # Collect noun chunks and named entities
        phrases = []
        
        # Add noun chunks
        for chunk in doc.noun_chunks:
            if len(chunk.text.split()) >= 2:  # At least 2 words
                phrases.append(chunk.text.lower())
        
        # Add named entities
        for ent in doc.ents:
            if len(ent.text) > 3:
                phrases.append(ent.text.lower())
        
        # Count frequencies
        phrase_freq = Counter(phrases)
        
        # Get top phrases
        top_phrases = [phrase for phrase, _ in phrase_freq.most_common(num_phrases)]
        
        return top_phrases


class ReadabilityAnalyzer:
    """
    Analyzes text readability using Flesch-Kincaid metrics
    """
    
    @staticmethod
    def flesch_kincaid_grade(text: str) -> float:
        """
        Calculate Flesch-Kincaid Grade Level
        
        Returns:
            Grade level (e.g., 8.5 = 8th-9th grade reading level)
        """
        # Count sentences, words, syllables
        sentences = re.split(r'[.!?]+', text)
        sentences = [s for s in sentences if s.strip()]
        
        if not sentences:
            return 0.0
        
        words = text.split()
        syllable_count = ReadabilityAnalyzer._count_syllables(text)
        
        # Flesch-Kincaid formula
        score = 0.39 * (len(words) / len(sentences)) + \
                11.8 * (syllable_count / len(words)) - 15.59
        
        return max(0, min(20, score))  # Cap between 0-20
    
    @staticmethod
    def _count_syllables(text: str) -> int:
        """Approximate syllable count"""
        text = text.lower()
        count = 0
        vowels = 'aeiou'
        
        for word in text.split():
            word_vowels = 0
            prev_is_vowel = False
            
            for char in word:
                if char in vowels:
                    if not prev_is_vowel:
                        word_vowels += 1
                    prev_is_vowel = True
                else:
                    prev_is_vowel = False
            
            # Add at least 1 syllable for short words
            count += max(1, word_vowels)
        
        return count


class NLPAnalyzer:
    """
    Main NLP analyzer orchestrating all components
    Removed sentiment analysis, replaced with intent classification
    Removed LDA, using NER and relationships for understanding
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.entity_recognizer = AgricultureNER()
        self.relationship_extractor = RelationshipExtractor()
        self.intent_classifier = IntentClassifier()
        self.summarizer = TextSummarizer()
        self.readability_analyzer = ReadabilityAnalyzer()
    
    def analyze_document(self, document: ProcessedDocument, 
                        keyword_matches: List[KeywordMatch] = None) -> NLPResult:
        """
        Perform complete NLP analysis on a document
        
        Args:
            document: ProcessedDocument object
            keyword_matches: Optional keyword matches for context
        
        Returns:
            NLPResult with all analysis
        """
        self.logger.info(f"Performing NLP analysis on {document.source_url}")
        
        text = document.cleaned_text
        
        # 1. Named Entity Recognition (includes agriculture-specific entities)
        entities = self.entity_recognizer.extract_entities(text, document.source_url)
        entities_by_type = self.entity_recognizer.get_entity_statistics(entities)
        
        # 2. Relationship Extraction
        relationships = self.relationship_extractor.extract_relationships(text, entities)
        
        # 3. Intent Classification (replaces sentiment analysis)
        intent = self.intent_classifier.classify(text)
        threat_score = self.intent_classifier.calculate_threat_score(intent, entities)
        
        # 4. Language and Readability
        detected_language = document.detected_language or "en"
        readability_score = self.readability_analyzer.flesch_kincaid_grade(text)
        avg_word_length = document.avg_word_length
        sentence_count = len(document.sentences)
        
        # 5. Summarization
        summary = self.summarizer.summarize(text, num_sentences=3)
        key_phrases = self.summarizer.extract_key_phrases(text, num_phrases=8)
        
        # 6. Extract threat keywords from matches
        threat_keywords = []
        if keyword_matches:
            threat_keywords = list(set([m.keyword for m in keyword_matches[:20]]))
        
        # Create result
        result = NLPResult(
            document_url=document.source_url,
            analyzed_at=datetime.now(),
            entities=entities,
            entities_by_type=entities_by_type,
            relationships=relationships,
            intent=intent,
            detected_language=detected_language,
            readability_score=readability_score,
            average_word_length=avg_word_length,
            sentence_count=sentence_count,
            threat_keywords=threat_keywords,
            threat_score=threat_score,
            summary=summary,
            key_phrases=key_phrases
        )
        
        self.logger.info(f"NLP analysis complete: {len(entities)} entities, "
                        f"{len(relationships)} relationships, "
                        f"Intent: {intent.intent} (conf: {intent.confidence:.2f}), "
                        f"Threat score: {threat_score:.1f}")
        
        return result
    
    def get_threat_assessment(self, result: NLPResult) -> Dict[str, Any]:
        """
        Generate threat assessment from NLP results
        
        Args:
            result: NLPResult object
        
        Returns:
            Threat assessment dictionary
        """
        assessment = {
            'overall_threat_level': 'LOW',
            'threat_score': result.threat_score,
            'detected_intent': result.intent.intent,
            'intent_confidence': result.intent.confidence,
            'risk_factors': [],
            'recommendations': []
        }
        
        # Determine threat level
        if result.threat_score >= 70:
            assessment['overall_threat_level'] = 'CRITICAL'
        elif result.threat_score >= 50:
            assessment['overall_threat_level'] = 'HIGH'
        elif result.threat_score >= 30:
            assessment['overall_threat_level'] = 'MEDIUM'
        
        # Add risk factors based on intent
        if result.intent.intent in ['credential_dump', 'data_breach_announcement']:
            assessment['risk_factors'].append(f"Document classified as {result.intent.intent} with {result.intent.confidence:.0%} confidence")
        
        if result.intent.intent == 'proprietary_data_sale':
            assessment['risk_factors'].append("Proprietary agricultural data being offered for sale")
        
        # Entity-based risk factors
        org_count = result.entities_by_type.get('ORG', 0)
        if org_count > 3:
            assessment['risk_factors'].append(f"Multiple organizations ({org_count}) mentioned - potential widespread impact")
        
        crop_count = result.entities_by_type.get('CROP', 0)
        if crop_count > 5:
            assessment['risk_factors'].append(f"Multiple crop types ({crop_count}) mentioned - broad agricultural impact")
        
        # Relationship-based risk factors
        if len(result.relationships) > 5:
            assessment['risk_factors'].append(f"Multiple entity relationships ({len(result.relationships)}) suggesting data correlation")
        
        # Check for specific relationship types
        if any(rel.relationship_type == 'leaked_from' for rel in result.relationships):
            assessment['risk_factors'].append("Direct evidence of data leakage identified")
        
        # Add recommendations
        if result.threat_score >= 50:
            assessment['recommendations'].append("Immediate investigation required")
            assessment['recommendations'].append("Reset credentials for affected systems")
        
        if result.intent.intent == 'credential_dump':
            assessment['recommendations'].append("Force password reset for all affected users")
            assessment['recommendations'].append("Enable multi-factor authentication immediately")
        
        if result.intent.intent == 'proprietary_data_sale':
            assessment['recommendations'].append("Initiate legal takedown process for dark web listings")
            assessment['recommendations'].append("Audit internal access logs for intellectual property")
        
        if any(rel.relationship_type == 'leaked_from' for rel in result.relationships):
            assessment['recommendations'].append("Verify data source and scope of leak")
        
        return assessment


# Standalone test function
def test_nlp_analyzer():
    """Test the NLP analysis module"""
    print("\n" + "="*60)
    print("TESTING NLP ANALYSIS MODULE")
    print("="*60)
    
    # Sample dark web content
    sample_text = """
    BREACH ALERT: AgriFarm Corporation Data Leak
    
    On March 15, 2024, a significant data breach occurred at AgriFarm Corp, 
    one of the largest agricultural technology companies. The leaked database 
    contains sensitive information including employee credentials, crop yield 
    predictions for 2024-2025, and proprietary algorithms like YieldPredict v2.
    
    The hacker known as "DarkHarvester" claims responsibility for the breach.
    "We accessed their main database server at 10.0.0.45 using compromised 
    admin credentials," the hacker stated. The stolen data includes:
    
    - 50,000+ user passwords (hashed and plaintext)
    - Soil composition analysis for 500+ farms
    - API keys for weather data services
    - Financial records totaling $2.5 million
    
    The leak was published on a dark web marketplace for 5 Bitcoin. Security 
    experts warn that this could lead to widespread agricultural espionage.
    
    Affected systems include the CropHealth monitoring platform and the 
    SmartIrrigation control system. Customers are advised to change their 
    passwords immediately.
    """
    
    # Create a simple processed document
    from preprocessor.data_cleaner import ProcessedDocument
    
    processed_doc = ProcessedDocument(
        source_url="http://darkweb.onion/agrifarm_breach",
        crawl_timestamp=datetime.now(),
        original_length=len(sample_text),
        cleaned_text=sample_text,
        cleaned_length=len(sample_text),
        tokens=sample_text.split()[:100],
        sentences=sample_text.split('.')[:10],
        emails=[],
        domains=[],
        ip_addresses=[],
        phone_numbers=[],
        credentials=[],
        agriculture_terms=[],
        word_count=len(sample_text.split()),
        unique_word_count=len(set(sample_text.split())),
        avg_word_length=5.0,
        special_char_ratio=0.05,
        detected_language='en',
        encoding='utf-8',
        content_hash='test_hash',
        normalized_hash='test_norm_hash'
    )
    
    # Initialize analyzer
    print("\n[1] Initializing NLP analyzer...")
    analyzer = NLPAnalyzer()
    
    # Analyze document
    print("\n[2] Analyzing document...")
    result = analyzer.analyze_document(processed_doc)
    
    # Display results
    print("\n[3] Named Entities Found:")
    for entity in result.entities[:10]:
        print(f"   • {entity.text} ({entity.label}) - confidence: {entity.confidence:.2f}")
    
    print(f"\n   Entity Statistics: {result.entities_by_type}")
    
    print("\n[4] Relationships Found:")
    for rel in result.relationships[:5]:
        print(f"   • {rel.source_entity} ({rel.source_type}) -> {rel.relationship_type} -> "
              f"{rel.target_entity} ({rel.target_type})")
    
    print("\n[5] Intent Classification (replaces sentiment):")
    print(f"   • Intent: {result.intent.intent}")
    print(f"   • Confidence: {result.intent.confidence:.2%}")
    if result.intent.all_scores:
        print(f"   • Top scores:")
        for intent, score in list(result.intent.all_scores.items())[:3]:
            print(f"     - {intent}: {score:.2%}")
    
    print(f"\n   • Threat Score: {result.threat_score:.1f}/100")
    
    print("\n[6] Readability:")
    print(f"   • Flesch-Kincaid Grade: {result.readability_score:.1f}")
    print(f"   • Avg Word Length: {result.average_word_length:.1f} chars")
    print(f"   • Sentence Count: {result.sentence_count}")
    
    print("\n[7] Key Phrases:")
    for phrase in result.key_phrases[:8]:
        print(f"   • {phrase}")
    
    print("\n[8] Summary:")
    print(f"   {result.summary[:200]}...")
    
    print("\n[9] Threat Assessment:")
    assessment = analyzer.get_threat_assessment(result)
    print(f"   • Threat Level: {assessment['overall_threat_level']}")
    print(f"   • Detected Intent: {assessment['detected_intent']}")
    print(f"   • Risk Factors: {assessment['risk_factors']}")
    print(f"   • Recommendations: {assessment['recommendations']}")
    
    print("\n" + "="*60)
    print("NLP ANALYSIS MODULE TEST COMPLETE")
    print("="*60)
    
    return True


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    test_nlp_analyzer()