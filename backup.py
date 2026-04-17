#keyword.py
"""
Keywords Detection Module for Dark Web Agriculture Monitor
Handles pattern matching, fuzzy matching, and context-aware keyword detection
"""

import os
import sys
import re
import json
import math
from datetime import datetime
from typing import List, Dict, Set, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from collections import Counter, defaultdict
from difflib import SequenceMatcher

import regex as re2  # Advanced regex with fuzzy matching
from fuzzywuzzy import fuzz, process

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import config_manager
from preprocessor.data_cleaner import ProcessedDocument, ExtractedEntity
import logging


@dataclass
class KeywordMatch:
    """Data structure for a keyword match"""
    keyword: str
    matched_text: str
    match_type: str  # exact, fuzzy, regex, contextual
    confidence: float  # 0-1 confidence score
    position: int  # Character position in text
    context: str  # Surrounding text (50 chars each side)
    category: str  # domain, proprietary, credential, agriculture
    source_url: str
    similarity_score: float = 1.0  # For fuzzy matches
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DocumentMatchResult:
    """Complete match results for a document"""
    document_url: str
    processed_at: datetime
    total_matches: int
    matches_by_category: Dict[str, int]
    high_confidence_matches: List[KeywordMatch]
    medium_confidence_matches: List[KeywordMatch]
    low_confidence_matches: List[KeywordMatch]
    overall_risk_score: float  # 0-100 risk score
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        data['processed_at'] = self.processed_at.isoformat()
        data['high_confidence_matches'] = [m.to_dict() for m in self.high_confidence_matches]
        data['medium_confidence_matches'] = [m.to_dict() for m in self.medium_confidence_matches]
        data['low_confidence_matches'] = [m.to_dict() for m in self.low_confidence_matches]
        return data


class PatternMatcher:
    """
    Handles exact and regex pattern matching for keywords
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Compile patterns for performance
        self.compiled_patterns = {}
        self._compile_keyword_patterns()
    
    def _compile_keyword_patterns(self):
        """Compile regex patterns for all keywords"""
        keywords = config_manager.get_keywords()
        
        # Compile domain patterns
        domains = keywords.get('domains', [])
        if domains:
            domain_pattern = r'\b(?:' + '|'.join(re.escape(d) for d in domains) + r')\b'
            self.compiled_patterns['domains'] = re.compile(domain_pattern, re.IGNORECASE)
        
        # Compile proprietary term patterns
        proprietary = keywords.get('proprietary_terms', [])
        if proprietary:
            proprietary_pattern = r'\b(?:' + '|'.join(re.escape(p) for p in proprietary) + r')\b'
            self.compiled_patterns['proprietary'] = re.compile(proprietary_pattern, re.IGNORECASE)
        
        # Compile agriculture term patterns
        agriculture = keywords.get('agriculture_terms', [])
        if agriculture:
            agriculture_pattern = r'(?:' + '|'.join(r'.*?'.join(map(re.escape, term.split()))for term in agriculture) + r')'
            self.compiled_patterns['agriculture'] = re.compile(agriculture_pattern, re.IGNORECASE)
        
        # Compile credential pattern
        credentials = keywords.get('credential_patterns', [])
        if credentials:
            credential_pattern = r'(?:' + '|'.join(re.escape(c) for c in credentials) + r')\s*\S+'
            self.compiled_patterns['credentials'] = re.compile(credential_pattern, re.IGNORECASE)
        
        # Compile sensitive data patterns
        sensitive = keywords.get('sensitive_data_types', [])
        if sensitive:
            sensitive_pattern = r'\b(?:' + '|'.join(re.escape(s) for s in sensitive) + r')\b'
            self.compiled_patterns['sensitive'] = re.compile(sensitive_pattern, re.IGNORECASE)
        
        self.logger.info(f"Compiled patterns for {len(self.compiled_patterns)} categories")
    
    def exact_match(self, text: str, keyword: str) -> List[Tuple[int, str]]:
        """
        Find exact matches of keyword in text
        
        Args:
            text: Text to search
            keyword: Keyword to find
        
        Returns:
            List of (position, matched_context) tuples
        """
        matches = []
        pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
        
        for match in pattern.finditer(text):
            # Get context (50 chars before and after)
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 50)
            context = text[start:end]
            matches.append((match.start(), context))
        
        return matches
    
    def regex_match_category(self, text: str, category: str) -> List[Tuple[str, int, str]]:
        """
        Match all keywords in a category using regex
        
        Args:
            text: Text to search
            category: Category name (domains, proprietary, agriculture, etc.)
        
        Returns:
            List of (matched_keyword, position, context) tuples
        """
        matches = []
        
        if category not in self.compiled_patterns:
            return matches
        
        pattern = self.compiled_patterns[category]
        
        for match in pattern.finditer(text):
            matched_text = match.group()
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 50)
            context = text[start:end]
            matches.append((matched_text, match.start(), context))
        
        return matches
    
    def detect_credential_leaks(self, text: str, extracted_credentials: List[ExtractedEntity]) -> List[KeywordMatch]:
        """
        Detect credential leaks by combining pattern matching and extracted entities
        
        Args:
            text: Original text
            extracted_credentials: Credentials from entity extraction
        
        Returns:
            List of credential keyword matches
        """
        matches = []
        
        # First, use regex pattern matching
        credential_matches = self.regex_match_category(text, 'credentials')
        
        for matched_text, position, context in credential_matches:
            match = KeywordMatch(
                keyword='credential_pattern',
                matched_text=matched_text[:100],  # Limit length
                match_type='regex',
                confidence=0.85,
                position=position,
                context=context,
                category='credential',
                source_url='',
                similarity_score=1.0
            )
            matches.append(match)
        
        # Also include extracted credentials from preprocessing
        for cred in extracted_credentials:
            match = KeywordMatch(
                keyword=cred.entity_type,
                matched_text=cred.value,
                match_type='extracted',
                confidence=cred.confidence,
                position=cred.position,
                context=cred.context,
                category='credential',
                source_url=cred.source_url,
                similarity_score=1.0
            )
            matches.append(match)
        

        # Deduplicate matches
        unique_matches = {}
        for m in matches:
            key = (m.matched_text.lower(), m.position, m.category)          # same password detected twice --> inflates risk score
            
            # Keep highest confidence version
            if key not in unique_matches or m.confidence > unique_matches[key].confidence:
                unique_matches[key] = m

        # Convert back to list
        matches = list(unique_matches.values())
        
        return matches


class FuzzyMatcher:
    """
    Handles fuzzy string matching for misspelled or obfuscated keywords
    """
    
    def __init__(self, threshold: int = 80):
        """
        Initialize fuzzy matcher
        
        Args:
            threshold: Minimum similarity score (0-100) for a match
        """
        self.threshold = threshold
        self.logger = logging.getLogger(__name__)
        
        # Build keyword index for fuzzy matching
        self.keywords_index = self._build_keyword_index()
    
    def _build_keyword_index(self) -> Dict[str, List[str]]:
        """Build index of keywords for fuzzy matching"""
        keywords = config_manager.get_keywords()
        index = defaultdict(list)
        
        for category, keyword_list in keywords.items():
            for keyword in keyword_list:
                # Add original keyword
                index[category].append(keyword.lower())
                # Add variations (e.g., remove spaces)
                if ' ' in keyword:
                    index[category].append(keyword.lower().replace(' ', ''))
                # Add with common substitutions (e.g., 0 for o)
                index[category].append(keyword.lower().replace('o', '0'))
                index[category].append(keyword.lower().replace('i', '1'))
        
        return index
    
    def fuzzy_match_text(self, text: str, category: str = None) -> List[Tuple[str, str, int, int]]:
        """
        Find fuzzy matches in text
        
        Args:
            text: Text to search
            category: Specific category to search (None for all)
        
        Returns:
            List of (matched_keyword, category, position, similarity_score)
        """
        matches = []
        text_lower = text.lower()
        words = re.findall(r'\b\w+\b', text_lower)
        
        # Process words in chunks for efficiency
        word_chunks = self._create_word_chunks(words)
        
        categories_to_search = [category] if category else self.keywords_index.keys()
        
        for cat in categories_to_search:
            keywords = self.keywords_index.get(cat, [])
            
            for chunk in word_chunks:
                for keyword in keywords:
                    # Skip very short keywords
                    if len(keyword) < 3:
                        continue
                    
                    # Calculate similarity
                    similarity = fuzz.ratio(chunk, keyword)
                    
                    if similarity >= self.threshold:
                        # Find position in original text
                        position = text_lower.find(chunk)
                        if position >= 0:
                            matches.append((keyword, cat, position, similarity))
        
        # Remove duplicates (keep highest similarity)
        unique_matches = {}
        for keyword, cat, pos, sim in matches:
            key = (keyword, pos)
            if key not in unique_matches or sim > unique_matches[key][3]:
                unique_matches[key] = (keyword, cat, pos, sim)
        
        return list(unique_matches.values())
    
    def _create_word_chunks(self, words: List[str], max_chunk_size: int = 4) -> List[str]:
        """
        Create chunks of consecutive words for fuzzy matching
        
        Args:
            words: List of words
            max_chunk_size: Maximum number of words in a chunk
        
        Returns:
            List of word chunks as strings
        """
        chunks = []
        
        # Single words
        chunks.extend(words)
        
        # Multi-word chunks
        for size in range(2, max_chunk_size + 1):
            for i in range(len(words) - size + 1):
                chunk = ' '.join(words[i:i+size])
                chunks.append(chunk)
        
        return chunks
    
    def fuzzy_match_domain(self, text: str, target_domains: List[str]) -> List[Tuple[str, int, float]]:
        """
        Specialized fuzzy matching for domain names (handles typosquatting)
        
        Args:
            text: Text to search
            target_domains: List of target domains to match
        
        Returns:
            List of (matched_domain, position, similarity_score)
        """
        matches = []
        
        # Extract potential domain patterns
        domain_pattern = re.compile(r'\b[a-zA-Z0-9][a-zA-Z0-9\-]{1,62}\.[a-zA-Z]{2,}\b')
        
        for match in domain_pattern.finditer(text.lower()):
            potential_domain = match.group()
            position = match.start()
            
            for target in target_domains:
                # Check for exact match
                if potential_domain == target.lower():
                    matches.append((target, position, 100.0))
                    continue
                
                # Check for typosquatting
                similarity = fuzz.ratio(potential_domain, target.lower())
                
                # Check for homograph attacks (e.g., rn vs m)
                homograph_score = self._check_homographs(potential_domain, target.lower())
                similarity = max(similarity, homograph_score)
                
                if similarity >= self.threshold:
                    matches.append((target, position, similarity))
        
        # Remove duplicates
        unique_matches = {}
        for domain, pos, sim in matches:
            if (domain, pos) not in unique_matches or sim > unique_matches[(domain, pos)][2]:
                unique_matches[(domain, pos)] = (domain, pos, sim)
        
        return list(unique_matches.values())
    
    def _check_homographs(self, text: str, target: str) -> float:
        """
        Check for homograph attacks (character substitutions)
        
        Args:
            text: Text to check
            target: Target string
        
        Returns:
            Similarity score
        """
        # Common homograph substitutions
        homograph_map = {
            'r': 'rn',
            'rn': 'r',
            'm': 'rn',
            'vv': 'w',
            'w': 'vv',
            '0': 'o',
            'o': '0',
            '1': 'l',
            'l': '1',
            '5': 's',
            's': '5'
        }
        
        best_score = fuzz.ratio(text, target)
        
        # Try substitutions
        for orig, sub in homograph_map.items():
            modified = text.replace(orig, sub)
            score = fuzz.ratio(modified, target)
            best_score = max(best_score, score)
        
        return best_score


class ContextAnalyzer:
    """
    Analyzes context around keyword matches to determine true positives
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Context indicators that increase confidence
        self.positive_indicators = [
            'leak', 'breach', 'exposed', 'dump', 'database', 'password',
            'credentials', 'confidential', 'private', 'secret', 'cracked',
            'hacked', 'compromised', 'stolen', 'dark web', 'onion'
        ]
        
        # Context indicators that decrease confidence
        self.negative_indicators = [
            'sample', 'example', 'demo', 'test', 'fake', 'dummy',
            'placeholder', 'not real', 'for demonstration'
        ]
    
    def analyze_match(self, match: KeywordMatch, full_text: str) -> float:
        """
        Analyze context around a match to adjust confidence
        
        Args:
            match: Keyword match to analyze
            full_text: Full document text
        
        Returns:
            Adjusted confidence score (0-1)
        """
        confidence = match.confidence
        
        # Get expanded context (200 chars around match)
        start = max(0, match.position - 200)
        end = min(len(full_text), match.position + 200)
        context = full_text[start:end].lower()
        
        # Check for positive indicators
        positive_count = sum(1 for ind in self.positive_indicators if ind in context)
        if positive_count > 0:
            confidence += min(0.2, positive_count * 0.05)
        
        # Check for negative indicators
        negative_count = sum(1 for ind in self.negative_indicators if ind in context)
        if negative_count > 0:
            confidence -= min(0.3, negative_count * 0.1)
        
        # Penalize matches in code blocks or comments
        if '<code>' in context or '```' in context:
            confidence *= 0.8
        
        # Boost matches near extracted credentials
        if match.category == 'credential' and 'password' in context:
            confidence = min(1.0, confidence + 0.1)
        
        return max(0.0, min(1.0, confidence))


class KeywordDetector:
    """
    Main keyword detection orchestrator
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.pattern_matcher = PatternMatcher()
        self.fuzzy_matcher = FuzzyMatcher(threshold=65)
        self.context_analyzer = ContextAnalyzer()
        
        # Category weights for risk scoring
        self.category_weights = {
            'credential': 1.0,
            'proprietary': 0.9,
            'domain': 0.6,
            'sensitive': 0.8,
            'agriculture': 0.5,
            'email': 0.4
        }
        
        # Load configuration
        self.keywords = config_manager.get_keywords()


    
    def detect_matches(self, document: ProcessedDocument) -> DocumentMatchResult:
        """
        Detect all keyword matches in a processed document
        
        Args:
            document: ProcessedDocument object
        
        Returns:
            DocumentMatchResult with all matches
        """
        self.logger.info(f"Detecting keywords in {document.source_url}")
        
        all_matches = []
        
        # Method 1: Exact pattern matching
        exact_matches = self._exact_pattern_matches(document)
        all_matches.extend(exact_matches)
        
        # Method 2: Fuzzy matching
        fuzzy_matches = self._fuzzy_matches(document)
        all_matches.extend(fuzzy_matches)
        
        # Method 3: Extracted entity matching
        entity_matches = self._entity_matches(document)
        all_matches.extend(entity_matches)
        
        # Method 4: Credential detection
        credential_matches = self.pattern_matcher.detect_credential_leaks(
            document.cleaned_text, 
            document.credentials
        )
        for match in credential_matches:
            match.source_url = document.source_url
        all_matches.extend(credential_matches)
        

         #Deduplication matches
        all_matches = self._deduplicate_matches(all_matches)

        self.logger.info(f"After deduplication: {len(all_matches)} matches")


        # Analyze context and adjust confidence
        for match in all_matches:
            original_confidence = match.confidence
            match.confidence = self.context_analyzer.analyze_match(match, document.cleaned_text)
            if original_confidence != match.confidence:
                self.logger.debug(f"Adjusted confidence: {original_confidence:.2f} -> {match.confidence:.2f}")
        
        # Categorize matches by confidence
        high_confidence = [m for m in all_matches if m.confidence >= 0.8]
        medium_confidence = [m for m in all_matches if 0.5 <= m.confidence < 0.8]
        low_confidence = [m for m in all_matches if m.confidence < 0.5]
        
        # Calculate matches by category
        matches_by_category = defaultdict(int)
        for match in all_matches:
            matches_by_category[match.category] += 1
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(all_matches, document)
        
        # Create result object
        result = DocumentMatchResult(
            document_url=document.source_url,
            processed_at=datetime.now(),
            total_matches=len(all_matches),
            matches_by_category=dict(matches_by_category),
            high_confidence_matches=high_confidence,
            medium_confidence_matches=medium_confidence,
            low_confidence_matches=low_confidence,
            overall_risk_score=risk_score
        )
        
        self.logger.info(f"Found {len(all_matches)} matches (High: {len(high_confidence)}, "
                        f"Risk score: {risk_score:.1f})")
        
        return result
    
    def _deduplicate_matches(self, matches: List[KeywordMatch]) -> List[KeywordMatch]:
        unique_matches = []

        for match in matches:
            duplicate_found = False

            for existing in unique_matches:
                if self._is_similar(match, existing):
                    duplicate_found = True
                    
                    # Keep higher confidence
                    if match.confidence > existing.confidence:
                        unique_matches.remove(existing)
                        unique_matches.append(match)
                    break

            if not duplicate_found:
                unique_matches.append(match)

        return unique_matches
    

    def _is_similar(self, m1: KeywordMatch, m2: KeywordMatch) -> bool:
        """Check if two matches are similar"""
        if m1.category != m2.category:
            return False

        similarity = fuzz.ratio(m1.matched_text.lower(), m2.matched_text.lower())
        
        return similarity > 85 and abs(m1.position - m2.position) < 50

    def _exact_pattern_matches(self, document: ProcessedDocument) -> List[KeywordMatch]:
        """Find exact pattern matches"""
        matches = []
        text = document.cleaned_text
        
        # Check each category
        categories = ['domains', 'proprietary', 'agriculture', 'sensitive']
        
        for category in categories:
            category_matches = self.pattern_matcher.regex_match_category(text, category)
            
            for matched_text, position, context in category_matches:
                # Map category to match category
                match_category = category.rstrip('s')  # Remove plural
                
                # Determine confidence based on category
                confidence = {
                    'domain': 0.9,
                    'proprietary': 0.95,
                    'agriculture': 0.7,
                    'sensitive': 0.85
                }.get(match_category, 0.8)
                
                match = KeywordMatch(
                    keyword=matched_text,
                    matched_text=matched_text,
                    match_type='exact',
                    confidence=confidence,
                    position=position,
                    context=context,
                    category=match_category,
                    source_url=document.source_url,
                    similarity_score=1.0
                )
                matches.append(match)

        # Extra: word-level agriculture matching
        for term in self.keywords.get('agriculture_terms', []):
            words = term.lower().split()
            
            for word in words:
                if len(word) < 4:
                    continue
                
                pattern = re.compile(r'\b' + re.escape(word) + r'\b', re.IGNORECASE)
                
                for match in pattern.finditer(text):
                    start = max(0, match.start() - 50)
                    end = min(len(text), match.end() + 50)
                    context = text[start:end]
                    
                    matches.append(KeywordMatch(
                        keyword=word,
                        matched_text=match.group(),
                        match_type='partial',
                        confidence=0.6,
                        position=match.start(),
                        context=context,
                        category='agriculture',
                        source_url=document.source_url,
                        similarity_score=0.6
                    ))        
        
        return matches
    
    def _fuzzy_matches(self, document: ProcessedDocument) -> List[KeywordMatch]:
        """Find fuzzy matches"""
        matches = []
        text = document.cleaned_text
        
        # Check all categories
        categories = ['domains', 'proprietary_terms', 'agriculture_terms']
        
        for category in categories:
            fuzzy_results = self.fuzzy_matcher.fuzzy_match_text(text, category)
            
            for keyword, cat, position, similarity in fuzzy_results:
                # Get context
                start = max(0, position - 50)
                end = min(len(text), position + 50)
                context = text[start:end]
                
                # Map category
                match_category = cat.rstrip('s').rstrip('_terms')
                
                # Confidence based on similarity score
                confidence = similarity / 100.0 * 0.8  # Cap at 0.8 for fuzzy matches
                
                match = KeywordMatch(
                    keyword=keyword,
                    matched_text=text[position:position+len(keyword)],
                    match_type='fuzzy',
                    confidence=confidence,
                    position=position,
                    context=context,
                    category=match_category,
                    source_url=document.source_url,
                    similarity_score=similarity / 100.0
                )
                matches.append(match)
        
        # Special domain fuzzy matching (typosquatting detection)
        if 'domains' in self.keywords:
            domain_matches = self.fuzzy_matcher.fuzzy_match_domain(
                text, 
                self.keywords['domains']
            )
            
            for domain, position, similarity in domain_matches:
                start = max(0, position - 50)
                end = min(len(text), position + 50)
                context = text[start:end]
                
                match = KeywordMatch(
                    keyword=domain,
                    matched_text=text[position:position+len(domain)],
                    match_type='fuzzy_domain',
                    confidence=similarity / 100.0 * 0.85,
                    position=position,
                    context=context,
                    category='domain',
                    source_url=document.source_url,
                    similarity_score=similarity / 100.0
                )
                matches.append(match)
        
        return matches
    
    def _entity_matches(self, document: ProcessedDocument) -> List[KeywordMatch]:
        """Convert extracted entities to keyword matches"""
        matches = []
        
        # Map entity types to categories
        entity_mapping = {
            'email': ('email', 0.85),
            'domain': ('domain', 0.9),
            'ip_address': ('ip', 0.7),
            'phone_number': ('phone', 0.6)
        }
        
        for entity_type, (category, base_confidence) in entity_mapping.items():
            entities = getattr(document, f"{entity_type}s", [])
            
            for entity in entities:
                # Check if domain matches target domains
                if entity_type == 'domain' and 'domains' in self.keywords:
                    if entity.value in self.keywords['domains']:
                        base_confidence = 0.95
                
                match = KeywordMatch(
                    keyword=entity.value,
                    matched_text=entity.value,
                    match_type='extracted_entity',
                    confidence=base_confidence,
                    position=entity.position,
                    context=entity.context,
                    category=category,
                    source_url=document.source_url,
                    similarity_score=1.0
                )
                matches.append(match)
        
        return matches
    
    def _calculate_risk_score(self, matches: List[KeywordMatch], document: ProcessedDocument) -> float:
        """
        Calculate overall risk score for the document
        
        Args:
            matches: List of keyword matches
            document: Processed document
        
        Returns:
            Risk score (0-100)
        """
        if not matches:
            return 0.0
        
        # Base score from matches
        weighted_score = 0.0
        total_weight = 0.0
        
        for match in matches:
            weight = self.category_weights.get(match.category, 0.5)
            weighted_score += match.confidence * weight
            total_weight += weight
        
        match_score = (weighted_score / total_weight) * 100 if total_weight > 0 else 0
        
        # Adjust based on document characteristics
        adjustment = 0
        
        # More content = potentially more risk
        if document.word_count > 1000:
            adjustment += 5
        elif document.word_count > 500:
            adjustment += 2
        
        # Penalize if only low confidence matches
        high_conf_ratio = len([m for m in matches if m.confidence >= 0.8]) / len(matches)
        if high_conf_ratio < 0.2:
            adjustment -= 10
        
        # Boost if credentials found
        if any(m.category == 'credential' for m in matches):
            adjustment += 15
        
        # Ensure score is within bounds
        risk_score = min(100, max(0, match_score + adjustment))
        
        return risk_score
    
    def generate_alert_summary(self, result: DocumentMatchResult) -> Dict[str, Any]:
        """
        Generate a summary for alerting
        
        Args:
            result: DocumentMatchResult
        
        Returns:
            Alert summary dictionary
        """
        alert_level = 'HIGH' if result.overall_risk_score >= 70 else \
                     'MEDIUM' if result.overall_risk_score >= 40 else 'LOW'
        
        summary = {
            'alert_level': alert_level,
            'risk_score': result.overall_risk_score,
            'source_url': result.document_url,
            'timestamp': result.processed_at.isoformat(),
            'total_matches': result.total_matches,
            'high_confidence_count': len(result.high_confidence_matches),
            'critical_findings': []
        }
        
        # Add high confidence credentials
        for match in result.high_confidence_matches[:10]:
            if match.category == 'credential':
                summary['critical_findings'].append({
                    'type': match.keyword,
                    'value': match.matched_text,
                    'context': match.context[:200]
                })
        
        # Add proprietary term matches
        for match in result.high_confidence_matches[:5]:
            if match.category == 'proprietary':
                summary['critical_findings'].append({
                    'type': 'Proprietary Data',
                    'value': match.keyword,
                    'context': match.context[:200]
                })
        
        return summary


# Standalone test function
def test_keyword_detector():
    """Test the keyword detection module"""
    print("\n" + "="*60)
    print("TESTING KEYWORD DETECTION MODULE")
    print("="*60)
    
    # Create a sample processed document
    from preprocessor.data_cleaner import DocumentProcessor
    
    sample_content = """
    ===== DARK WEB LEAK - AGRIFARM DATA =====
    
    [Database Dump] - AgriFarm Corp - March 2024
    
    EMAILS:
    admin@agrifarm.com
    ceo@agrifarm.com
    security@agrifarm.com
    
    CREDENTIALS FOUND:
    password: Harvest2024!Secure
    api_key: AKIAIOSFODNN7EXAMPLE
    database_url: postgresql://agriuser:P@ssw0rd123@db.agrifarm.com:5432/agridb
    
    PROPRIETARY DATA:
    Our YieldPredict v2 algorithm shows 25% increase in crop yield.
    The SoilSense Algorithm parameters: pH=6.5, N=150ppm, P=30ppm.
    
    INTERNAL DOCUMENTS:
    Irrigation schedules for Q2 2024 are attached.
    Fertilizer formula F-2024-A: 20-10-10 NPK + micronutrients.
    
    SAMPLE OF LEAKED DATA:
    Employee SSN: 123-45-6789, 987-65-4321
    Credit Card: 4111-1111-1111-1111
    
    This is a real data breach, not a test or example.
    """
    
    # Process the document
    print("\n[1] Processing sample document...")
    processor = DocumentProcessor()
    processed = processor.process_document(sample_content, "http://darkweb.onion/agrifarm_leak")
    
    # Initialize detector
    print("\n[2] Initializing keyword detector...")
    detector = KeywordDetector()
    
    # Detect matches
    print("\n[3] Detecting keyword matches...")
    result = detector.detect_matches(processed)
    
    # Display results
    print("\n[4] Detection Results:")
    print(f"   • Total matches: {result.total_matches}")
    print(f"   • Matches by category: {result.matches_by_category}")
    print(f"   • Overall risk score: {result.overall_risk_score:.1f}/100")
    
    print(f"\n   High Confidence Matches ({len(result.high_confidence_matches)}):")
    for match in result.high_confidence_matches[:5]:
        print(f"     - [{match.category.upper()}] {match.keyword}")
        print(f"       Confidence: {match.confidence:.2f}")
        print(f"       Context: {match.context[:100]}...")
    
    print(f"\n   Medium Confidence Matches ({len(result.medium_confidence_matches)}):")
    for match in result.medium_confidence_matches[:3]:
        print(f"     - [{match.category}] {match.keyword} (conf: {match.confidence:.2f})")
    
    # Generate alert summary
    print("\n[5] Alert Summary:")
    alert = detector.generate_alert_summary(result)
    print(f"   • Alert Level: {alert['alert_level']}")
    print(f"   • Risk Score: {alert['risk_score']}")
    print(f"   • Critical Findings: {len(alert['critical_findings'])}")
    
    for finding in alert['critical_findings'][:3]:
        print(f"     - {finding['type']}: {finding['value']}")
    
    print("\n" + "="*60)
    print("KEYWORD DETECTION MODULE TEST COMPLETE")
    print("="*60)
    
    return True


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    test_keyword_detector()

# It reads text from dark web
# Finds important keywords
# Detects misspelled or hidden keywords
# Understand context (is it real leak or just example)
# Calculate a risk score
# Generate an alert


#analyzer.py
"""
NLP Analysis Module for Dark Web Agriculture Monitor
Handles semantic analysis, named entity recognition, topic modeling, and relationship extraction
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
from textblob import TextBlob
from gensim import corpora, models
from gensim.models import LdaModel, CoherenceModel
import numpy as np

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
    os.system("python -m spacy download en_core_web_lg")
    nlp_small = spacy.load("en_core_web_sm")
    nlp_large = spacy.load("en_core_web_lg")


@dataclass
class NamedEntity:
    """Data structure for named entities"""
    text: str
    label: str  # PERSON, ORG, GPE, DATE, etc.
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
class TopicInfo:
    """Data structure for topic modeling results"""
    topic_id: int
    topic_words: List[str]
    topic_weights: List[float]
    coherence_score: float
    dominant_in_document: bool
    
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
    
    # Sentiment analysis
    sentiment_polarity: float  # -1 to 1
    sentiment_subjectivity: float  # 0 to 1
    sentiment_label: str  # positive, negative, neutral
    
    # Language and readability
    detected_language: str
    readability_score: float  # Flesch-Kincaid score
    average_word_length: float
    sentence_count: int
    
    # Topic modeling
    topics: List[TopicInfo]
    dominant_topic: int
    
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
        data['topics'] = [t.to_dict() for t in self.topics]
        return data


class NamedEntityRecognizer:
    """
    Advanced named entity recognition using spaCy
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.nlp = nlp_small
        
        # Custom entity patterns for agriculture domain
        self._add_custom_patterns()
        
        # Entity type mapping for display
        self.entity_labels = {
            'PERSON': 'Person Name',
            'ORG': 'Organization',
            'GPE': 'Location',
            'DATE': 'Date/Time',
            'MONEY': 'Monetary Value',
            'PRODUCT': 'Product',
            'EVENT': 'Event',
            'LAW': 'Law/Regulation',
            'PERCENT': 'Percentage',
            'QUANTITY': 'Quantity'
        }
    
    def _add_custom_patterns(self):
        """Add custom entity patterns for agriculture and dark web contexts"""
        # Create patterns for agriculture-specific entities
        patterns = [
            {"label": "CROP", "pattern": [{"LOWER": {"IN": ["corn", "wheat", "soybean", "rice", "cotton"]}}]},
            {"label": "FERTILIZER", "pattern": [{"LOWER": {"IN": ["nitrogen", "phosphorus", "potassium", "npk"]}}]},
            {"label": "DARK_WEB_SITE", "pattern": [{"LOWER": {"REGEX": r".*\.onion"}}]},
            {"label": "CREDENTIAL", "pattern": [{"LOWER": {"IN": ["password", "api_key", "secret"]}}]},
        ]
        
        # Add patterns to pipeline if using EntityRuler
        if "entity_ruler" not in self.nlp.pipe_names:
            ruler = self.nlp.add_pipe("entity_ruler", before="ner")
            ruler.add_patterns(patterns)
    
    def extract_entities(self, text: str, source_url: str = "") -> List[NamedEntity]:
        """
        Extract named entities from text
        
        Args:
            text: Text to analyze
            source_url: Source URL for reference
        
        Returns:
            List of named entities
        """
        self.logger.debug(f"Extracting named entities from {source_url}")
        
        # Process with spaCy
        doc = self.nlp(text[:1000000])  # Limit to 1M chars for performance
        
        entities = []
        
        for ent in doc.ents:
            # Filter out very short or low-confidence entities
            if len(ent.text) < 2:
                continue
            
            # Get context (50 chars around entity)
            start = max(0, ent.start_char - 50)
            end = min(len(text), ent.end_char + 50)
            context = text[start:end]
            
            # Calculate confidence (spaCy doesn't provide confidence, so we estimate)
            confidence = self._estimate_entity_confidence(ent)
            
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
    
    def _estimate_entity_confidence(self, ent) -> float:
        """Estimate confidence for extracted entity"""
        # Longer entities are generally more reliable
        length_boost = min(0.2, len(ent.text) / 100)
        
        # Certain entity types are more reliable
        type_confidence = {
            'DATE': 0.95,
            'PERCENT': 0.95,
            'MONEY': 0.9,
            'PERSON': 0.85,
            'ORG': 0.8,
            'GPE': 0.85,
            'PRODUCT': 0.7
        }.get(ent.label_, 0.75)
        
        return min(0.99, type_confidence + length_boost)
    
    def get_entity_statistics(self, entities: List[NamedEntity]) -> Dict[str, int]:
        """Get statistics about entity types"""
        stats = Counter()
        for entity in entities:
            stats[entity.label] += 1
        return dict(stats)


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
                ('exposed', 'nsubj', 'pobj')
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
        
        doc = self.nlp(text[:500000])  # Limit for performance
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
                relationship_type=verb,  # dynamic
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


class SentimentAnalyzer:
    """
    Sentiment analysis for threat assessment
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Threat indicators for dark web context
        self.threat_indicators = {
            'high': ['breach', 'leak', 'dump', 'exposed', 'hacked', 'cracked', 'stolen'],
            'medium': ['database', 'credentials', 'passwords', 'access', 'login'],
            'low': ['sample', 'example', 'test', 'demo']
        }
    
    def analyze_sentiment(self, text: str) -> Tuple[float, float, str]:
        """
        Analyze sentiment polarity and subjectivity
        
        Args:
            text: Text to analyze
        
        Returns:
            Tuple of (polarity, subjectivity, label)
        """
        blob = TextBlob(text[:50000])  # Limit for performance
        
        polarity = blob.sentiment.polarity  # -1 (negative) to 1 (positive)
        subjectivity = blob.sentiment.subjectivity  # 0 (objective) to 1 (subjective)
        
        # Determine sentiment label
        if polarity > 0.1:
            label = 'positive'
        elif polarity < -0.1:
            label = 'negative'
        else:
            label = 'neutral'
        
        self.logger.debug(f"Sentiment: {label} (polarity={polarity:.2f})")
        return polarity, subjectivity, label
    
    def calculate_threat_score(self, text: str) -> float:
        """
        Calculate threat score based on keyword presence
        
        Args:
            text: Text to analyze
        
        Returns:
            Threat score (0-100)
        """
        text_lower = text.lower()
        score = 0

        
        
        found_keywords = set()

        for level, keywords in self.threat_indicators.items():
            for keyword in keywords:
                if keyword in text_lower:
                    found_keywords.add(keyword)

        for keyword in found_keywords:
            if keyword in self.threat_indicators['high']:
                score += 15
            elif keyword in self.threat_indicators['medium']:
                score += 7
            else:
                score += 2
        
        # Cap at 100
        return min(100, score)


class TopicModeler:
    """
    Topic modeling using LDA (Latent Dirichlet Allocation)
    """
    
    def __init__(self, num_topics: int = 5):
        self.logger = logging.getLogger(__name__)
        self.num_topics = num_topics
        self.lda_model = None
        self.dictionary = None
        self.corpus = None
        
        # Predefined agriculture topics for reference
        self.agriculture_topics = {
            'crop_data': ['yield', 'harvest', 'crop', 'planting', 'season', 'forecast'],
            'soil_info': ['soil', 'composition', 'nitrogen', 'ph', 'moisture', 'fertility'],
            'credential_leak': ['password', 'login', 'api_key', 'secret', 'token', 'database'],
            'supply_chain': ['supply', 'logistics', 'inventory', 'shipping', 'warehouse'],
            'financial': ['price', 'market', 'cost', 'payment', 'transaction', 'credit']
        }
    
    def train_model(self, documents: List[str]):
        """
        Train LDA model on a collection of documents
        
        Args:
            documents: List of document texts
        """
        self.logger.info(f"Training LDA model on {len(documents)} documents")
        
        # Preprocess documents
        processed_docs = [self._preprocess_text(doc) for doc in documents]
        
        # Create dictionary and corpus
        self.dictionary = corpora.Dictionary(processed_docs)
        self.dictionary.filter_extremes(no_below=1, no_above=0.5)
        self.corpus = [self.dictionary.doc2bow(doc) for doc in processed_docs]
        
        # Train LDA model
        self.lda_model = LdaModel(
            corpus=self.corpus,
            id2word=self.dictionary,
            num_topics=self.num_topics,
            passes=10,
            random_state=42,
            alpha='auto',
            eta='auto'
        )
        
        # Calculate coherence score
        coherence_model = CoherenceModel(
            model=self.lda_model,
            texts=processed_docs,
            dictionary=self.dictionary,
            coherence='c_v'
        )
        coherence_score = coherence_model.get_coherence()
        
        self.logger.info(f"LDA model trained. Coherence score: {coherence_score:.3f}")
        
        return coherence_score
    
    def _preprocess_text(self, text: str) -> List[str]:
        """Preprocess text for topic modeling"""
        # Convert to lowercase
        text = text.lower()
        
        # Remove punctuation and digits
        text = re.sub(f'[{punctuation}0-9]', ' ', text)
        
        # Tokenize and remove short words
        tokens = [word for word in text.split() if len(word) > 3]
        
        return tokens
    
    def get_document_topics(self, text: str) -> List[TopicInfo]:
        """
        Get topic distribution for a single document
        
        Args:
            text: Document text
        
        Returns:
            List of TopicInfo objects
        """
        if not self.lda_model:
            self.logger.warning("LDA model not trained. Training on single document.")
            self.train_model([text])
        
        # Preprocess document
        processed_doc = self._preprocess_text(text)
        bow = self.dictionary.doc2bow(processed_doc)
        
        # Get topic distribution
        topic_distribution = self.lda_model.get_document_topics(bow)
        
        topics = []
        for topic_id, weight in topic_distribution:
            # Get top words for this topic
            topic_words = self.lda_model.show_topic(topic_id, topn=10)
            words = [word for word, _ in topic_words]
            word_weights = [weight for _, weight in topic_words]
            
            topic = TopicInfo(
                topic_id=topic_id,
                topic_words=words,
                topic_weights=word_weights,
                coherence_score=0.0,  # Would need full corpus for coherence
                dominant_in_document=(weight == max([w for _, w in topic_distribution]))
            )
            topics.append(topic)
        
        # Sort by weight
        topics.sort(key=lambda x: x.topic_weights[0], reverse=True)
        
        return topics


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
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.entity_recognizer = NamedEntityRecognizer()
        self.relationship_extractor = RelationshipExtractor()
        self.sentiment_analyzer = SentimentAnalyzer()
        self.topic_modeler = TopicModeler(num_topics=5)
        self.summarizer = TextSummarizer()
        self.readability_analyzer = ReadabilityAnalyzer()
        self.training_documents = []
        self.min_docs_for_training = 10
        
        # Track if topic model is trained
        self.topic_model_trained = False
    
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
        
        # 1. Named Entity Recognition
        entities = self.entity_recognizer.extract_entities(text, document.source_url)
        entities_by_type = self.entity_recognizer.get_entity_statistics(entities)
        
        # 2. Relationship Extraction
        relationships = self.relationship_extractor.extract_relationships(text, entities)
        
        # 3. Sentiment Analysis
        polarity, subjectivity, sentiment_label = self.sentiment_analyzer.analyze_sentiment(text)
        threat_score = self.sentiment_analyzer.calculate_threat_score(text)
        
        # 4. Language and Readability
        detected_language = document.detected_language or "en"
        readability_score = self.readability_analyzer.flesch_kincaid_grade(text)
        avg_word_length = document.avg_word_length
        sentence_count = len(document.sentences)
        
        # 5. Topic Modeling (train if needed, otherwise analyze)
        if not self.topic_model_trained and len(text) > 1000:
            self.topic_modeler.train_model([text])
            self.topic_model_trained = True
        
        topics = self.topic_modeler.get_document_topics(text) if self.topic_model_trained else []
        dominant_topic = topics[0].topic_id if topics else -1
        
        # 6. Summarization
        summary = self.summarizer.summarize(text, num_sentences=3)
        key_phrases = self.summarizer.extract_key_phrases(text, num_phrases=8)
        
        # 7. Extract threat keywords from matches
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
            sentiment_polarity=polarity,
            sentiment_subjectivity=subjectivity,
            sentiment_label=sentiment_label,
            detected_language=detected_language,
            readability_score=readability_score,
            average_word_length=avg_word_length,
            sentence_count=sentence_count,
            topics=topics,
            dominant_topic=dominant_topic,
            threat_keywords=threat_keywords,
            threat_score=threat_score,
            summary=summary,
            key_phrases=key_phrases
        )
        
        self.logger.info(f"NLP analysis complete: {len(entities)} entities, "
                        f"{len(relationships)} relationships, "
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
        
        # Add risk factors
        if result.sentiment_polarity < -0.3:
            assessment['risk_factors'].append("Highly negative sentiment indicating malicious intent")
        
        if len(result.relationships) > 5:
            assessment['risk_factors'].append("Multiple entity relationships suggesting data correlation")
        
        # Check for specific entity types
        org_count = result.entities_by_type.get('ORG', 0)
        if org_count > 3:
            assessment['risk_factors'].append(f"Multiple organizations ({org_count}) mentioned")
        
        # Add recommendations
        if result.threat_score >= 50:
            assessment['recommendations'].append("Immediate investigation required")
            assessment['recommendations'].append("Reset credentials for affected systems")
        
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
        cleaned_text=sample_text.lower(),
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
    
    print("\n[5] Sentiment Analysis:")
    print(f"   • Polarity: {result.sentiment_polarity:.2f} ({result.sentiment_label})")
    print(f"   • Subjectivity: {result.sentiment_subjectivity:.2f}")
    print(f"   • Threat Score: {result.threat_score:.1f}/100")
    
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

# brain (dark web monitoring system)

#Output
# A detailed intelligence report like:
# Who is mentioned?
# What happened ?
# Is it dangerous ?
# What is the topic ?
# Summary of the content