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
    match_type: str  # exact, fuzzy, regex, contextual, ner_validated
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


class ContextValidator:
    """Advanced context validation to reduce false positives"""
    
    # Patterns that indicate FALSE positives (test data, examples)
    FALSE_POSITIVE_PATTERNS = [
        r'(?i)(?:sample|example|test|demo|dummy|placeholder|for illustration only)',
        r'(?i)<(?:code|pre|comment)>.*?</(?:code|pre|comment)>',
        r'(?i)```.*?```',  # Code blocks
        r'(?i)<!--.*?-->',  # HTML comments
        r'(?i)(?:not real|not actual|fictitious|mock[- ]?data)',
        r'(?i)for demonstration purposes',
        r'(?i)this is not a real',
        r'(?i)educational purposes only'
    ]
    
    # Patterns that indicate TRUE positives (actual leaks)
    TRUE_POSITIVE_PATTERNS = [
        r'(?i)(?:leak|breach|dump|exfiltrated|stolen|cracked|compromised)',
        r'(?i)(?:database|credentials|passwords|secrets) dumped',
        r'(?i)(?:dark web|onion|tor|marketplace)',
        r'(?i)(?:bitcoin|monero|ransom)',
        r'(?i)hacked|breached|compromised',
        r'(?i)confidential|restricted|internal use only',
        r'(?i)credentials found|passwords found'
    ]
    
    @classmethod
    def validate(cls, match: KeywordMatch, full_text: str) -> Tuple[bool, float]:
        """
        Validate match and return (is_valid, adjusted_confidence)
        
        Args:
            match: Keyword match to validate
            full_text: Full document text
        
        Returns:
            Tuple of (is_valid, adjusted_confidence)
        """
        # Get expanded context (300 chars around match)
        start = max(0, match.position - 300)
        end = min(len(full_text), match.position + 300)
        context_window = full_text[start:end]
        
        # Check for false positive indicators
        for pattern in cls.FALSE_POSITIVE_PATTERNS:
            if re.search(pattern, context_window):
                # Exception: credential matches might still be real even in examples
                if match.category != 'credential':
                    return False, 0.0
        
        # Adjust confidence based on true positive indicators
        confidence_boost = 0
        for pattern in cls.TRUE_POSITIVE_PATTERNS:
            if re.search(pattern, context_window):
                confidence_boost += 0.1
                if confidence_boost >= 0.3:  # Max boost
                    break
        
        # Special handling for agriculture terms in code blocks
        if match.category == 'agriculture' and re.search(r'```.*?' + re.escape(match.keyword) + r'.*?```', context_window, re.IGNORECASE | re.DOTALL):
            # Agriculture term in code block - likely false positive
            return False, 0.0
        
        new_confidence = min(1.0, match.confidence + confidence_boost)
        return True, new_confidence


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
            key = (m.matched_text.lower(), m.position, m.category)
            
            # Keep highest confidence version
            if key not in unique_matches or m.confidence > unique_matches[key].confidence:
                unique_matches[key] = m
        
        # Convert back to list
        matches = list(unique_matches.values())
        
        return matches
    
    def partial_word_match(self, text: str, keyword: str, min_match_ratio: float = 0.6) -> List[Tuple[str, int, str, float]]:
        """
        Find partial word matches for agriculture terms (high recall)
        
        Args:
            text: Text to search
            keyword: Keyword to match partially
            min_match_ratio: Minimum ratio of characters that must match
        
        Returns:
            List of (matched_word, position, context, similarity)
        """
        matches = []
        keyword_lower = keyword.lower()
        words = re.findall(r'\b\w+\b', text.lower())
        
        for word in words:
            if len(word) < 3 or len(keyword) < 3:
                continue
            
            # Calculate character overlap ratio
            common_chars = set(word) & set(keyword_lower)
            match_ratio = len(common_chars) / max(len(set(keyword_lower)), 1)
            
            if match_ratio >= min_match_ratio:
                # Find position in original text
                pos = text.lower().find(word)
                if pos >= 0:
                    start = max(0, pos - 50)
                    end = min(len(text), pos + len(word) + 50)
                    context = text[start:end]
                    matches.append((word, pos, context, match_ratio))
        
        return matches


class FuzzyMatcher:
    """
    Handles fuzzy string matching for misspelled or obfuscated keywords
    """
    
    def __init__(self, threshold: int = 70):
        """
        Initialize fuzzy matcher
        
        Args:
            threshold: Minimum similarity score (0-100) for a match
        """
        self.threshold = threshold
        self.logger = logging.getLogger(__name__)
        
        # Build keyword index for fuzzy matching
        self.keywords_index = self._build_keyword_index()
    
    def set_threshold(self, threshold: int):
        """Dynamically set threshold for different detection modes"""
        self.threshold = threshold
        self.logger.debug(f"Fuzzy matcher threshold set to {threshold}")
    
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
                # Add with common leet speak substitutions
                index[category].append(keyword.lower().replace('e', '3'))
                index[category].append(keyword.lower().replace('a', '4'))
        
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
                    
                    # Skip if chunk is too short compared to keyword
                    if len(chunk) < len(keyword) * 0.5:
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
    
    def _create_word_chunks(self, words: List[str], max_chunk_size: int = 3) -> List[str]:
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
        
        # Multi-word chunks (reduced max_chunk_size for performance)
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
                
                # Higher threshold for domain fuzzy matching (precision focused)
                if similarity >= max(self.threshold, 80):
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
            's': '5',
            'rn': 'm',
            'cl': 'd',
            'vv': 'w'
        }
        
        best_score = fuzz.ratio(text, target)
        
        # Try substitutions
        for orig, sub in homograph_map.items():
            modified = text.replace(orig, sub)
            score = fuzz.ratio(modified, target)
            best_score = max(best_score, score)
        
        return best_score


class KeywordDetector:
    """
    Main keyword detection orchestrator with two-pass detection strategy
    """
    
    # Detection modes
    MODE_HIGH_RECALL = 'high_recall'
    MODE_BALANCED = 'balanced'
    MODE_HIGH_PRECISION = 'high_precision'
    
    def __init__(self, mode: str = MODE_BALANCED):
        """
        Initialize keyword detector
        
        Args:
            mode: Detection mode (high_recall, balanced, high_precision)
        """
        self.logger = logging.getLogger(__name__)
        self.mode = mode
        
        # Set thresholds based on mode
        self._configure_mode(mode)
        
        self.pattern_matcher = PatternMatcher()
        self.fuzzy_matcher = FuzzyMatcher(threshold=self.fuzzy_threshold)
        self.context_validator = ContextValidator()
        
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
    
    def _configure_mode(self, mode: str):
        """Configure detection parameters based on mode"""
        if mode == self.MODE_HIGH_RECALL:
            self.fuzzy_threshold = 55
            self.min_confidence = 0.3
            self.include_partial_words = True
            self.context_validation = False
            self.require_ner_validation = False
            self.logger.info("Configured for HIGH RECALL mode")
            
        elif mode == self.MODE_HIGH_PRECISION:
            self.fuzzy_threshold = 85
            self.min_confidence = 0.75
            self.include_partial_words = False
            self.context_validation = True
            self.require_ner_validation = True
            self.logger.info("Configured for HIGH PRECISION mode")
            
        else:  # MODE_BALANCED
            self.fuzzy_threshold = 70
            self.min_confidence = 0.5
            self.include_partial_words = False
            self.context_validation = True
            self.require_ner_validation = False
            self.logger.info("Configured for BALANCED mode")
    
    def set_mode(self, mode: str):
        """Change detection mode dynamically"""
        self.mode = mode
        self._configure_mode(mode)
        self.fuzzy_matcher.set_threshold(self.fuzzy_threshold)
    
    def detect_matches(self, document: ProcessedDocument, ner_entities: List = None) -> DocumentMatchResult:
        """
        Detect all keyword matches in a processed document
        
        Args:
            document: ProcessedDocument object
            ner_entities: Optional NER entities for cross-validation
        
        Returns:
            DocumentMatchResult with all matches
        """
        self.logger.info(f"Detecting keywords in {document.source_url} (mode: {self.mode})")
        
        all_matches = []
        
        # PASS 1: High recall - cast wide net
        recall_matches = self._high_recall_pass(document)
        all_matches.extend(recall_matches)
        
        # PASS 2: Context validation and filtering
        if self.context_validation:
            validated_matches = []
            for match in all_matches:
                is_valid, adjusted_confidence = self.context_validator.validate(match, document.cleaned_text)
                if is_valid:
                    match.confidence = adjusted_confidence
                    validated_matches.append(match)
            all_matches = validated_matches
        
        # PASS 3: Cross-validation with NER entities (if available and required)
        if ner_entities and (self.require_ner_validation or self.mode == self.MODE_BALANCED):
            all_matches = self._cross_validate_with_ner(all_matches, ner_entities)
        
        # Apply minimum confidence threshold
        all_matches = [m for m in all_matches if m.confidence >= self.min_confidence]
        
        # Deduplicate matches
        all_matches = self._deduplicate_matches(all_matches)
        
        self.logger.info(f"After all passes: {len(all_matches)} matches")
        
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
    
    def _high_recall_pass(self, document: ProcessedDocument) -> List[KeywordMatch]:
        """First pass: High recall detection"""
        matches = []
        text = document.cleaned_text
        
        # Method 1: Exact pattern matching
        exact_matches = self._exact_pattern_matches(document)
        matches.extend(exact_matches)
        
        # Method 2: Fuzzy matching (with current threshold)
        fuzzy_matches = self._fuzzy_matches(document)
        matches.extend(fuzzy_matches)
        
        # Method 3: Credential detection
        credential_matches = self.pattern_matcher.detect_credential_leaks(
            document.cleaned_text, 
            document.credentials
        )
        for match in credential_matches:
            match.source_url = document.source_url
        matches.extend(credential_matches)
        
        # Method 4: Partial word matching (only for high recall mode)
        if self.include_partial_words:
            partial_matches = self._partial_word_matches(document)
            matches.extend(partial_matches)
        
        return matches
    
    def _partial_word_matches(self, document: ProcessedDocument) -> List[KeywordMatch]:
        """Find partial word matches for agriculture terms (high recall)"""
        matches = []
        text = document.cleaned_text
        
        agriculture_terms = self.keywords.get('agriculture_terms', [])
        
        for term in agriculture_terms:
            # Split multi-word terms
            words_in_term = term.lower().split()
            
            for word in words_in_term:
                if len(word) < 4:
                    continue
                
                partial_results = self.pattern_matcher.partial_word_match(text, word, min_match_ratio=0.6)
                
                for matched_word, position, context, match_ratio in partial_results:
                    match = KeywordMatch(
                        keyword=term,
                        matched_text=matched_word,
                        match_type='partial',
                        confidence=0.4 + (match_ratio * 0.3),  # 0.4 to 0.7
                        position=position,
                        context=context,
                        category='agriculture',
                        source_url=document.source_url,
                        similarity_score=match_ratio
                    )
                    matches.append(match)
        
        return matches
    
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

        # Extra: word-level agriculture matching (for multi-word terms)
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
                        keyword=term,
                        matched_text=match.group(),
                        match_type='exact_word',
                        confidence=0.65,
                        position=match.start(),
                        context=context,
                        category='agriculture',
                        source_url=document.source_url,
                        similarity_score=1.0
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
                confidence = (similarity / 100.0) * 0.85  # Cap at 0.85 for fuzzy matches
                
                match = KeywordMatch(
                    keyword=keyword,
                    matched_text=text[position:position+len(keyword)] if position + len(keyword) <= len(text) else keyword,
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
                    matched_text=text[position:position+len(domain)] if position + len(domain) <= len(text) else domain,
                    match_type='fuzzy_domain',
                    confidence=(similarity / 100.0) * 0.9,
                    position=position,
                    context=context,
                    category='domain',
                    source_url=document.source_url,
                    similarity_score=similarity / 100.0
                )
                matches.append(match)
        
        return matches
    
    def _cross_validate_with_ner(self, matches: List[KeywordMatch], ner_entities: List) -> List[KeywordMatch]:
        """
        Cross-validate keyword matches with NER entities
        
        Args:
            matches: Keyword matches to validate
            ner_entities: Named entities from NLP analysis
        
        Returns:
            Validated matches with adjusted confidence
        """
        validated = []
        
        for match in matches:
            matched_lower = match.matched_text.lower()
            boost_applied = False
            
            # Check if match appears as a named entity
            for entity in ner_entities:
                if matched_lower in entity.text.lower() or entity.text.lower() in matched_lower:
                    # Boost confidence for NER-validated matches
                    match.confidence = min(1.0, match.confidence + 0.15)
                    match.match_type = "ner_validated"
                    boost_applied = True
                    break
            
            # For agriculture terms, check if in context with other agriculture entities
            if not boost_applied and match.category == 'agriculture':
                # Check surrounding context for agriculture indicators
                context_lower = match.context.lower()
                ag_indicators = ['crop', 'yield', 'soil', 'harvest', 'plant', 'farm']
                if any(ind in context_lower for ind in ag_indicators):
                    match.confidence = min(0.9, match.confidence + 0.1)
                    match.match_type = "context_validated"
                    boost_applied = True
            
            validated.append(match)
        
        return validated
    
    def _deduplicate_matches(self, matches: List[KeywordMatch]) -> List[KeywordMatch]:
        """Remove duplicate matches with category-specific logic"""
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
        """Check if two matches are similar with category-specific logic"""
        if m1.category != m2.category:
            return False
        
        # For credentials, exact value match is enough
        if m1.category == 'credential' and m1.matched_text == m2.matched_text:
            return True
        
        # For agriculture terms, use more aggressive dedup
        if m1.category == 'agriculture':
            similarity = fuzz.ratio(m1.matched_text.lower(), m2.matched_text.lower())
            # Lower threshold for agriculture (more variation in terminology)
            return similarity > 80 and abs(m1.position - m2.position) < 100
        
        # Default
        similarity = fuzz.ratio(m1.matched_text.lower(), m2.matched_text.lower())
        return similarity > 85 and abs(m1.position - m2.position) < 50
    
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
        high_conf_ratio = len([m for m in matches if m.confidence >= 0.8]) / len(matches) if matches else 0
        if high_conf_ratio < 0.2:
            adjustment -= 10
        
        # Boost if credentials found
        if any(m.category == 'credential' for m in matches):
            adjustment += 15
        
        # Boost for proprietary data
        if any(m.category == 'proprietary' and m.confidence > 0.8 for m in matches):
            adjustment += 10

        # Reduce risk if intent is marketplace_listing with low confidence
        if hasattr(self, 'last_intent') and self.last_intent == 'marketplace_listing':
            if self.last_intent_confidence < 0.4:
                risk_score *= 0.5  
        
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
            'detection_mode': self.mode,
            'critical_findings': []
        }
        
        # Add high confidence credentials
        for match in result.high_confidence_matches[:10]:
            if match.category == 'credential':
                summary['critical_findings'].append({
                    'type': match.keyword,
                    'value': match.matched_text[:50],  # Truncate for safety
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
    from preprocessor.data_cleaner import DocumentProcessor, ProcessedDocument
    
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
    
    # Test different modes
    for mode in [KeywordDetector.MODE_HIGH_RECALL, KeywordDetector.MODE_BALANCED, KeywordDetector.MODE_HIGH_PRECISION]:
        print(f"\n[2] Testing {mode.upper()} mode...")
        detector = KeywordDetector(mode=mode)
        result = detector.detect_matches(processed)
        
        print(f"   • Total matches: {result.total_matches}")
        print(f"   • High confidence: {len(result.high_confidence_matches)}")
        print(f"   • Medium confidence: {len(result.medium_confidence_matches)}")
        print(f"   • Low confidence: {len(result.low_confidence_matches)}")
        print(f"   • Risk score: {result.overall_risk_score:.1f}/100")
    
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