"""
Feature extractor for ML classifier per keyword
Extracts context features from keyword matches
"""

import re
import logging
from typing import List, Dict, Any

class FeatureExtractor:
    """Extract features from keyword matches for ML classification"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Patterns for feature detection
        self.sample_patterns = re.compile(r'(sample|example|test|demo|placeholder|dummy|mock|fictitious|for illustration)', re.IGNORECASE)
        self.real_leak_patterns = re.compile(r'(dump|leak|breach|exfiltrated|stolen|compromised|cracked|database|credentials)', re.IGNORECASE)
        self.dark_web_patterns = re.compile(r'(dark web|onion|tor|marketplace|hacker|breach|ransom)', re.IGNORECASE)
        self.credential_patterns = re.compile(r'password:|api_key:|secret:|token:|username:', re.IGNORECASE)
        
    def extract_features(self, match_text: str, context: str, full_text: str = "") -> List[float]:
        """
        Extract numerical features from a keyword match
        
        Args:
            match_text: The matched keyword/text
            context: 100-200 chars around the match
            full_text: Full document text (optional)
        
        Returns:
            List of numerical features
        """
        features = []
        
        # Feature 1: Is it in a code block?
        in_code_block = 1 if ('```' in context or '`' in context) else 0
        features.append(in_code_block)
        
        # Feature 2: Contains sample/test keywords?
        has_sample = 1 if self.sample_patterns.search(context) else 0
        features.append(has_sample)
        
        # Feature 3: Contains colon or equals (credential format)?
        has_colon = 1 if re.search(r'[:=]\s*\S+', context) else 0
        features.append(has_colon)
        
        # Feature 4: Has real password pattern (mixed case + numbers)?
        has_real_password = 1 if re.search(r'[A-Z][a-z]+\d+', context) else 0
        features.append(has_real_password)
        
        # Feature 5: Line length (normalized)
        lines = context.split('\n')
        first_line = lines[0] if lines else context
        line_length = min(len(first_line) / 200, 1.0)  # Normalize to 0-1
        features.append(line_length)
        
        # Feature 6: Number of surrounding words
        words = len(re.findall(r'\b\w+\b', context))
        word_count = min(words / 50, 1.0)  # Normalize to 0-1
        features.append(word_count)
        
        # Feature 7: Contains real leak indicators?
        has_leak_indicators = 1 if self.real_leak_patterns.search(context) else 0
        features.append(has_leak_indicators)
        
        # Feature 8: Contains dark web indicators?
        has_darkweb = 1 if self.dark_web_patterns.search(context) else 0
        features.append(has_darkweb)
        
        # Feature 9: Credential format (password:xxx)
        has_credential_format = 1 if self.credential_patterns.search(context) else 0
        features.append(has_credential_format)
        
        # Feature 10: Match length (normalized)
        match_length = min(len(match_text) / 50, 1.0)
        features.append(match_length)
        
        return features
    
    def get_feature_names(self) -> List[str]:
        """Return names of features for debugging"""
        return [
            'in_code_block',
            'has_sample_keyword',
            'has_colon_or_equal',
            'has_real_password_pattern',
            'line_length_normalized',
            'word_count_normalized',
            'has_leak_indicators',
            'has_darkweb_indicators',
            'has_credential_format',
            'match_length_normalized'
        ]