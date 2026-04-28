"""
Data Preprocessing Module for Dark Web Agriculture Monitor
Handles text cleaning, normalization, and entity extraction from crawled content
"""

import os
import sys
import re
import hashlib
import json
from datetime import datetime
from typing import List, Dict, Set, Tuple, Optional, Any
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse
import email.utils
from collections import Counter

import nltk
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer, WordNetLemmatizer
import tldextract
from email_validator import validate_email, EmailNotValidError

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import config_manager
import logging


@dataclass
class ExtractedEntity:
    """Data structure for extracted entities from text"""
    entity_type: str  # email, domain, credential, phone, ip, etc.
    value: str
    confidence: float  # 0-1 confidence score
    context: str  # Surrounding text for context
    position: int  # Character position in original text
    source_url: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ProcessedDocument:
    """Complete processed document with all extracted information"""
    # Original metadata
    source_url: str
    crawl_timestamp: datetime
    original_length: int
    
    # Cleaned content
    cleaned_text: str
    cleaned_length: int
    
    # Tokenized content
    tokens: List[str]
    sentences: List[str]
    
    # Extracted entities
    emails: List[ExtractedEntity]
    domains: List[ExtractedEntity]
    ip_addresses: List[ExtractedEntity]
    phone_numbers: List[ExtractedEntity]
    credentials: List[ExtractedEntity]
    agriculture_terms: List[ExtractedEntity]
    
    # Statistical features
    word_count: int
    unique_word_count: int
    avg_word_length: float
    special_char_ratio: float
    
    # Language and encoding
    detected_language: str
    encoding: str
    
    # Hashes for deduplication
    content_hash: str
    normalized_hash: str
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        data['crawl_timestamp'] = self.crawl_timestamp.isoformat()
        # Convert entity lists to dicts
        for entity_list in ['emails', 'domains', 'ip_addresses', 'phone_numbers', 'credentials', 'agriculture_terms']:
            data[entity_list] = [e.to_dict() for e in getattr(self, entity_list)]
        return data


class TextCleaner:
    """
    Handles text cleaning and normalization operations
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Compile regex patterns for performance
        self.url_pattern = re.compile(r'https?://\S+|www\.\S+')
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.phone_pattern = re.compile(r'\b[\+\d]?(?:[\d\-\(\)\/\.]\s?){6,15}\b')
        
        # Credential patterns (sensitive information)
        self.credential_patterns = {
            'password': re.compile(r'password\s*[=:]\s*\S+', re.IGNORECASE),
            'passwd': re.compile(r'passwd\s*[=:]\s*\S+', re.IGNORECASE),
            'pwd': re.compile(r'pwd\s*[=:]\s*\S+', re.IGNORECASE),
            'api_key': re.compile(r'api[_\s]?key\s*[=:]\s*\S+', re.IGNORECASE),
            'secret': re.compile(r'secret\s*[=:]\s*\S+', re.IGNORECASE),
            'token': re.compile(r'token\s*[=:]\s*\S+', re.IGNORECASE),
            'username': re.compile(r'username\s*[=:]\s*\S+', re.IGNORECASE),
            'login': re.compile(r'login\s*[=:]\s*\S+', re.IGNORECASE),
            'private_key': re.compile(r'private[\s_]key\s*[=:]\s*\S+', re.IGNORECASE),
            'aws_key': re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
            'mongodb': re.compile(r'mongodb://[^/\s]+', re.IGNORECASE),
            'mysql': re.compile(r'mysql://[^/\s]+', re.IGNORECASE),
            'postgresql': re.compile(r'postgresql://[^/\s]+', re.IGNORECASE),
        }
        
        # Agriculture-specific terms (from config)
        self.agriculture_terms = set(term.lower() for term in config_manager.get_keywords('agriculture_terms'))
        
        # Stop words for filtering
        self.stop_words = set(stopwords.words('english'))
        
        # Initialize stemmer and lemmatizer
        self.stemmer = PorterStemmer()
        self.lemmatizer = WordNetLemmatizer()
    
    def clean_text(self, text: str, remove_urls: bool = True, 
                   remove_special_chars: bool = True,
                   normalize_whitespace: bool = True) -> str:
        """
        Clean and normalize text content
        
        Args:
            text: Raw text to clean
            remove_urls: Remove URLs from text
            remove_special_chars: Remove special characters
            normalize_whitespace: Normalize whitespace
        
        Returns:
            Cleaned text
        """
        if not text:
            return ""
        
        original_length = len(text)
        
        # Remove URLs if requested
        if remove_urls:
            text = self.url_pattern.sub(' ', text) # Remove URLs
        
        # Remove email addresses (they're extracted separately)
        text = self.email_pattern.sub(' ', text)
        
        # Remove IP addresses (they're extracted separately)
        text = self.ip_pattern.sub(' ', text)
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove special characters if requested
        if remove_special_chars:
            # Keep alphanumeric, spaces, and basic punctuation
            text = re.sub(r'[^a-zA-Z0-9\s\.\,\!\?\-\'\"]', ' ', text)
        
        # Normalize whitespace
        if normalize_whitespace:
            text = re.sub(r'\s+', ' ', text)
            text = text.strip()
        
        cleaned_length = len(text)
        
        self.logger.debug(f"Cleaned text: {original_length} -> {cleaned_length} chars")
        
        return text
    
    def tokenize_text(self, text: str, remove_stopwords: bool = True,
                     stem: bool = False, lemmatize: bool = False) -> List[str]:
        """
        Tokenize text into words
        
        Args:
            text: Text to tokenize
            remove_stopwords: Remove common stop words
            stem: Apply stemming to tokens
            lemmatize: Apply lemmatization to tokens
        
        Returns:
            List of tokens
        """
        if not text:
            return []
        
        # Word tokenization
        try:
            tokens = word_tokenize(text)
        except Exception as e:
            self.logger.warning(f"Tokenization failed: {e}, using simple split")
            tokens = text.split()
        
        # Remove non-alphabetic tokens
        tokens = [token for token in tokens if token.isalpha()]
        
        # Remove stopwords
        if remove_stopwords:
            tokens = [token for token in tokens if token not in self.stop_words]
        
        # Apply stemming
        if stem:
            tokens = [self.stemmer.stem(token) for token in tokens]
        
        # Apply lemmatization
        if lemmatize:
            tokens = [self.lemmatizer.lemmatize(token) for token in tokens]
        
        return tokens
    
    def segment_sentences(self, text: str) -> List[str]:
        """Split text into sentences"""
        if not text:
            return []
        
        try:
            sentences = sent_tokenize(text)
        except Exception:
            # Fallback to simple splitting
            sentences = text.split('. ')
        
        return sentences


class EntityExtractor:
    """
    Extracts valuable entities from text including emails, domains, credentials
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.text_cleaner = TextCleaner()
        
        # Compile patterns (reuse from TextCleaner)
        self.email_pattern = self.text_cleaner.email_pattern
        self.ip_pattern = self.text_cleaner.ip_pattern
        self.phone_pattern = self.text_cleaner.phone_pattern
        self.credential_patterns = self.text_cleaner.credential_patterns
        
        # Domain extraction using tldextract
        self.domain_extractor = tldextract.TLDExtract()
        
        # Agriculture terms (from config)
        self.agriculture_terms = config_manager.get_keywords('agriculture_terms')
        self.proprietary_terms = config_manager.get_keywords('proprietary_terms')
        
        # Common TLDs for domain validation
        self.valid_tlds = {'com', 'org', 'net', 'io', 'co', 'uk', 'de', 'fr', 'jp', 
                          'cn', 'ru', 'br', 'in', 'au', 'ca', 'onion'}
    
    def extract_emails(self, text: str, source_url: str = "") -> List[ExtractedEntity]:
        """
        Extract email addresses from text
        
        Args:
            text: Text to extract from
            source_url: Source URL for context
        
        Returns:
            List of extracted email entities
        """
        emails = []
        
        for match in self.email_pattern.finditer(text):
            email = match.group()
            
            # Validate email format
            try:
                validation = validate_email(email)
                email = validation.email  # Normalized email
                
                # Get context (50 chars before and after)
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]
                
                entity = ExtractedEntity(
                    entity_type='email',
                    value=email,
                    confidence=0.95,
                    context=context,
                    position=match.start(),
                    source_url=source_url
                )
                emails.append(entity)
                
            except EmailNotValidError:
                self.logger.debug(f"Invalid email format: {email}")
                continue
        
        return emails
    
    def extract_domains(self, text: str, source_url: str = "") -> List[ExtractedEntity]:
        """
        Extract domain names from text
        
        Args:
            text: Text to extract from
            source_url: Source URL for context
        
        Returns:
            List of extracted domain entities
        """
        domains = []

        emails = self.extract_emails(text, source_url)
        email_domains = set()

        for email in emails:
            domain_part = email.value.split('@')[-1]
            email_domains.add(domain_part.lower())
        
        # Look for domain patterns (word.word)
        domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
        
        for match in domain_pattern.finditer(text):
            domain = match.group().lower()

            #Skip domains from emails
            if domain in email_domains:
                continue
            
            # Extract domain parts
            extracted = self.domain_extractor(domain)
            
            # Validate domain
            if extracted.suffix and extracted.suffix in self.valid_tlds:
                # Get context
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]
                
                entity = ExtractedEntity(
                    entity_type='domain',
                    value=domain,
                    confidence=0.90,
                    context=context,
                    position=match.start(),
                    source_url=source_url
                )
                domains.append(entity)
        
        # Remove duplicates based on value
        unique_domains = {}
        for domain in domains:
            if domain.value not in unique_domains:
                unique_domains[domain.value] = domain
        
        return list(unique_domains.values())
    
    def extract_ip_addresses(self, text: str, source_url: str = "") -> List[ExtractedEntity]:
        """
        Extract IP addresses from text
        
        Args:
            text: Text to extract from
            source_url: Source URL for context
        
        Returns:
            List of extracted IP entities
        """
        ips = []
        
        for match in self.ip_pattern.finditer(text):
            ip = match.group()
            
            # Validate IP range
            parts = ip.split('.')
            valid = all(0 <= int(part) <= 255 for part in parts)
            
            if valid:
                # Get context
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]
                
                entity = ExtractedEntity(
                    entity_type='ip_address',
                    value=ip,
                    confidence=0.95,
                    context=context,
                    position=match.start(),
                    source_url=source_url
                )
                ips.append(entity)
            
        #Remove duplicates based on IP value
        unique_ips = {}

        for ip in ips:
            if ip.value not in unique_ips:
                unique_ips[ip.value] = ip
        
        return list(unique_ips.values())
    
    def extract_phone_numbers(self, text: str, source_url: str = "") -> List[ExtractedEntity]:
        """
        Extract phone numbers from text
        
        Args:
            text: Text to extract from
            source_url: Source URL for context
        
        Returns:
            List of extracted phone entities
        """
        phones = []
        
        for match in self.phone_pattern.finditer(text):
            phone = match.group()
            
            # Clean phone number for validation
            clean_phone = re.sub(r'[\s\-\(\)\.]', '', phone)
            
            # Basic validation: should be 7-15 digits
            if 7 <= len(clean_phone) <= 15:
                # Get context
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]
                
                entity = ExtractedEntity(
                    entity_type='phone_number',
                    value=phone,
                    confidence=0.85,
                    context=context,
                    position=match.start(),
                    source_url=source_url
                )
                phones.append(entity)
        
        return phones
    
    def extract_credentials(self, text: str, source_url: str = "") -> List[ExtractedEntity]:
        """
        Extract credential patterns (passwords, API keys, etc.)
        
        Args:
            text: Text to extract from
            source_url: Source URL for context
        
        Returns:
            List of extracted credential entities (deduplicated)
        """
        credentials = []
        seen_values = set()  # Track unique credentials in this document
        
        for cred_type, pattern in self.credential_patterns.items():
            for match in pattern.finditer(text):
                credential = match.group()
                
                # Create a normalized key for deduplication
                # Use credential type + redacted value to avoid storing full secrets
                redacted_value = credential[:10] + "..." if len(credential) > 10 else credential
                dedup_key = f"{cred_type}_{redacted_value}"
                
                # Skip if already seen in this document
                if dedup_key in seen_values:
                    continue
                seen_values.add(dedup_key)
                
                # Get context (50 chars before and after)
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]
                
                # Redact the actual credential value for storage (security)
                # Store slightly more for uniqueness but not full value
                redacted_value = credential[:15] + "..." if len(credential) > 15 else credential
                
                entity = ExtractedEntity(
                    entity_type=f'credential_{cred_type}',
                    value=redacted_value,  # Store redacted version
                    confidence=0.80,
                    context=context,
                    position=match.start(),
                    source_url=source_url
                )
                credentials.append(entity)
                
                self.logger.warning(f"Found potential credential ({cred_type}) in {source_url}")
        
        # Remove duplicates based on entity_type + value (additional safety)
        unique_credentials = {}
        for cred in credentials:
            key = (cred.entity_type, cred.value)
            if key not in unique_credentials:
                unique_credentials[key] = cred
        
        result = list(unique_credentials.values())
        
        if result:
            self.logger.info(f"Extracted {len(result)} unique credentials from {source_url} (had {len(credentials)} raw matches)")
        
        return result
    
    def extract_agriculture_terms(self, text: str, source_url: str = "") -> List[ExtractedEntity]:
        """
        Extract agriculture-specific terminology
        
        Args:
            text: Text to extract from
            source_url: Source URL for context
        
        Returns:
            List of extracted agriculture term entities
        """
        terms = []
        text_lower = text.lower()
        
        # Check for agriculture terms
        for term in self.agriculture_terms:
            pattern = re.compile(r'\b' + re.escape(term.lower()) + r'\b')
            for match in pattern.finditer(text_lower):
                # Get context
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]
                
                entity = ExtractedEntity(
                    entity_type='agriculture_term',
                    value=term,
                    confidence=0.75,
                    context=context,
                    position=match.start(),
                    source_url=source_url
                )
                terms.append(entity)
        
        # Check for proprietary terms (higher confidence)
        for term in self.proprietary_terms:
            if term.lower() in text_lower:
                pattern = re.compile(r'\b' + re.escape(term.lower()) + r'\b')
                for match in pattern.finditer(text_lower):
                    start = max(0, match.start() - 50)
                    end = min(len(text), match.end() + 50)
                    context = text[start:end]
                    
                    entity = ExtractedEntity(
                        entity_type='proprietary_term',
                        value=term,
                        confidence=0.95,  # Higher confidence for proprietary terms
                        context=context,
                        position=match.start(),
                        source_url=source_url
                    )
                    terms.append(entity)
        
        return terms


class DocumentProcessor:
    """
    Main document processor that orchestrates all preprocessing steps
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.text_cleaner = TextCleaner()
        self.entity_extractor = EntityExtractor()
        
        # Statistics tracking
        self.processed_count = 0
        self.total_entities_found = Counter()
    
    def process_document(self, raw_text: str, source_url: str, 
                        original_metadata: Optional[Dict] = None) -> ProcessedDocument:
        """
        Process a raw document through all preprocessing steps
        
        Args:
            raw_text: Raw text content to process
            source_url: Source URL of the document
            original_metadata: Optional original metadata
        
        Returns:
            ProcessedDocument with all extracted information
        """
        self.logger.info(f"Processing document from {source_url} ({len(raw_text)} chars)")
        
        # Step 1: Clean the text
        cleaned_text = self.text_cleaner.clean_text(
            raw_text,
            remove_urls=True,
            remove_special_chars=True,
            normalize_whitespace=True
        )
        
        # Step 2: Tokenize and segment
        tokens = self.text_cleaner.tokenize_text(
            cleaned_text,
            remove_stopwords=True,
            stem=False,
            lemmatize=False
        )
        
        sentences = self.text_cleaner.segment_sentences(cleaned_text)
        
        # Step 3: Extract entities
        emails = self.entity_extractor.extract_emails(raw_text, source_url)
        domains = self.entity_extractor.extract_domains(raw_text, source_url)
        ip_addresses = self.entity_extractor.extract_ip_addresses(raw_text, source_url)
        phone_numbers = self.entity_extractor.extract_phone_numbers(raw_text, source_url)
        credentials = self.entity_extractor.extract_credentials(raw_text, source_url)
        credentials = self.remove_duplicate_credentials(credentials)
        agriculture_terms = self.entity_extractor.extract_agriculture_terms(raw_text, source_url)
        
        # Update statistics
        self.processed_count += 1
        self.total_entities_found['emails'] += len(emails)
        self.total_entities_found['domains'] += len(domains)
        self.total_entities_found['credentials'] += len(credentials)
        self.total_entities_found['agriculture_terms'] += len(agriculture_terms)
        
        # Step 4: Calculate statistics
        word_count = len(tokens)
        unique_word_count = len(set(tokens))
        avg_word_length = sum(len(w) for w in tokens) / max(word_count, 1)
        
        # Special character ratio (non-alphanumeric in original)
        special_chars = sum(1 for c in raw_text if not c.isalnum() and not c.isspace())
        special_char_ratio = special_chars / max(len(raw_text), 1)
        
        # Step 5: Generate hashes
        content_hash = hashlib.sha256(raw_text.encode()).hexdigest()
        normalized_hash = hashlib.sha256(cleaned_text.encode()).hexdigest()
        
        # Step 6: Detect language (simplified - just English for now)
        detected_language = 'en'
        
        # Create processed document
        processed_doc = ProcessedDocument(
            source_url=source_url,
            crawl_timestamp=datetime.now(),
            original_length=len(raw_text),
            cleaned_text=cleaned_text[:10000],  # Limit stored text length
            cleaned_length=len(cleaned_text),
            tokens=tokens[:5000],  # Limit tokens stored
            sentences=sentences[:500],
            emails=emails,
            domains=domains,
            ip_addresses=ip_addresses,
            phone_numbers=phone_numbers,
            credentials=credentials,
            agriculture_terms=agriculture_terms,
            word_count=word_count,
            unique_word_count=unique_word_count,
            avg_word_length=avg_word_length,
            special_char_ratio=special_char_ratio,
            detected_language=detected_language,
            encoding='utf-8',
            content_hash=content_hash,
            normalized_hash=normalized_hash
        )
        
        self.logger.info(f"Document processed: {len(emails)} emails, {len(domains)} domains, "
                        f"{len(credentials)} credentials found")
        
        return processed_doc
    

    def remove_duplicate_credentials(self, credentials: List[ExtractedEntity]) -> List[ExtractedEntity]:
        """
        Remove duplicate credentials from the list
        
        Args:
            credentials: List of credential entities
        
        Returns:
            Deduplicated list
        """
        unique = {}
        
        for cred in credentials:
            # Create a unique key based on type and redacted value
            key = (cred.entity_type, cred.value)
            if key not in unique:
                unique[key] = cred
        
        return list(unique.values())
    
    def process_batch(self, documents: List[Tuple[str, str, Optional[Dict]]]) -> List[ProcessedDocument]:
        """
        Process multiple documents in batch
        
        Args:
            documents: List of (raw_text, source_url, metadata) tuples
        
        Returns:
            List of ProcessedDocument objects
        """
        processed = []
        
        for raw_text, source_url, metadata in documents:
            try:
                doc = self.process_document(raw_text, source_url, metadata)
                processed.append(doc)
            except Exception as e:
                self.logger.error(f"Failed to process {source_url}: {str(e)}")
                continue
        
        self.logger.info(f"Batch processing complete: {len(processed)}/{len(documents)} successful")
        return processed
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get preprocessing statistics"""
        return {
            'total_documents_processed': self.processed_count,
            'entities_found': dict(self.total_entities_found),
            'average_entities_per_doc': {
                entity: count / max(self.processed_count, 1)
                for entity, count in self.total_entities_found.items()
            }
        }


# Standalone test function
def test_preprocessor():
    """Test the data preprocessing module"""
    print("\n" + "="*60)
    print("TESTING DATA PREPROCESSING MODULE")
    print("="*60)
    
    # Sample dark web content for testing
    sample_content = """
    === BREACHED AGRICULTURE DATA DUMP ===
    
    Date: 2024-01-15
    Source: AgriFarm Corp Database
    
    EMAILS FOUND:
    admin@agrifarm.com
    security@agrifarm.com
    john.doe@gmail.com
    
    CREDENTIALS:
    password: Harvest2024!
    api_key: AKIAIOSFODNN7EXAMPLE
    database: postgresql://user:pass@10.0.0.1:5432/agridb
    
    DOMAINS:
    agrifarm.com
    cropscience.io
    harvestdata.co
    
    AGRICULTURE DATA:
    Crop yield predictions for 2024 season show 15% increase.
    Soil composition analysis reveals high nitrogen levels in Zone B.
    Irrigation schedule for next week adjusted due to weather forecast.
    
    IP ADDRESSES:
    192.168.1.100
    10.0.0.1
    
    SENSITIVE INFO:
    Credit card: 4111-1111-1111-1111
    SSN: 123-45-6789
    """
    
    print("\n[1] Initializing document processor...")
    processor = DocumentProcessor()
    
    print("\n[2] Processing sample document...")
    processed = processor.process_document(sample_content,"http://6e5gwbwm3gos4wbnlltzorgulrd3eipjjbe53n5riutzbpst4f6nw5ad.onion")
    
    print("\n[3] Processing Results:")
    print(f"   • Original length: {processed.original_length} chars")
    print(f"   • Cleaned length: {processed.cleaned_length} chars")
    print(f"   • Word count: {processed.word_count}")
    print(f"   • Unique words: {processed.unique_word_count}")
    
    print("\n[4] Extracted Entities:")
    print(f"   • Emails: {len(processed.emails)}")
    for email in processed.emails[:3]:
        print(f"     - {email.value} (confidence: {email.confidence})")
    
    print(f"   • Domains: {len(processed.domains)}")
    for domain in processed.domains[:3]:
        print(f"     - {domain.value}")
    
    print(f"   • IP Addresses: {len(processed.ip_addresses)}")
    for ip in processed.ip_addresses:
        print(f"     - {ip.value}")
    
    print(f"   • Credentials: {len(processed.credentials)}")
    for cred in processed.credentials[:3]:
        print(f"     - {cred.entity_type}: {cred.value}")
    
    print(f"   • Agriculture Terms: {len(processed.agriculture_terms)}")
    for term in processed.agriculture_terms[:5]:
        print(f"     - {term.value}")
    
    print("\n[5] Text Sample (cleaned):")
    print(f"   {processed.cleaned_text[:200]}...")
    
    print("\n[6] Tokens Sample (first 20):")
    print(f"   {processed.tokens[:20]}")
    
    print("\n[7] Statistics:")
    stats = processor.get_statistics()
    for key, value in stats.items():
        print(f"   • {key}: {value}")
    
    print("\n" + "="*60)
    print("PREPROCESSING MODULE TEST COMPLETE")
    print("="*60)
    
    return True


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    test_preprocessor()


# TextCleaner --> cleans and prepares text
# Entity Cleaner --> Finds useful/sensitive data
# Document Processor --> Control Everything
# Data Class --> Store result in structured form


####LOGIC###
# RAW TEXT -> Text Cleaner -> Tokenization (split int words) -> Entity Extraction  (finds email, passwrods etc.) -> Statistics (word count, etc) -> Processed Document