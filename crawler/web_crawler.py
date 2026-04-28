"""
Web Crawling Module for Dark Web Agriculture Monitor
Handles crawling of .onion sites, link extraction, and depth-controlled traversal
"""

import os
import sys
import time
import re
import json
from urllib.parse import urljoin, urlparse
from datetime import datetime
from typing import Set, Dict, List, Optional, Tuple, Any
from collections import deque
from dataclasses import dataclass, asdict
from queue import PriorityQueue
from preprocessor.data_cleaner import DocumentProcessor
import requests
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for dark web sites
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import config_manager
from tor_network.tor_manager import TorManager
import logging


@dataclass
class CrawledPage:
    """Data structure for storing crawled page information"""
    url: str
    title: str
    content: str
    content_length: int
    crawl_depth: int
    found_at: str  # URL that linked to this page
    crawled_at: datetime
    status_code: int
    links_found: List[str]
    content_type: str
    hash_content: str  # For deduplication
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for storage"""
        data = asdict(self)
        data['crawled_at'] = self.crawled_at.isoformat()
        return data


class CrawlerQueue:
    """
    Manages URLs to be crawled with priority system
    Higher priority for pages with more relevant keywords
    """
    
    def __init__(self):
        self.queue = PriorityQueue()
        self.visited_urls: Set[str] = set()
        self.in_queue: Set[str] = set()
        self.url_counter = 0
        
    def add_url(self, url: str, depth: int, priority: int = 0, referrer: str = None):
        """
        Add URL to crawl queue
        
        Args:
            url: URL to crawl
            depth: Current crawl depth
            priority: Higher value = higher priority
            referrer: URL that linked to this page
        """
        if url in self.visited_urls or url in self.in_queue:
            return
        
        # Normalize URL
        url = self.normalize_url(url)
        
        # Queue item with negative priority (PriorityQueue returns lowest first)
        # So we use negative to make higher priority come first
        queue_item = (-priority, self.url_counter, url, depth, referrer)
        self.queue.put(queue_item)
        self.in_queue.add(url)
        self.url_counter += 1
        
    def get_next(self) -> Optional[Tuple[str, int, str]]:
        """Get next URL to crawl"""
        if self.queue.empty():
            return None
        
        priority, _, url, depth, referrer = self.queue.get()
        self.in_queue.discard(url)
        return url, depth, referrer
    
    def mark_visited(self, url: str):
        """Mark URL as visited"""
        url = self.normalize_url(url)
        self.visited_urls.add(url)
        self.in_queue.discard(url)
    
    def is_visited(self, url: str) -> bool:
        """Check if URL has been visited"""
        return self.normalize_url(url) in self.visited_urls
    
    def size(self) -> int:
        """Get number of URLs in queue"""
        return self.queue.qsize()
    
    def visited_count(self) -> int:
        """Get number of visited URLs"""
        return len(self.visited_urls)
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL by removing fragments and trailing slashes"""
        parsed = urlparse(url)
        # Remove fragment
        url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        # Remove trailing slash
        url = url.rstrip('/')
        return url.lower()


class DarkWebCrawler:
    """
    Main crawler for dark web .onion sites
    Handles crawling with respect to rate limits and depth constraints
    """
    
    def __init__(self, tor_manager: TorManager):
        """
        Initialize crawler with Tor manager
        
        Args:
            tor_manager: Configured TorManager instance
        """
        self.tor_manager = tor_manager
        self.logger = logging.getLogger(__name__)
        
        # Crawler configuration
        self.max_depth = config_manager.get('crawler.max_depth', 3)
        self.max_pages_per_site = config_manager.get('crawler.max_pages_per_site', 100)
        self.request_delay = config_manager.get('crawler.request_delay', 5)
        

        #Preprocessing text
        self.processor = DocumentProcessor()


        # Track crawled pages
        self.crawled_pages: List[CrawledPage] = []
        self.failed_urls: List[Tuple[str, str]] = []  # (url, error_reason)
        
        # Domain visit counters
        self.domain_visits: Dict[str, int] = {}

        # URL queue
        self.queue = CrawlerQueue()
        
        # Keywords for relevance scoring
        self.relevance_keywords = config_manager.get_keywords('agriculture_terms')
        
        self.logger.info(f"Crawler initialized: max_depth={self.max_depth}, delay={self.request_delay}s")
    
    def start_crawl(self, seed_urls: List[str]) -> List[CrawledPage]:
        """
        Start crawling from seed URLs
        
        Args:
            seed_urls: List of initial .onion URLs to crawl
        
        Returns:
            List of crawled pages
        """
        self.logger.info(f"Starting crawl with {len(seed_urls)} seed URLs")
        
        # Add seed URLs to queue
        for url in seed_urls:
            self.queue.add_url(url, depth=0, priority=100, referrer="seed")
        
        # Main crawl loop
        while self.queue.size() > 0:
            # Check if we've reached limit
            if len(self.crawled_pages) >= self.max_pages_per_site * len(seed_urls):
                self.logger.info(f"Reached page limit: {len(self.crawled_pages)} pages crawled")
                break
            
            # Get next URL
            next_item = self.queue.get_next()
            if not next_item:
                break
                
            url, depth, referrer = next_item

            self.queue.mark_visited(url)
            
            # Skip if depth exceeded
            if depth > self.max_depth:
                self.logger.debug(f"Skipping {url} - depth {depth} exceeds max {self.max_depth}")
                continue
            
            # Check domain visit limit
            domain = self.extract_domain(url)
            if self.domain_visits.get(domain, 0) >= self.max_pages_per_site:
                self.logger.debug(f"Skipping {url} - reached page limit for domain {domain}")
                continue
            
            # Crawl the page
            self.logger.info(f"Crawling [{depth}/{self.max_depth}]: {url}")
            page = self.crawl_page(url, depth, referrer)
            self.queue.mark_visited(url)
            
            if page:
                self.crawled_pages.append(page)
                self.domain_visits[domain] = self.domain_visits.get(domain, 0) + 1
                self.logger.info(f" Crawled: {url} ({len(page.content)} chars, {len(page.links_found)} links)")
                

                #process Content Here
                processed_doc = self.processor.process_document(
                    raw_text= page.content,
                    source_url= page.url
                )

                self.logger.info(
                    f"Processed: {len(processed_doc.emails)} emails,"
                    f"{len(processed_doc.credentials)} credentials"
                )



                # Extract and queue new links
                self.queue_new_links(page, depth + 1)
            else:
                self.logger.warning(f" Failed to crawl: {url}")
            
            # Respect rate limiting
            time.sleep(self.request_delay)
            
            # Rotate identity periodically
            if len(self.crawled_pages) % 10 == 0 and len(self.crawled_pages) > 0:
                self.logger.info("Rotating Tor identity...")
                self.tor_manager.rotate_identity()
        
        self.logger.info(f"Crawl completed. Crawled: {len(self.crawled_pages)}, Failed: {len(self.failed_urls)}")
        return self.crawled_pages
    
    def crawl_page(self, url: str, depth: int, referrer: str) -> Optional[CrawledPage]:
        """
        Crawl a single page
        
        Args:
            url: URL to crawl
            depth: Current crawl depth
            referrer: URL that linked to this page
        
        Returns:
            CrawledPage object or None if failed
        """
        try:
            # Fetch page content through Tor
            response = self.tor_manager.make_request(url, use_tor=True)
            
            if not response:
                self.failed_urls.append((url, "No response"))
                return None
            if response.status_code == 404:
                self.failed_urls.append((url, "404 Not Found"))
                return None
            
            if response.status_code != 200:
                self.failed_urls.append((url, f"HTTP {response.status_code}"))
                return None
            
            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract title
            title = self.extract_title(soup)
            
            # Extract main content
            content = self.extract_main_content(soup)
            
            # Extract links
            links = self.extract_links(soup, url)
            
            # Generate content hash for deduplication
            content_hash = self.generate_content_hash(content)
            
            # Check if duplicate content
            if self.is_duplicate_content(content_hash):
                self.logger.debug(f"Skipping duplicate content: {url}")
                return None
            
            # Create page object
            page = CrawledPage(
                url=url,
                title=title,
                content=content[:50000],  # Limit content length
                content_length=len(content),
                crawl_depth=depth,
                found_at=referrer,
                crawled_at=datetime.now(),
                status_code=response.status_code,
                links_found=links[:100],  # Limit links stored
                content_type=response.headers.get('content-type', 'unknown'),
                hash_content=content_hash
            )
            
            return page
            
        except Exception as e:
            self.logger.error(f"Error crawling {url}: {str(e)}")
            self.failed_urls.append((url, str(e)))
            return None
    
    def extract_title(self, soup: BeautifulSoup) -> str:
        """Extract page title from HTML"""
        title_tag = soup.find('title')
        if title_tag:
            return title_tag.get_text().strip()[:200]
        return "No Title"
    
    def extract_main_content(self, soup: BeautifulSoup) -> str:
        """
        Extract main textual content from HTML
        Removes script, style tags and extracts meaningful text
        """
        # Remove script and style elements
        for script in soup(["script", "style", "nav", "footer", "header"]):
            script.decompose()
        
        # Get text
        text = soup.get_text()
        
        # Clean up whitespace
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = ' '.join(chunk for chunk in chunks if chunk)
        
        return text
    
    def extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """
        Extract all links from page
        
        Args:
            soup: BeautifulSoup object
            base_url: Base URL for resolving relative links
        
        Returns:
            List of absolute URLs
        """
        links = []
        
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if not href:
                continue
            
            # Resolve relative URLs
            absolute_url = urljoin(base_url, href)
            
            # Only keep .onion links for dark web crawling
            if '.onion' in absolute_url:
                # Normalize URL
                absolute_url = self.normalize_onion_url(absolute_url)
                links.append(absolute_url)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_links = []
        for link in links:
            if link not in seen:
                seen.add(link)
                unique_links.append(link)
        
        return unique_links
    
    def normalize_onion_url(self, url: str) -> str:
        """Normalize .onion URL to standard format"""
        # Ensure scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Remove trailing slashes and fragments
        parsed = urlparse(url)
        url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/')
        
        return url
    
    def queue_new_links(self, page: CrawledPage, next_depth: int):
        """
        Queue new links from crawled page
        
        Args:
            page: Crawled page
            next_depth: Depth for next level
        """
        for link in page.links_found:
            # Skip if already visited
            if self.queue.is_visited(link):
                continue
            
            # Calculate priority based on relevance
            priority = self.calculate_relevance_score(page.content, link)
            
            # Add to queue
            self.queue.add_url(link, depth=next_depth, priority=priority, referrer=page.url)
    
    def calculate_relevance_score(self, content: str, url: str) -> int:
        """
        Calculate relevance score for a URL based on content and URL
        
        Returns:
            Score from 0-100 (higher = more relevant)
        """
        score = 0
        content_lower = content.lower()
        
        # Check for agriculture keywords in content
        for keyword in self.relevance_keywords:
            if keyword.lower() in content_lower:
                score += 10
        
        # Check for credentials patterns
        credentials_patterns = config_manager.get_keywords('credential_patterns')
        for pattern in credentials_patterns:
            if pattern.lower() in content_lower:
                score += 20  # High priority for credentials
        
        # URL-based scoring
        if 'login' in url.lower() or 'auth' in url.lower():
            score += 15
        if 'database' in url.lower() or 'data' in url.lower():
            score += 10
        
        return min(score, 100)  # Cap at 100
    
    def generate_content_hash(self, content: str) -> str:
        """Generate hash for content deduplication"""
        import hashlib
        # Use first 1000 chars for hash to save memory
        content_sample = content[:1000]
        return hashlib.md5(content_sample.encode()).hexdigest()
    
    def is_duplicate_content(self, content_hash: str) -> bool:
        """Check if similar content has been seen"""
        # Simple deduplication - check last 10 pages
        recent_hashes = [p.hash_content for p in self.crawled_pages[-10:]]
        return content_hash in recent_hashes
    
    @staticmethod
    def extract_domain(url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc
    
    def get_crawl_statistics(self) -> Dict[str, Any]:
        """Get statistics about the crawl"""
        return {
            'total_pages_crawled': len(self.crawled_pages),
            'failed_pages': len(self.failed_urls),
            'unique_domains': len(self.domain_visits),
            'queue_size': self.queue.size(),
            'visited_urls': self.queue.visited_count(),
            'pages_with_content': len([p for p in self.crawled_pages if len(p.content) > 100]),
            'average_content_length': sum(p.content_length for p in self.crawled_pages) / max(len(self.crawled_pages), 1),
            'domains_visited': dict(list(self.domain_visits.items())[:10]),  # Top 10 domains
            'failed_urls_sample': self.failed_urls[:5]
        }
    
    def save_crawled_data(self, output_file: str = "crawled_data.json"):
        """Save crawled data to JSON file"""
        data = {
            'crawl_metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_pages': len(self.crawled_pages),
                'max_depth': self.max_depth
            },
            'crawled_pages': [page.to_dict() for page in self.crawled_pages],
            'failed_urls': self.failed_urls
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Saved crawled data to {output_file}")


class CrawlerScheduler:
    """
    Schedules and manages periodic crawling operations
    """
    
    def __init__(self, crawler: DarkWebCrawler):
        self.crawler = crawler
        self.logger = logging.getLogger(__name__)
        self.is_running = False
    
    def run_scheduled_crawl(self, seed_urls: List[str], interval_minutes: int = 60):
        """
        Run crawler at scheduled intervals
        
        Args:
            seed_urls: Seed URLs to crawl
            interval_minutes: Interval between crawls in minutes
        """
        import signal
        
        def signal_handler(signum, frame):
            self.logger.info("Received interrupt signal. Stopping scheduler...")
            self.is_running = False
        
        signal.signal(signal.SIGINT, signal_handler)
        
        self.is_running = True
        crawl_count = 0
        
        while self.is_running:
            crawl_count += 1
            self.logger.info(f"Starting crawl #{crawl_count}")
            
            # Run crawl
            pages = self.crawler.start_crawl(seed_urls)
            
            # Save results
            filename = f"crawl_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            self.crawler.save_crawled_data(filename)
            
            # Print statistics
            stats = self.crawler.get_crawl_statistics()
            self.logger.info(f"Crawl #{crawl_count} completed: {stats['total_pages_crawled']} pages")
            
            if self.is_running:
                self.logger.info(f"Waiting {interval_minutes} minutes until next crawl...")
                time.sleep(interval_minutes * 60)


# Standalone test function
def test_crawler():
    """Test the web crawler module"""
    print("\n" + "="*60)
    print("TESTING WEB CRAWLER MODULE")
    print("="*60)
    
    # Initialize Tor manager
    print("\n[1] Initializing Tor connection...")
    tor_manager = TorManager()
    if not tor_manager.setup_tor_connection():
        print("Tor connection failed. Cannot test crawler.")
        return False
    
    # Initialize crawler
    print("\n[2] Initializing crawler...")
    crawler = DarkWebCrawler(tor_manager)
    
    # Test seed URLs (use known test onion sites or example)
    test_seeds = [
        "http://6e5gwbwm3gos4wbnlltzorgulrd3eipjjbe53n5riutzbpst4f6nw5ad.onion",  # Example - may be down
        "http://darkfailllnkf4vf.onion/"   # Example - may be down
    ]
    
    print(f"\n[3] Starting test crawl with {len(test_seeds)} seed URLs...")
    print("   (Note: Many onion sites may be offline)")
    
    # Limit crawl for testing
    original_limit = crawler.max_pages_per_site
    crawler.max_pages_per_site = 5  # Limit for testing
    
    pages = crawler.start_crawl(test_seeds)
    
    # Print results
    print(f"\n[4] Crawl Results:")
    print(f"   • Pages crawled: {len(pages)}")
    
    if pages:
        print(f"   • First page: {pages[0].url}")
        print(f"   • Title: {pages[0].title[:50]}")
        print(f"   • Content length: {pages[0].content_length} chars")
        print(f"   • Links found: {len(pages[0].links_found)}")
    
    # Print statistics
    print("\n[5] Crawler Statistics:")
    stats = crawler.get_crawl_statistics()
    for key, value in stats.items():
        if key != 'failed_urls_sample':
            print(f"   • {key}: {value}")
    
    # Save data
    crawler.save_crawled_data("test_crawl_output.json")
    print("\n[6] Saved crawled data to test_crawl_output.json")
    
    # Cleanup
    tor_manager.close_connection()
    
    print("\n" + "="*60)
    print("CRAWLER MODULE TEST COMPLETE")
    print("="*60)
    
    return True


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    test_crawler()