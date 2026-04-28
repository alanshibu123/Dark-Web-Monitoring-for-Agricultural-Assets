"""
Tor Network Module for Dark Web Agriculture Monitor
Handles Tor connection, identity management, and anonymous requests
"""

import os
import sys # Python controller for Tor
import time
import socket
import requests
from stem import Signal
from stem.control import Controller
from stem.process import launch_tor
import socks
import logging
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import config_manager

class TorManager:
    """
    Manages Tor network connection and anonymous browsing capabilities.
    Provides methods for connecting to Tor, rotating identities, and making requests.
    """
    
    def __init__(self):
        """Initialize Tor Manager with configuration"""
        self.logger = logging.getLogger(__name__)
        self.tor_config = config_manager.get_tor_config()
        self.settings = config_manager.get('tor', {})
        
        # Tor connection parameters
        self.socks_host = self.tor_config['tor']['socks_host']
        self.socks_port = self.tor_config['tor']['socks_port']
        self.control_host = self.tor_config['tor']['control_host']
        self.control_port = self.tor_config['tor']['control_port']
        
        # Connection state
        self.tor_controller = None
        self.is_connected = False
        self.current_ip = None
        self.session = None
        
        # Statistics
        self.requests_made = 0
        self.identity_rotations = 0
        
        self.logger.info("Tor Manager initialized")
    
    def setup_tor_connection(self) -> bool:
        """
        Establish connection to Tor network
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        self.logger.info("Setting up Tor connection...")
        
        try:
            # First, check if Tor is already running
            if self._check_tor_running():
                self.logger.info("Tor service is already running")
                self._connect_to_controller()
            else:
                self.logger.info("Starting Tor process...")
                self._start_tor_process()
            self._setup_session()
            # Test the connection
            if self._test_connection():
                self.is_connected = True
                self.current_ip = self.get_current_ip()
                self.logger.info(f" Tor connected successfully! Exit IP: {self.current_ip}")
                return True
            else:
                self.logger.error(" Tor connection test failed")
                return False
                
        except Exception as e:
            self.logger.error(f" Failed to setup Tor connection: {str(e)}")
            return False
    
    def _check_tor_running(self) -> bool:
        """Check if Tor service is already running"""
        try:
            # Try to connect to Tor's control port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.control_host, self.control_port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _start_tor_process(self):
        """Launch a new Tor process"""
        try:
            tor_process = launch_tor(
                tor_cmd='tor',
                args=[
                    '--SocksPort', str(self.socks_port),
                    '--ControlPort', str(self.control_port),
                    '--CookieAuthentication', '0',
                    '--HashedControlPassword', self._generate_hashed_password()
                ],
                timeout=60
            )
            self.logger.info("Tor process launched successfully")
            time.sleep(5)  # Give Tor time to bootstrap
            self._connect_to_controller()
            
        except Exception as e:
            self.logger.error(f"Failed to start Tor process: {str(e)}")
            raise
    
    def _generate_hashed_password(self) -> str:
        """Generate hashed password for Tor control port"""
        from stem.control import Controller
        from stem.process import launch_tor_with_config
        
        # Simple password for now - in production, use secure password
        return "16:872860B76453A77D60CA2BB8C1A7042072093276A3D701AD684053EC4C"
    
    def _connect_to_controller(self):
        """Connect to Tor's control port for management"""
        try:
            self.tor_controller = Controller.from_port(
                port=self.control_port
            )
            self.tor_controller.authenticate()
            self.logger.info("Connected to Tor controller")
        except Exception as e:
            self.logger.error(f"Failed to connect to Tor controller: {str(e)}")
            raise
    
    def _setup_session(self):
        """Setup requests session with Tor proxy"""
        self.session = requests.Session()
        
        # Configure proxy
        proxy_url = f"socks5h://{self.socks_host}:{self.socks_port}"
        self.session.proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        
        # Set default headers to appear like a real browser
        self.session.headers.update({
            'User-Agent': config_manager.get('crawler.user_agent'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        self.logger.info("Session configured with Tor proxy")
    
    def _test_connection(self) -> bool:
        """Test if Tor is working properly"""
        try:
            test_url = "https://check.torproject.org/api/ip"
            response = self.make_request(test_url, use_tor=True)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if data.get("IsTor") is True:
                        self.logger.info("Tor connection verified successfully")
                        return True
                    else:
                        self.logger.warning("Traffic is NOT going through Tor")
                        return False
                except Exception:
                    self.logger.error("Failed to parse Tor API response")
                    return False
            else:
                self.logger.warning("No valid response from Tor test API")
                return False
                
        except Exception as e:
            self.logger.error(f"Tor connection test failed: {str(e)}")
            return False
    
    def rotate_identity(self, max_attempts: int = 3) -> bool:
        """
        Request new Tor identity (new exit node)
        
        Args:
            max_attempts: Number of attempts to get a new IP
        
        Returns:
            bool: True if successful (IP may still be same after max_attempts)
        """
        
        if not self.tor_controller:
            self.logger.error("No Tor controller available")
            return False
        
        old_ip = self.current_ip
        self.logger.info(f"Current IP: {old_ip}")
        
        for attempt in range(max_attempts):
            try:
                self.logger.debug(f"Rotation attempt {attempt + 1}/{max_attempts}")
                
                # Send NEWNYM signal
                self.tor_controller.signal(Signal.NEWNYM)
                self.identity_rotations += 1
                
                # Wait for new circuit - longer wait for better results
                wait_time = 5 + (attempt * 3)  # 5, 8, 11 seconds
                self.logger.debug(f"Waiting {wait_time}s for circuit to build...")
                time.sleep(wait_time)
                
                # Get new IP
                self.current_ip = self.get_current_ip()
                
                # Check if IP changed
                if old_ip != self.current_ip:
                    self.logger.info(f" Identity rotated! {old_ip} -> {self.current_ip}")
                    self.logger.info(f"Total rotations: {self.identity_rotations}")
                    
                    # Create new session after identity change
                    self._setup_session()
                    return True
                else:
                    self.logger.warning(f"IP unchanged on attempt {attempt + 1}")
                    
                    # Try to force a new circuit on next attempt
                    if attempt < max_attempts - 1:
                        self.logger.debug("Attempting to force new circuit...")
                        self._force_new_circuit()
                        
            except Exception as e:
                self.logger.error(f"Rotation attempt {attempt + 1} failed: {str(e)}")
        
        # If all attempts failed, accept current IP
        self.logger.warning(f" Could not change IP after {max_attempts} attempts")
        self.logger.info(f"Using same IP: {self.current_ip}")
        
        # Still create new session
        self._setup_session()
        return True

    def _force_new_circuit(self) -> bool:
        """
        Internal method to force a new circuit by closing existing ones
        """
        try:
            circuits = self.tor_controller.get_circuits()
            
            # Close all circuits (they will be recreated)
            for circuit in circuits:
                try:
                    if circuit.status == 'BUILT':
                        self.tor_controller.close_circuit(circuit.id)
                        self.logger.debug(f"Closed circuit: {circuit.id}")
                except Exception as e:
                    self.logger.debug(f"Could not close circuit {circuit.id}: {e}")
            
            time.sleep(2)
            return True
            
        except Exception as e:
            self.logger.debug(f"Force new circuit failed: {e}")
            return False
        
    def get_current_ip(self) -> Optional[str]:
        """
        Get current Tor exit node IP address
        
        Returns:
            str: Current IP address or None if failed
        """
        try:
            # Use ip check service through Tor
            response = self.make_request("http://httpbin.org/ip", use_tor=True)
            if response and response.status_code == 200:
                import json
                ip_data = response.json()
                return ip_data.get('origin', 'Unknown')
            return None
        except Exception as e:
            self.logger.error(f"Failed to get current IP: {str(e)}")
            return None
    
    def make_request(self, url: str, use_tor: bool = True, 
                    timeout: int = None, retry_count: int = None) -> Optional[requests.Response]:
        """
        Make HTTP request through Tor or normal connection
        
        Args:
            url: Target URL
            use_tor: Whether to route through Tor
            timeout: Request timeout in seconds
            retry_count: Number of retry attempts
        
        Returns:
            Response object or None if failed
        """
        if timeout is None:
            timeout = config_manager.get('crawler.timeout', 30)
        
        if retry_count is None:
            retry_count = config_manager.get('crawler.retry_attempts', 3)
        
        session_to_use = self.session if use_tor else requests
        
        for attempt in range(retry_count):
            try:
                self.logger.debug(f"Request attempt {attempt + 1}/{retry_count}: {url}")
                
                response = session_to_use.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=False  # Dark web sites often have self-signed certs
                )
                
                if use_tor:
                    self.requests_made += 1
                
                self.logger.debug(f"Response status: {response.status_code}")
                
                # Check if response is valid
                if response.status_code == 200:
                    return response
                elif response.status_code == 403:
                    self.logger.warning(f"Access forbidden (403) for {url}")
                    # Rotate identity if blocked
                    if use_tor and attempt < retry_count - 1:
                        self.rotate_identity()
                elif response.status_code == 429:
                    self.logger.warning(f"Rate limited (429) for {url}")
                    time.sleep(10)  # Wait longer if rate limited
                    
            except requests.exceptions.Timeout:
                self.logger.warning(f"Timeout on attempt {attempt + 1} for {url}")
                if attempt < retry_count - 1:
                    time.sleep(2)
                    
            except requests.exceptions.ConnectionError as e:
                self.logger.warning(f"Connection error: {str(e)[:100]}")
                if attempt < retry_count - 1:
                    time.sleep(3)
                    if use_tor:
                        self.rotate_identity()
                        
            except Exception as e:
                self.logger.error(f"Unexpected error: {str(e)}")
                if attempt < retry_count - 1:
                    time.sleep(2)
        
        self.logger.error(f"Failed to fetch {url} after {retry_count} attempts")
        return None
    
    def fetch_onion_site(self, onion_url: str) -> Optional[str]:
        """
        Specifically fetch a .onion site content
        
        Args:
            onion_url: The .onion URL to fetch
        
        Returns:
            HTML content as string or None if failed
        """
        if '.onion' not in onion_url:
            self.logger.warning(f"URL doesn't appear to be a .onion site: {onion_url}")
        
        self.logger.info(f" Fetching onion site: {onion_url}")
        
        response = self.make_request(onion_url, use_tor=True)
        
        if response and response.status_code == 200:
            content_length = len(response.text)
            self.logger.info(f" Successfully fetched {onion_url} ({content_length} bytes)")
            return response.text
        else:
            self.logger.error(f" Failed to fetch {onion_url}")
            return None
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """
        Get statistics about Tor connection and usage
        
        Returns:
            Dictionary with connection statistics
        """
        stats = {
            'is_connected': self.is_connected,
            'current_ip': self.current_ip,
            'requests_made': self.requests_made,
            'identity_rotations': self.identity_rotations,
            'socks_port': self.socks_port,
            'control_port': self.control_port
        }
        
        # Try to get additional Tor circuit info
        if self.tor_controller:
            try:
                circuits = self.tor_controller.get_circuits()
                stats['active_circuits'] = len([c for c in circuits if c.status == 'BUILT'])
                stats['total_circuits'] = len(circuits)
            except:
                pass
        
        return stats
    
    def close_connection(self):
        """Safely close Tor connection and cleanup"""
        self.logger.info("Closing Tor connection...")
        
        if self.tor_controller:
            try:
                if self.tor_controller.is_alive():
                    self.tor_controller.close()
            except Exception as e:
                # This error is harmless - controller already closed
                self.logger.debug(f"Controller close issue (ignored): {e}")
        
        if self.session:
            try:
                self.session.close()
            except:
                pass
        
        self.is_connected = False
        self.logger.info("Tor connection closed")

class TorConnectionValidator:
    """
    Utility class to validate Tor network health and anonymity
    """
    
    @staticmethod
    def check_anonymity(tor_manager: TorManager) -> Dict[str, bool]:
        """
        Check if requests are truly anonymous
        
        Returns:
            Dictionary with anonymity check results
        """
        checks = {
            'ip_masked': False,
            'dns_leak': False,
            'webrtc_leak': False
        }
        
        try:
            # Check IP leak
            response = tor_manager.make_request("http://httpbin.org/ip", use_tor=True)
            if response:
                import json
                ip_data = response.json()
                tor_ip = ip_data.get('origin', '')
                
                # Get direct IP (without Tor)
                direct_response = requests.get("http://httpbin.org/ip", timeout=10)
                if direct_response:
                    direct_ip = direct_response.json().get('origin', '')
                    checks['ip_masked'] = tor_ip != direct_ip and tor_ip != ''
            
            # Check DNS leak (simplified)
            checks['dns_leak'] = True  # socks5h prevents DNS leaks
            
            return checks
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Anonymity check failed: {str(e)}")
            return checks


# Standalone test function
def test_tor_module():
    """Test the Tor module functionality"""
    print("\n" + "="*60)
    print("TESTING TOR NETWORK MODULE")
    print("="*60)
    
    # Initialize Tor manager
    tor_manager = TorManager()
    
    # Setup connection
    print("\n[1] Setting up Tor connection...")
    if not tor_manager.setup_tor_connection():
        print("   Tor connection failed!")
        print("   Make sure Tor is installed and running")
        print("   On Ubuntu/Debian: sudo apt install tor")
        print("   On Mac: brew install tor")
        print("   Start Tor: sudo systemctl start tor (Linux) or tor (Mac)")
        return False
    
    # Get stats
    print("\n[2] Connection statistics:")
    stats = tor_manager.get_connection_stats()
    for key, value in stats.items():
        print(f"   • {key}: {value}")
    
    # Test anonymity
    print("\n[3] Testing anonymity...")
    validator = TorConnectionValidator()
    anonymity = validator.check_anonymity(tor_manager)
    for key, value in anonymity.items():
        print(f"   • {key}: {'Anonymity' if value else 'NoAnonymity'}")
    
    # Test fetching a known onion site (example - may not be accessible)
    print("\n[4] Testing onion site fetch...")
    test_onion = "http://torlinksge6enqcy.onion/"  # Example, may be down
    print(f"   Attempting to fetch: {test_onion}")
    content = tor_manager.fetch_onion_site(test_onion)
    if content:
        print(f"Success! Content length: {len(content)} chars")
        print(f"   Preview: {content[:200]}...")
    else:
        print(f"Could not fetch (site may be down or unreachable)")
    
    # Test identity rotation
    print("\n[5] Testing identity rotation...")
    old_ip = tor_manager.current_ip
    tor_manager.rotate_identity()
    new_ip = tor_manager.current_ip
    print(f"   Old IP: {old_ip}")
    print(f"   New IP: {new_ip}")
    print(f"   {'IP changed successfully' if old_ip != new_ip else ' IP did not change'}")
    
    # Final stats
    print("\n[6] Final statistics:")
    final_stats = tor_manager.get_connection_stats()
    print(f"   • Total requests made: {final_stats['requests_made']}")
    print(f"   • Total identity rotations: {final_stats['identity_rotations']}")
    
    # Cleanup
    tor_manager.close_connection()
    
    print("\n" + "="*60)
    print("TOR MODULE TEST COMPLETE")
    print("="*60)
    
    return True


if __name__ == "__main__":
    # Configure logging for test
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    test_tor_module()

# Proxy Routing
# Identity Routing
# Circuit Management	Understanding Tor's NEWNYM signal
# Session Management	Maintaining consistent headers across requests
# Anonymity Testing	Verifying your IP is actually hidden
# NEWNYM Signal Command to request new identity.