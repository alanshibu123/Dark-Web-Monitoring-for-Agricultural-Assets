"""
Configuration Module for Dark Web Agriculture Monitor
Handles all configuration parameters, environment variables, and runtime settings
"""

import os # Access environmental variables
import yaml # A human-readable fromate
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
import logging # library for recording what the program does.

class ConfigurationManager:
    """
    Central configuration manager for the entire application.
    Loads settings from YAML files and environment variables.
    """
    
    def __init__(self, config_dir: str = "config"): # init (runs when creating a new object)
        """
        Initialize configuration manager
        
        Args:
            config_dir: Directory containing configuration files
        """
        self.config_dir = Path(config_dir)
        self.configs = {}
        self.load_all_configs()
        self.setup_logging()
        
    def load_all_configs(self):
        """Load all configuration files from the config directory"""
        
        # Load main settings if exists
        settings_file = self.config_dir / "settings.yaml"
        if settings_file.exists():
            with open(settings_file, 'r') as f:
                self.configs['settings'] = yaml.safe_load(f)
        else:
            # Default settings
            self.configs['settings'] = self.get_default_settings()
            
        # Load keywords
        keywords_file = self.config_dir / "keywords.yaml"
        if keywords_file.exists():
            with open(keywords_file, 'r') as f:
                self.configs['keywords'] = yaml.safe_load(f)
        else:
            self.configs['keywords'] = self.get_default_keywords()
            
        # Load Tor config
        tor_file = self.config_dir / "tor_config.yaml"
        if tor_file.exists():
            with open(tor_file, 'r') as f:
                self.configs['tor'] = yaml.safe_load(f)
        else:
            self.configs['tor'] = self.get_default_tor_config()
    
    def get_default_settings(self) -> Dict[str, Any]:
        """Return default application settings"""
        return {
            'app': {
                'name': 'Dark Web Agriculture Monitor',
                'version': '1.0.0',
                'environment': 'development',  # development, staging, production
                'debug_mode': True
            },
            'crawler': {
                'max_depth': 3,
                'max_pages_per_site': 100,
                'request_delay': 5,  # seconds between requests
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
                'timeout': 30,
                'retry_attempts': 3
            },
            'tor': {
                'socks_port': 9150,
                'control_port': 9151,
                'password': 'your_tor_password_here',
                'tor_binary_path': '/usr/bin/tor'  # Update based on your OS
            },
            'database': {
                'type': 'sqlite',  # sqlite, postgresql, mysql
                'path': 'data/monitoring.db',
                'backup_interval_hours': 24
            },
            'alerting': {
                'email_enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'from_email': 'alerts@agrimonitor.com',
                'to_emails': ['security@agrifarm.com'],
                'webhook_enabled': False,
                'webhook_url': '',
                'log_alerts': True
            },
            'nlp': {
                'model': 'en_core_web_sm',  # spaCy model
                'sensitivity': 'medium',  # low, medium, high
                'confidence_threshold': 0.7
            },
            'monitoring': {
                'scan_interval_minutes': 60,
                'target_sites': [
                    'http://6e5gwbwm3gos4wbnlltzorgulrd3eipjjbe53n5riutzbpst4f6nw5ad.onion',
                    'http://darkfailllnkf4vf.onion/'
                ],
                'excluded_patterns': [
                    '*.jpg', '*.png', '*.gif', '*.mp4'
                ]
            }
        }
    
    def get_default_keywords(self) -> Dict[str, List[str]]:
        """Return default agriculture-related keywords for monitoring"""
        return {
            'domains': [
                'agrifarm.com',
                'harvestdata.co',
                'cropmonitor.org'
            ],
            'proprietary_terms': [
                'YieldPredict v2',
                'SoilSense Algorithm',
                'CropHealth API'
            ],
            'sensitive_data_types': [
                'passport',
                'ssn',
                'credit card',
                'bank account',
                'passwords'
            ],
            'agriculture_terms': [
                'crop yield data',
                'soil composition',
                'irrigation schedule',
                'fertilizer formula',
                'pesticide mixture',
                'harvest forecast',
                'livestock database',
                'supply chain manifest'
            ],
            'credential_patterns': [
                'password:',
                'login:',
                'username:',
                'api_key:',
                'secret:',
                'token:'
            ]
        }
    
    def get_default_tor_config(self) -> Dict[str, Any]:
        """Return default Tor network configuration"""
        return {
            'tor': {
                'socks_host': '127.0.0.1',
                'socks_port': 9150,
                'control_host': '127.0.0.1',
                'control_port': 9151,
                'torrc_path': '/etc/tor/torrc',
                'new_identity_interval': 300,  # seconds
                'max_circuit_failures': 5
            },
            'proxies': {
                'http': 'socks5h://127.0.0.1:9150',
                'https': 'socks5h://127.0.0.1:9150'
            },
            'verification': {
                'check_ip_url': 'http://check.torproject.org/',
                'expected_string': 'Congratulations'
            }
        }
    
    def setup_logging(self):
        """Configure logging for the entire application"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"agri_monitor_{datetime.now().strftime('%Y%m%d')}.log"
        
        logging.basicConfig(
            level=logging.DEBUG if self.configs['settings']['app']['debug_mode'] else logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()  # Also print to console
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("Configuration Manager initialized successfully")
    
    def get(self, key: str, default=None):
        """
        Get configuration value by dot-notation key
        Example: get('crawler.max_depth') returns 3
        """
        keys = key.split('.')
        value = self.configs.get('settings', {})
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def get_keywords(self, category: str = None) -> Dict[str, List[str]]:
        """Get keywords for a specific category or all keywords"""
        if category:
            return self.configs['keywords'].get(category, [])
        return self.configs['keywords']
    
    def get_tor_config(self) -> Dict[str, Any]:
        """Get Tor network configuration"""
        return self.configs['tor']
    
    def reload_config(self):
        """Reload all configurations (useful for dynamic updates)"""
        self.load_all_configs()
        self.logger.info("Configuration reloaded")
    
    def validate_config(self) -> bool:
        """Validate critical configuration parameters"""
        errors = []
        
        # Check required directories exist
        data_dir = Path(self.get('database.path', 'data')).parent
        data_dir.mkdir(exist_ok=True)
        
        # Validate crawler settings
        if self.get('crawler.max_depth') < 1:
            errors.append("Crawler max_depth must be at least 1")
        
        if self.get('crawler.request_delay') < 1:
            errors.append("Request delay too low - might get blocked")
        
        # Validate alert settings
        if self.get('alerting.email_enabled'):
            if not self.get('alerting.smtp_server'):
                errors.append("Email enabled but SMTP server not configured")
        
        if errors:
            self.logger.error(f"Configuration validation failed: {errors}")
            return False
        
        self.logger.info("Configuration validation passed")
        return True


# Create a global configuration instance for easy import
config_manager = ConfigurationManager()

# Dot-notation Access	config.get('crawler.max_depth') pattern
# Validation Logic  Checking if settings are safe before running.