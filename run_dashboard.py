#!/usr/bin/env python3
"""
Dashboard Launcher for Dark Web Agriculture Monitor
"""

import os
import sys
import webbrowser
import threading
import time

# ============================================================
# FIX: Add parent directory (project root) to path
# ============================================================
# Get the directory containing this file (dashboard folder)
current_dir = os.path.dirname(os.path.abspath(__file__))
# Get the parent directory (project root)
parent_dir = os.path.dirname(current_dir)
# Add project root to path
sys.path.insert(0, parent_dir)


from dashboard.app import run_dashboard
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def open_browser():
    """Open browser after delay"""
    time.sleep(2)
    webbrowser.open('http://localhost:5000')

if __name__ == '__main__':
    print("=" * 60)
    print("DARK WEB AGRICULTURE MONITOR - DASHBOARD")
    print("=" * 60)
    print("\nStarting dashboard server...")
    print("Dashboard will be available at: http://localhost:5000")
    print("Press Ctrl+C to stop\n")
    
    # Open browser automatically
    threading.Thread(target=open_browser, daemon=True).start()
    
    # Run dashboard
    run_dashboard(host='0.0.0.0', port=5000, debug=False)