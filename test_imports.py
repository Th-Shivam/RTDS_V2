#!/usr/bin/env python3

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("Testing all imports...")

try:
    # Test Flask imports
    from flask import Flask, jsonify, render_template
    from flask_socketio import SocketIO, emit
    from flask_cors import CORS
    print("✅ Flask imports successful")
    
    # Test network monitoring imports
    from scapy.all import sniff, IP, TCP, UDP, ARP, get_if_list
    print("✅ Scapy imports successful")
    
    # Test file monitoring imports
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    print("✅ Watchdog imports successful")
    
    # Test other imports
    import requests
    import sqlite3
    import hashlib
    import time
    import threading
    from datetime import datetime, timedelta
    from collections import defaultdict, deque
    from contextlib import contextmanager
    from dotenv import load_dotenv
    print("✅ Other imports successful")
    
    # Test environment loading
    load_dotenv()
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if api_key:
        print("✅ VirusTotal API key loaded")
    else:
        print("⚠️  VirusTotal API key not found")
    
    print("\n🎉 All imports successful! Project should work now.")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)
