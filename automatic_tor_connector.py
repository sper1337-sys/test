"""
Automatic Tor Connection System
Automatically detects and connects through Tor Browser without user configuration.
Users only need to download and run Tor Browser - no setup required.
"""

import socket
import time
import os
import platform
import subprocess
import requests
import threading
from pathlib import Path
import json
import psutil


class AutomaticTorConnector:
    """
    Automatic Tor connection system that detects and connects through Tor Browser
    without requiring any user configuration.
    """
    
    def __init__(self):
        self.tor_ports = [9050, 9150]  # Standard Tor ports (9050 = Tor daemon, 9150 = Tor Browser)
        self.tor_control_ports = [9051, 9151]  # Control ports
        self.tor_verified = False
        self.active_port = None
        self.session = None
        self.tor_browser_paths = self._get_tor_browser_paths()
        self.connection_status = "disconnected"
        self.last_check_time = 0
        self.check_interval = 30  # Check every 30 seconds
        
    def _get_tor_browser_paths(self):
        """Get common Tor Browser installation paths for different operating systems"""
        system = platform.system().lower()
        paths = []
        
        if system == "windows":
            # Common Windows paths
            paths.extend([
                os.path.expanduser("~/Desktop/Tor Browser/Browser/TorBrowser/Tor/tor.exe"),
                os.path.expanduser("~/Downloads/Tor Browser/Browser/TorBrowser/Tor/tor.exe"),
                "C:/Program Files/Tor Browser/Browser/TorBrowser/Tor/tor.exe",
                "C:/Program Files (x86)/Tor Browser/Browser/TorBrowser/Tor/tor.exe",
                os.path.expanduser("~/AppData/Local/Tor Browser/Browser/TorBrowser/Tor/tor.exe"),
                os.path.expanduser("~/Documents/Tor Browser/Browser/TorBrowser/Tor/tor.exe")
            ])
        elif system == "darwin":  # macOS
            paths.extend([
                "/Applications/Tor Browser.app/Contents/MacOS/Tor/tor",
                os.path.expanduser("~/Applications/Tor Browser.app/Contents/MacOS/Tor/tor"),
                os.path.expanduser("~/Desktop/Tor Browser.app/Contents/MacOS/Tor/tor"),
                os.path.expanduser("~/Downloads/Tor Browser.app/Contents/MacOS/Tor/tor")
            ])
        elif system == "linux":
            paths.extend([
                os.path.expanduser("~/tor-browser_en-US/Browser/TorBrowser/Tor/tor"),
                os.path.expanduser("~/Desktop/tor-browser_en-US/Browser/TorBrowser/Tor/tor"),
                os.path.expanduser("~/Downloads/tor-browser_en-US/Browser/TorBrowser/Tor/tor"),
                "/opt/tor-browser_en-US/Browser/TorBrowser/Tor/tor",
                "/usr/local/bin/tor",
                "/usr/bin/tor"
            ])
        
        return paths
    
    def detect_tor_browser_process(self):
        """Detect if Tor Browser is running"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name'].lower() if proc_info['name'] else ""
                    cmdline = ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ""
                    
                    # Look for Tor Browser processes
                    if any(tor_indicator in proc_name for tor_indicator in ['tor', 'firefox']) and \
                       any(browser_indicator in cmdline.lower() for browser_indicator in ['tor browser', 'torbrowser', 'tor.exe']):
                        return True
                        
                    # Look for standalone Tor processes
                    if 'tor' in proc_name and any(tor_path in cmdline for tor_path in self.tor_browser_paths):
                        return True
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                    
            return False
        except Exception:
            return False
    
    def check_tor_port(self, port):
        """Check if Tor is listening on a specific port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # Reduce timeout from 3s to 0.5s
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def detect_active_tor_port(self):
        """Detect which Tor port is active"""
        for port in self.tor_ports:
            if self.check_tor_port(port):
                return port
        return None
    
    def verify_tor_connection(self):
        """Verify Tor connection by checking IP address"""
        if not self.active_port:
            return False
            
        try:
            # Create a session with Tor proxy
            test_session = requests.Session()
            test_session.proxies = {
                'http': f'socks5h://127.0.0.1:{self.active_port}',
                'https': f'socks5h://127.0.0.1:{self.active_port}'
            }
            test_session.timeout = 3  # Reduce timeout from 10s to 3s
            
            # Test connection by getting IP address
            response = test_session.get('https://check.torproject.org/api/ip', timeout=3)
            if response.status_code == 200:
                data = response.json()
                return data.get('IsTor', False)
                
        except Exception:
            pass
            
        return False
    
    def wait_for_tor_browser(self, timeout=60):
        """Wait for Tor Browser to start and become available"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            # Check if Tor Browser process is running
            if self.detect_tor_browser_process():
                # Give it a moment to fully initialize
                time.sleep(2)
                
                # Check for active Tor port
                active_port = self.detect_active_tor_port()
                if active_port:
                    self.active_port = active_port
                    
                    # Verify the connection actually works
                    if self.verify_tor_connection():
                        self.tor_verified = True
                        self.connection_status = "connected"
                        return True
            
            time.sleep(1)
        
        return False
    
    def setup_automatic_session(self):
        """Setup session with automatic Tor detection"""
        # First, try to detect existing Tor connection
        self.active_port = self.detect_active_tor_port()
        
        if self.active_port and self.verify_tor_connection():
            self.tor_verified = True
            self.connection_status = "connected"
        else:
            self.connection_status = "waiting_for_tor"
            # Wait for Tor Browser to start (reduced timeout)
            if not self.wait_for_tor_browser(timeout=10):  # Reduce from 60s to 10s
                raise Exception("AUTOMATIC TOR CONNECTION FAILED: Please start Tor Browser and try again")
        
        # Create session with detected Tor configuration
        self.session = requests.Session()
        self.session.proxies = {
            'http': f'socks5h://127.0.0.1:{self.active_port}',
            'https': f'socks5h://127.0.0.1:{self.active_port}'
        }
        
        # Enable SSL/TLS verification
        self.session.verify = True
        
        # Set realistic browser headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1'
        })
        
        self.connection_status = "ready"
        return True
    
    def check_connection_health(self):
        """Check if Tor connection is still healthy"""
        current_time = time.time()
        
        # Only check periodically to avoid overhead
        if current_time - self.last_check_time < self.check_interval:
            return self.tor_verified
        
        self.last_check_time = current_time
        
        # Quick port check
        if not self.check_tor_port(self.active_port):
            self.tor_verified = False
            self.connection_status = "disconnected"
            return False
        
        # Verify connection still works
        if not self.verify_tor_connection():
            self.tor_verified = False
            self.connection_status = "disconnected"
            return False
        
        return True
    
    def make_request(self, method, url, **kwargs):
        """Make request through automatic Tor connection"""
        # Check connection health
        if not self.check_connection_health():
            # Try to reconnect
            try:
                self.setup_automatic_session()
            except Exception as e:
                raise Exception(f"AUTOMATIC TOR RECONNECTION FAILED: {str(e)}")
        
        # Ensure session exists
        if not self.session:
            raise Exception("AUTOMATIC TOR ERROR: No session available")
        
        try:
            kwargs['timeout'] = kwargs.get('timeout', 15)
            
            if method.upper() == 'GET':
                return self.session.get(url, **kwargs)
            elif method.upper() == 'POST':
                return self.session.post(url, **kwargs)
            elif method.upper() == 'PUT':
                return self.session.put(url, **kwargs)
            elif method.upper() == 'DELETE':
                return self.session.delete(url, **kwargs)
            else:
                raise Exception(f"Unsupported HTTP method: {method}")
                
        except Exception as e:
            raise Exception(f"AUTOMATIC TOR REQUEST FAILED: {str(e)}")
    
    def get_connection_status(self):
        """Get current connection status"""
        return {
            'status': self.connection_status,
            'tor_verified': self.tor_verified,
            'active_port': self.active_port,
            'tor_browser_detected': self.detect_tor_browser_process(),
            'last_check': self.last_check_time
        }
    
    def get_user_instructions(self):
        """Get user-friendly instructions for setting up Tor"""
        system = platform.system().lower()
        
        instructions = {
            'title': 'Automatic Tor Connection Setup',
            'description': 'This application automatically connects through Tor Browser for maximum security and anonymity.',
            'steps': []
        }
        
        if system == "windows":
            instructions['steps'] = [
                "1. Download Tor Browser from: https://www.torproject.org/download/",
                "2. Install or extract Tor Browser to any location (Desktop, Downloads, etc.)",
                "3. Start Tor Browser and wait for it to connect",
                "4. Keep Tor Browser running in the background",
                "5. Start this application - it will automatically detect and use Tor Browser"
            ]
        elif system == "darwin":
            instructions['steps'] = [
                "1. Download Tor Browser from: https://www.torproject.org/download/",
                "2. Drag Tor Browser to Applications folder or any location",
                "3. Start Tor Browser and wait for it to connect",
                "4. Keep Tor Browser running in the background",
                "5. Start this application - it will automatically detect and use Tor Browser"
            ]
        else:  # Linux
            instructions['steps'] = [
                "1. Download Tor Browser from: https://www.torproject.org/download/",
                "2. Extract the tar.xz file to any location",
                "3. Run ./start-tor-browser.desktop or ./Browser/start-tor-browser",
                "4. Wait for Tor Browser to connect",
                "5. Keep Tor Browser running in the background",
                "6. Start this application - it will automatically detect and use Tor Browser"
            ]
        
        instructions['notes'] = [
            "• No configuration required - the application automatically detects Tor Browser",
            "• Keep Tor Browser running while using this application",
            "• The application will wait up to 60 seconds for Tor Browser to start",
            "• All network traffic will be automatically routed through Tor for anonymity"
        ]
        
        return instructions


class TorConnectionDialog:
    """Dialog to guide users through automatic Tor setup"""
    
    def __init__(self, parent, tor_connector):
        self.parent = parent
        self.tor_connector = tor_connector
        self.dialog = None
        self.status_label = None
        self.progress_var = None
        
    def show_setup_dialog(self):
        """Show Tor setup dialog with automatic detection"""
        import tkinter as tk
        from tkinter import ttk
        
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Automatic Tor Connection Setup")
        self.dialog.geometry("600x500")
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Center dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - 300
        y = (self.dialog.winfo_screenheight() // 2) - 250
        self.dialog.geometry(f"+{x}+{y}")
        
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="🔒 Automatic Tor Connection", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Instructions
        instructions = self.tor_connector.get_user_instructions()
        
        desc_label = ttk.Label(main_frame, text=instructions['description'], 
                              wraplength=550, justify='left')
        desc_label.pack(pady=(0, 15))
        
        # Steps frame
        steps_frame = ttk.LabelFrame(main_frame, text="Setup Steps", padding=10)
        steps_frame.pack(fill=tk.X, pady=(0, 15))
        
        for step in instructions['steps']:
            step_label = ttk.Label(steps_frame, text=step, wraplength=500, justify='left')
            step_label.pack(anchor='w', pady=2)
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Connection Status", padding=10)
        status_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.status_label = ttk.Label(status_frame, text="Waiting for Tor Browser...", 
                                     font=('Arial', 10, 'bold'))
        self.status_label.pack(pady=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, 
                                      mode='indeterminate')
        progress_bar.pack(fill=tk.X, pady=5)
        progress_bar.start()
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(15, 0))
        
        # Auto-connect button
        connect_btn = ttk.Button(button_frame, text="Auto-Connect to Tor", 
                                command=self.start_auto_connection)
        connect_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Manual refresh button
        refresh_btn = ttk.Button(button_frame, text="Check Again", 
                                command=self.check_tor_status)
        refresh_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Cancel button
        cancel_btn = ttk.Button(button_frame, text="Cancel", 
                               command=self.dialog.destroy)
        cancel_btn.pack(side=tk.RIGHT)
        
        # Notes frame
        notes_frame = ttk.LabelFrame(main_frame, text="Important Notes", padding=10)
        notes_frame.pack(fill=tk.X, pady=(15, 0))
        
        for note in instructions['notes']:
            note_label = ttk.Label(notes_frame, text=note, wraplength=500, justify='left')
            note_label.pack(anchor='w', pady=1)
        
        # Start automatic detection
        self.start_auto_connection()
        
        return self.dialog
    
    def start_auto_connection(self):
        """Start automatic Tor connection in background thread"""
        def connect_thread():
            try:
                self.update_status("Detecting Tor Browser...")
                
                if self.tor_connector.setup_automatic_session():
                    self.update_status("✅ Connected to Tor successfully!")
                    self.dialog.after(2000, self.dialog.destroy)  # Close after 2 seconds
                else:
                    self.update_status("❌ Could not connect to Tor. Please check Tor Browser is running.")
                    
            except Exception as e:
                self.update_status(f"❌ Connection failed: {str(e)}")
        
        threading.Thread(target=connect_thread, daemon=True).start()
    
    def check_tor_status(self):
        """Check current Tor status"""
        status = self.tor_connector.get_connection_status()
        
        if status['tor_verified']:
            self.update_status("✅ Tor connection verified and ready!")
        elif status['tor_browser_detected']:
            self.update_status("🔄 Tor Browser detected, verifying connection...")
        else:
            self.update_status("⏳ Waiting for Tor Browser to start...")
    
    def update_status(self, message):
        """Update status label"""
        if self.status_label:
            self.status_label.config(text=message)


# Global instance for easy access
automatic_tor = AutomaticTorConnector()


def get_automatic_tor_connector():
    """Get the global automatic Tor connector instance"""
    return automatic_tor


def show_tor_setup_dialog(parent):
    """Show Tor setup dialog"""
    dialog = TorConnectionDialog(parent, automatic_tor)
    return dialog.show_setup_dialog()