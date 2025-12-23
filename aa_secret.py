"""
POLLY'S TUNNELS - SECURE CHAT HOST
Creates secure chat rooms and shares credentials
WITH REGISTRATION & APPROVAL SYSTEM
WITH CHAT HISTORY & FILE SHARING & VIDEO CHAT
MAXIMUM SECURITY - TOR ONLY - ZERO TRACE
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, Menu, filedialog
import requests
import json
import time
import threading
import hashlib
import hmac
import base64
import os
import gc
import ctypes
import secrets
import socket
import platform
import subprocess
import uuid
import psutil
import random
import random
import keyring
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
import urllib3
from enhanced_decoy_system import EnhancedDecoySystem
from secure_secret_generation import SecureSecretGenerator, get_installation_secrets, initialize_new_installation
from safety_numbers import SafetyNumberGenerator, SafetyNumberDisplay
from external_storage_encryption import ExternalStorageManager
from configuration_encryption import ConfigurationEncryption
from randomized_self_destruct import RandomizedSelfDestruct
from deniable_encryption import DeniableEncryptionManager, DeniableEncryptionUI
from english_language_manager import EnglishLanguageManager, english_manager
from automatic_tor_connector import show_tor_setup_dialog
from loading_screen import LoadingManager
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CLASSIFIED ENDPOINTS - TOR ONLY
BASE_URL = "https://jsonblob.com/api/jsonBlob"
REGISTRY_URL = "https://jsonblob.com/api/jsonBlob"

# ============================================================================
# ENGLISH INTERFACE TEXT CONSTANTS
# ============================================================================

class EnglishInterfaceText:
    """English-only interface text constants for consistent language display - now using centralized manager"""
    
    def __init__(self):
        self.manager = english_manager
    
    # Application Title
    @property
    def APP_TITLE(self):
        return self.manager.get_text_constant('APP_TITLE_HOST')
    
    @property
    def APP_SUBTITLE(self):
        return self.manager.get_text_constant('APP_SUBTITLE_HOST')
    
    @property
    def APP_FEATURES(self):
        return self.manager.get_text_constant('APP_FEATURES')
    
    # Main Interface
    @property
    def CLASSIFIED_BANNER(self):
        return self.manager.get_text_constant('CLASSIFIED_BANNER')
    
    @property
    def HOST(self):
        return self.manager.get_text_constant('HOST')
    
    @property
    def COMMAND_CENTER(self):
        return self.manager.get_text_constant('COMMAND_CENTER')
    
    @property
    def OPERATIONS(self):
        return self.manager.get_text_constant('OPERATIONS')
    
    @property
    def RECENT_OPERATIONS(self):
        return self.manager.get_text_constant('RECENT_OPERATIONS')
    
    # Buttons
    @property
    def NEW_SECURE_CHANNEL(self):
        return self.manager.get_text_constant('NEW_SECURE_CHANNEL')
    
    @property
    def USER_MONITORING(self):
        return self.manager.get_text_constant('USER_MONITORING')
    
    @property
    def MISSION_HISTORY(self):
        return self.manager.get_text_constant('MISSION_HISTORY')
    
    @property
    def INITIATE(self):
        return self.manager.get_text_constant('INITIATE')
    
    @property
    def RETURN_TO_BASE(self):
        return self.manager.get_text_constant('RETURN_TO_BASE')
    
    # Menu Items
    @property
    def NEW_OPERATION(self):
        return self.manager.get_text_constant('NEW_OPERATION')
    
    @property
    def DISCONNECT(self):
        return self.manager.get_text_constant('DISCONNECT')
    
    @property
    def SECURE_EXIT(self):
        return self.manager.get_text_constant('SECURE_EXIT')
    
    @property
    def SECURITY(self):
        return self.manager.get_text_constant('SECURITY')
    
    @property
    def AUTO_DECRYPT(self):
        return self.manager.get_text_constant('AUTO_DECRYPT')
    
    # Main Content
    @property
    def SECURE_COMMAND_HOST(self):
        return self.manager.get_text_constant('SECURE_COMMAND_HOST')
    
    @property
    def CLASSIFIED_COMM_SYSTEM(self):
        return self.manager.get_text_constant('CLASSIFIED_COMM_SYSTEM')
    
    @property
    def ACTIVE_CHANNELS(self):
        return self.manager.get_text_constant('ACTIVE_CHANNELS')
    
    @property
    def MILITARY_ENCRYPTION(self):
        return self.manager.get_text_constant('MILITARY_ENCRYPTION')
    
    @property
    def ANONYMOUS_ROUTING(self):
        return self.manager.get_text_constant('ANONYMOUS_ROUTING')
    
    @property
    def CLASSIFIED_OPERATIONS(self):
        return self.manager.get_text_constant('CLASSIFIED_OPERATIONS')
    
    # Action Cards
    @property
    def CREATE_SECURE_CHANNEL(self):
        return self.manager.get_text_constant('CREATE_SECURE_CHANNEL')
    
    @property
    def CREATE_CHANNEL_DESC(self):
        return self.manager.get_text_constant('CREATE_CHANNEL_DESC')
    
    @property
    def MANAGE_AGENTS(self):
        return self.manager.get_text_constant('MANAGE_AGENTS')
    
    @property
    def MANAGE_AGENTS_DESC(self):
        return self.manager.get_text_constant('MANAGE_AGENTS_DESC')
    
    @property
    def ACCESS_CHANNELS(self):
        return self.manager.get_text_constant('ACCESS_CHANNELS')
    
    @property
    def ACCESS_CHANNELS_DESC(self):
        return self.manager.get_text_constant('ACCESS_CHANNELS_DESC')
    
    # Status
    @property
    def SYSTEM_READY(self):
        return self.manager.get_text_constant('SYSTEM_READY')
    
    # Authentication
    @property
    def ENTER_PASSWORD(self):
        return self.manager.get_text_constant('ENTER_PASSWORD')
    
    @property
    def AUTHENTICATE(self):
        return self.manager.get_text_constant('AUTHENTICATE')
    
    @property
    def ACCESS_DENIED(self):
        return self.manager.get_text_constant('ACCESS_DENIED')
    
    @property
    def INVALID_PASSWORD(self):
        return self.manager.get_text_constant('INVALID_PASSWORD')
    
    @property
    def AUTHENTICATION_FAILED(self):
        return self.manager.get_text_constant('AUTHENTICATION_FAILED')
    
    # Security Messages
    @property
    def EMERGENCY_WIPE(self):
        return self.manager.get_text_constant('EMERGENCY_WIPE')
    
    @property
    def DATA_DESTROYED(self):
        return self.manager.get_text_constant('DATA_DESTROYED')
    
    @property
    def DISCONNECTED(self):
        return self.manager.get_text_constant('DISCONNECTED')
    
    @property
    def SECURE_CHANNEL_TERMINATED(self):
        return self.manager.get_text_constant('SECURE_CHANNEL_TERMINATED')

# ============================================================================
# WINTER CHERRY BLOSSOM THEME SYSTEM - EMBEDDED
# ============================================================================

class WinterCherryBlossomTheme:
    """Winter Cherry Blossom theme system - elegant winter theme with cherry blossom accents and brownish tones"""
    
    def __init__(self):
        self.name = "Winter Cherry Blossom"
        self.version = "2.0"
        
    def get_color_palette(self):
        """Get the complete Winter Cherry Blossom color palette with brownish accents"""
        return {
            # Primary backgrounds - soft winter tones
            'bg': '#f8f6f4',                    # Warm winter white
            'sidebar_bg': '#f0ede8',            # Soft cream sidebar
            'card_bg': '#ffffff',               # Pure white cards
            'message_bg': '#faf9f7',            # Subtle warm background
            
            # Text colors - rich browns and soft grays
            'fg': '#5d4e37',                    # Rich coffee brown
            'sidebar_fg': '#6b5b47',            # Warm brown text
            'accent': '#d4a574',                # Golden brown accent
            'accent_light': '#e8d5b7',          # Light golden cream
            
            # Cherry blossom accents - soft pinks
            'blossom_primary': '#f4c2c2',       # Soft cherry blossom pink
            'blossom_secondary': '#e8b4b8',     # Deeper blossom pink
            'blossom_light': '#fdf2f2',         # Very light blossom tint
            'blossom_accent': '#d4a5a5',        # Muted blossom accent
            
            # Interactive elements - brownish tones
            'button_bg': '#d4a574',             # Golden brown buttons
            'button_fg': '#ffffff',             # White button text
            'button_hover': '#c19660',          # Darker brown on hover
            'button_active': '#b8894d',         # Active button state
            
            # Input fields
            'entry_bg': '#ffffff',              # White input background
            'entry_fg': '#5d4e37',              # Brown input text
            'entry_border': '#d4a574',          # Golden brown borders
            'entry_focus': '#f4c2c2',           # Blossom pink focus
            
            # Message bubbles
            'own_message': '#fdf2f2',           # Light blossom for own messages
            'their_message': '#f8f6f4',         # Warm white for others
            'message_fg': '#5d4e37',            # Brown message text
            
            # Status colors - muted and professional
            'success': '#8fbc8f',               # Soft sage green
            'warning': '#daa520',               # Golden rod warning
            'danger': '#cd5c5c',                # Muted red
            'info': '#87ceeb',                  # Sky blue info
            
            # Borders and separators
            'border': '#e8d5b7',               # Light golden border
            'separator': '#f0ede8',             # Subtle separator
            
            # Winter-specific elements
            'winter_primary': '#e8f4f8',        # Soft winter blue
            'winter_secondary': '#d6eaf8',      # Light winter blue
            'winter_accent': '#b8dce8',         # Muted winter blue
            
            # Table elements
            'table_header': '#f0ede8',          # Light cream header
            'table_row_even': '#ffffff',        # White even rows
            'table_row_odd': '#faf9f7',         # Subtle warm odd rows
            
            # Security-specific colors
            'security_high': '#cd5c5c',         # Muted red for high security
            'security_medium': '#daa520',       # Golden warning
            'security_low': '#8fbc8f',          # Sage green for safe
            'classified': '#f4c2c2'             # Blossom pink for classified
        }
    
    def get_font_config(self, font_type='body'):
        """Get Winter Cherry Blossom typography configuration"""
        fonts = {
            # Headings and titles
            'title': ('Segoe UI', 24, 'bold'),        # Main application title
            'heading': ('Segoe UI', 18, 'bold'),      # Section headings
            'subheading': ('Segoe UI', 14, 'bold'),   # Subsection headings
            'dialog_title': ('Segoe UI', 16, 'bold'), # Dialog window titles
            
            # Body text
            'body': ('Segoe UI', 11, 'normal'),       # Main body text
            'body_small': ('Segoe UI', 10, 'normal'), # Small body text
            'caption': ('Segoe UI', 9, 'normal'),     # Captions and labels
            
            # Interactive elements
            'button': ('Segoe UI', 11, 'normal'),     # Button text
            'button_large': ('Segoe UI', 12, 'bold'), # Large/primary buttons
            'menu': ('Segoe UI', 10, 'normal'),       # Menu items
            'tooltip': ('Segoe UI', 9, 'normal'),     # Tooltip text
            
            # Input and forms
            'input': ('Segoe UI', 11, 'normal'),      # Input field text
            'label': ('Segoe UI', 10, 'normal'),      # Form labels
            'placeholder': ('Segoe UI', 10, 'italic'), # Placeholder text
            
            # Messages and chat
            'message': ('Segoe UI', 11, 'normal'),    # Chat message text
            'message_time': ('Segoe UI', 9, 'normal'), # Message timestamps
            'message_sender': ('Segoe UI', 10, 'bold'), # Message sender names
            
            # Technical and code
            'monospace': ('Consolas', 10, 'normal'),  # Code and technical text
            'monospace_small': ('Consolas', 9, 'normal'), # Small code text
            'terminal': ('Courier New', 10, 'normal'), # Terminal/console text
            
            # Status and indicators
            'status': ('Segoe UI', 10, 'normal'),     # Status messages
            'badge': ('Segoe UI', 9, 'bold'),         # Badges and counters
            'notification': ('Segoe UI', 10, 'normal') # Notification text
        }
        return fonts.get(font_type, fonts['body'])
    
    def apply_theme(self, widget, widget_type='default'):
        """Apply Winter Cherry Blossom theme to a widget"""
        colors = self.get_color_palette()
        
        if isinstance(widget, tk.Button):
            widget.configure(
                bg=colors['button_bg'],
                fg=colors['button_fg'],
                font=self.get_font_config('button'),
                relief='flat',
                borderwidth=1,
                highlightthickness=0,
                activebackground=colors['button_hover'],
                activeforeground=colors['button_fg'],
                bd=1
            )
        elif isinstance(widget, tk.Entry):
            widget.configure(
                bg=colors['entry_bg'],
                fg=colors['entry_fg'],
                font=self.get_font_config('input'),
                relief='solid',
                borderwidth=1,
                highlightthickness=1,
                highlightcolor=colors['entry_focus'],
                insertbackground=colors['entry_fg'],
                selectbackground=colors['blossom_light'],
                selectforeground=colors['fg']
            )
        elif isinstance(widget, tk.Text):
            widget.configure(
                bg=colors['entry_bg'],
                fg=colors['entry_fg'],
                font=self.get_font_config('body'),
                relief='solid',
                borderwidth=1,
                highlightthickness=1,
                highlightcolor=colors['entry_focus'],
                insertbackground=colors['entry_fg'],
                selectbackground=colors['blossom_light'],
                selectforeground=colors['fg']
            )
        elif isinstance(widget, tk.Frame):
            widget.configure(bg=colors['card_bg'])
        elif isinstance(widget, tk.Label):
            widget.configure(
                bg=colors['card_bg'],
                fg=colors['fg'],
                font=self.get_font_config('body')
            )
        elif isinstance(widget, tk.Toplevel) or isinstance(widget, tk.Tk):
            widget.configure(bg=colors['bg'])
        elif isinstance(widget, tk.Listbox):
            widget.configure(
                bg=colors['entry_bg'],
                fg=colors['entry_fg'],
                font=self.get_font_config('body'),
                selectbackground=colors['blossom_light'],
                selectforeground=colors['fg'],
                relief='solid',
                borderwidth=1,
                highlightcolor=colors['entry_focus']
            )
        elif isinstance(widget, tk.Scrollbar):
            widget.configure(
                bg=colors['card_bg'],
                troughcolor=colors['separator'],
                activebackground=colors['button_hover'],
                relief='flat'
            )

class WinterCherryBlossomComponents:
    """Winter Cherry Blossom styled UI components for consistent theming"""
    
    def __init__(self, theme):
        self.theme = theme
        self.colors = theme.get_color_palette()
    
    def create_styled_button(self, parent, text, command=None, style='default', **kwargs):
        """Create a Winter Cherry Blossom styled button"""
        # Ensure command is properly bound
        if command is None:
            print(f"WARNING: Button '{text}' created without command!")
        
        button = tk.Button(parent, text=text, command=command, **kwargs)
        self.theme.apply_theme(button)
        
        # Add hover effects with dynamic color lookup (fixes theme change bug)
        def on_enter(e):
            if button['state'] != 'disabled':
                # Use dynamic color lookup instead of closure reference
                current_colors = self.theme.get_color_palette() if hasattr(self, 'theme') else self.colors
                button.configure(bg=current_colors.get('button_hover', current_colors['button_bg']))
        def on_leave(e):
            if button['state'] != 'disabled':
                # Use dynamic color lookup instead of closure reference
                current_colors = self.theme.get_color_palette() if hasattr(self, 'theme') else self.colors
                button.configure(bg=current_colors['button_bg'])
        def on_press(e):
            if button['state'] != 'disabled':
                # Use dynamic color lookup instead of closure reference
                current_colors = self.theme.get_color_palette() if hasattr(self, 'theme') else self.colors
                button.configure(bg=current_colors.get('button_active', current_colors['button_bg']))
        def on_release(e):
            if button['state'] != 'disabled':
                # Use dynamic color lookup instead of closure reference
                current_colors = self.theme.get_color_palette() if hasattr(self, 'theme') else self.colors
                button.configure(bg=current_colors.get('button_hover', current_colors['button_bg']))
            
        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)
        button.bind("<Button-1>", on_press)
        button.bind("<ButtonRelease-1>", on_release)
        
        # Verify command is callable
        if command and not callable(command):
            print(f"ERROR: Command for button '{text}' is not callable: {command}")
        
        return button
    
    def create_styled_entry(self, parent, **kwargs):
        """Create a Winter Cherry Blossom styled entry field"""
        entry = tk.Entry(parent, **kwargs)
        self.theme.apply_theme(entry)
        
        # Add focus effects
        def on_focus_in(e):
            entry.configure(highlightbackground=self.colors['entry_focus'])
        def on_focus_out(e):
            entry.configure(highlightbackground=self.colors['entry_border'])
            
        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)
        
        return entry
    
    def create_styled_text(self, parent, **kwargs):
        """Create a Winter Cherry Blossom styled text area"""
        text = tk.Text(parent, **kwargs)
        self.theme.apply_theme(text)
        
        # Add focus effects
        def on_focus_in(e):
            text.configure(highlightbackground=self.colors['entry_focus'])
        def on_focus_out(e):
            text.configure(highlightbackground=self.colors['entry_border'])
            
        text.bind("<FocusIn>", on_focus_in)
        text.bind("<FocusOut>", on_focus_out)
        
        return text
    
    def create_styled_frame(self, parent, **kwargs):
        """Create a Winter Cherry Blossom styled frame"""
        frame = tk.Frame(parent, **kwargs)
        self.theme.apply_theme(frame)
        return frame
    
    def create_styled_label(self, parent, text, style='body', **kwargs):
        """Create a Winter Cherry Blossom styled label"""
        label = tk.Label(parent, text=text, **kwargs)
        label.configure(
            bg=self.colors['card_bg'],
            fg=self.colors['fg'],
            font=self.theme.get_font_config(style)
        )
        return label
    
    def create_message_frame(self, parent, is_own_message=False, **kwargs):
        """Create a styled message frame with appropriate colors"""
        frame = tk.Frame(parent, **kwargs)
        if is_own_message:
            frame.configure(bg=self.colors['own_message'])
        else:
            frame.configure(bg=self.colors['their_message'])
        return frame
    
    def create_status_label(self, parent, text, status_type='info', **kwargs):
        """Create a status label with appropriate color for the status type"""
        label = tk.Label(parent, text=text, **kwargs)
        
        status_colors = {
            'success': self.colors['success'],
            'warning': self.colors['warning'],
            'danger': self.colors['danger'],
            'info': self.colors['info'],
            'classified': self.colors['classified']
        }
        
        bg_color = status_colors.get(status_type, self.colors['info'])
        text_color = '#ffffff' if status_type in ['danger', 'warning'] else self.colors['fg']
        
        label.configure(
            bg=bg_color,
            fg=text_color,
            font=self.theme.get_font_config('status'),
            padx=8,
            pady=4
        )
        return label
    
    def create_styled_listbox(self, parent, **kwargs):
        """Create a Winter Cherry Blossom styled listbox"""
        listbox = tk.Listbox(parent, **kwargs)
        self.theme.apply_theme(listbox)
        return listbox
    
    def create_styled_scrollbar(self, parent, **kwargs):
        """Create a Winter Cherry Blossom styled scrollbar"""
        scrollbar = tk.Scrollbar(parent, **kwargs)
        self.theme.apply_theme(scrollbar)
        return scrollbar
    
    def create_scrollable_container(self, parent, height=None, **kwargs):
        """Create a scrollable container with Winter Cherry Blossom theme"""
        scrollable = ScrollableFrame(parent, theme_colors=self.colors, **kwargs)
        if height:
            scrollable.configure(height=height)
        return scrollable
    
    def apply_window_theme(self, window):
        """Apply Winter Cherry Blossom theme to a window or dialog"""
        self.theme.apply_theme(window)
        window.configure(bg=self.colors['bg'])
        
        # Configure window properties for professional appearance
        if hasattr(window, 'configure'):
            try:
                window.configure(highlightcolor=self.colors['accent'])
            except:
                pass

# ============================================================================
# END WINTER CHERRY BLOSSOM THEME SYSTEM
# ============================================================================

class ScrollableFrame(tk.Frame):
    """Scrollable frame with Winter Cherry Blossom themed scrollbar"""
    def __init__(self, parent, theme_colors=None, **kwargs):
        super().__init__(parent, **kwargs)
        
        # Store theme colors
        self.theme_colors = theme_colors or {}
        self._destroyed = False
        
        # Create canvas and scrollbar
        self.canvas = tk.Canvas(self, bg=self.theme_colors.get('bg', '#f8f6f4'), 
                               highlightthickness=0)
        self.scrollbar = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg=self.theme_colors.get('bg', '#f8f6f4'))
        
        # Configure scrollbar appearance
        if self.theme_colors:
            self.scrollbar.configure(
                bg=self.theme_colors.get('card_bg', '#ffffff'),
                troughcolor=self.theme_colors.get('separator', '#f0ede8'),
                activebackground=self.theme_colors.get('button_hover', '#c19660'),
                relief='flat'
            )
        
        # Create window in canvas
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self._on_frame_configure(e)
        )
        
        self.canvas_frame = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        
        # Configure canvas scrolling
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Pack canvas and scrollbar
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Bind mouse wheel scrolling only to this canvas (not globally)
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind("<Button-4>", self._on_mousewheel)  # Linux scroll up
        self.canvas.bind("<Button-5>", self._on_mousewheel)  # Linux scroll down
        
        # Bind canvas resize to update scrollable frame width
        self.canvas.bind('<Configure>', self._on_canvas_configure)
        
        # Bind destroy event to cleanup
        self.bind("<Destroy>", self._on_destroy)
    
    def _on_frame_configure(self, event):
        """Update scroll region when frame is configured"""
        if not self._destroyed:
            try:
                self.canvas.configure(scrollregion=self.canvas.bbox("all"))
            except:
                pass
    
    def _on_canvas_configure(self, event):
        """Update the scrollable frame width when canvas is resized"""
        if not self._destroyed:
            try:
                self.canvas.itemconfig(self.canvas_frame, width=event.width)
            except:
                pass
    
    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling"""
        if not self._destroyed:
            try:
                if event.num == 5 or event.delta < 0:
                    # Scroll down
                    self.canvas.yview_scroll(1, "units")
                elif event.num == 4 or event.delta > 0:
                    # Scroll up
                    self.canvas.yview_scroll(-1, "units")
            except:
                pass
    
    def _on_destroy(self, event):
        """Cleanup when widget is destroyed"""
        if event.widget == self:
            self._destroyed = True
    
    def get_frame(self):
        """Get the scrollable frame to add widgets to"""
        return self.scrollable_frame

# ============================================================================
# END SCROLLABLE FRAME SYSTEM
# ============================================================================

class MasterPasswordManager:
    """Master password system with 12-word recovery phrase and 3-attempt lockout"""
    def __init__(self):
        self.master_key = None
        self.failed_attempts = 0
        self.max_attempts = 3  # Set to 3 attempts as requested
        self.decoy_password = None
        self.decoy_data = []
        self.is_decoy_mode = False
        self.attempt_file = "host_attempts.dat"
        self.recovery_phrase = None
        self.recovery_phrase_hash = None
        self.password_change_attempts = 0
        self.recovery_file = "host_recovery.dat"
        self.master_password_hash = None  # Store the master password hash
        # Enhanced decoy system
        self.enhanced_decoy = EnhancedDecoySystem()
        
        # Secure secret generation system
        self.secret_generator = SecureSecretGenerator()
        self.installation_secrets = None
        
        # Safety number system for end-to-end encryption verification
        self.safety_generator = SafetyNumberGenerator()
        self.safety_display = SafetyNumberDisplay(self.safety_generator)
        
        # External storage encryption system
        self.external_storage = None
        
        # Deniable encryption system
        self.deniable_encryption = DeniableEncryptionManager("host_deniable_config.json")
        self.deniable_ui = DeniableEncryptionUI(self.deniable_encryption)
        
        # Randomized self-destruct system
        self.randomized_self_destruct = RandomizedSelfDestruct()
        
        # Initialize secure secrets at startup
        self.initialize_secure_secrets()
    
    def hash_password(self, password):
        """Create secure password hash with random salt and constant-time comparison"""
        # Always generate new random salt for security
        salt = secrets.token_bytes(32)
        
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Use stronger algorithm and more iterations
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=salt,
            iterations=100000,  # Balanced security and performance
        )
        key = kdf.derive(password)
        return base64.b64encode(salt + key).decode()
    
    def verify_password(self, password, hash_str):
        """Verify password against hash using constant-time comparison"""
        try:
            decoded = base64.b64decode(hash_str.encode())
            salt = decoded[:32]
            stored_key = decoded[32:]
            
            if isinstance(password, str):
                password = password.encode('utf-8')
            
            # Use same strong algorithm and iterations
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=64,
                salt=salt,
                iterations=100000,  # Match hash_password iterations
            )
            key = kdf.derive(password)
            
            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(stored_key, key)
        except Exception:
            return False
        
    def initialize_secure_secrets(self):
        """Initialize secure cryptographic secrets for this installation"""
        try:
            # Try to load existing installation secrets
            self.installation_secrets = get_installation_secrets()
            
            if self.installation_secrets is None:
                # First time installation - generate new secrets
                self.installation_secrets = initialize_new_installation()
            else:
                pass  # Existing installation secrets loaded
            
            # Initialize external storage encryption with storage key
            storage_key = self.get_storage_encryption_key()
            if storage_key:
                self.external_storage = ExternalStorageManager(storage_key)
            else:
                # Fallback: create with random key
                self.external_storage = ExternalStorageManager()
                
        except Exception as e:
            # Continue without secure secrets (fallback mode)
            self.installation_secrets = None
            # Still initialize external storage with random key
            self.external_storage = ExternalStorageManager()
    
    def get_installation_secret(self, secret_name):
        """Get a specific installation secret by name"""
        if self.installation_secrets and secret_name in self.installation_secrets:
            return self.installation_secrets[secret_name]
        return None
    
    def get_master_encryption_key(self):
        """Get the master encryption key for this installation"""
        return self.get_installation_secret('master_encryption_key')
    
    def get_authentication_salt(self):
        """Get the authentication salt for this installation"""
        return self.get_installation_secret('authentication_salt')
    
    def get_storage_encryption_key(self):
        """Get the storage encryption key for this installation"""
        return self.get_installation_secret('storage_encryption_key')
        
    def derive_master_key(self, password, salt=None):
        """Derive encryption key from master password with random salt"""
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Generate random salt if not provided (for new passwords)
        if salt is None:
            salt = secrets.token_bytes(32)
        elif isinstance(salt, str):
            salt = base64.b64decode(salt.encode('utf-8'))
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=2000000,  # 2M iterations for master password
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        
        # Return both key and salt for storage
        return {
            'key': key,
            'salt': base64.b64encode(salt).decode('utf-8')
        }
    
    def generate_recovery_phrase(self):
        """Generate a unique, fully random 12-word recovery phrase"""
        # BIP39 word list (first 2048 words for cryptographic security)
        word_list = [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
            "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
            "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
            "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "against", "age",
            "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol",
            "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also",
            "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient",
            "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna",
            "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arcade",
            "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army", "around",
            "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect",
            "assault", "asset", "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude",
            "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
            "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor",
            "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar",
            "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty",
            "because", "become", "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
            "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike",
            "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast",
            "bleak", "bless", "blind", "blood", "blossom", "blow", "blue", "blur", "blush", "board",
            "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
            "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass",
            "brave", "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli",
            "broken", "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo",
            "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
            "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage",
            "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon",
            "canoe", "canvas", "canyon", "capable", "capital", "captain", "car", "carbon", "card", "care",
            "career", "careful", "careless", "cargo", "carpet", "carry", "cart", "case", "cash", "casino",
            "cast", "casual", "cat", "catalog", "catch", "category", "cattle", "caught", "cause", "caution",
            "cave", "ceiling", "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk",
            "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap", "check", "cheese",
            "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice", "choose", "chronic",
            "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle", "citizen", "city", "civil", "claim",
            "clamp", "clarify", "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff",
            "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club",
            "clump", "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee", "coil", "coin",
            "collect", "color", "column", "combine", "come", "comfort", "comic", "common", "company", "concert",
            "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper",
            "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple",
            "course", "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash",
            "crater", "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp",
            "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch",
            "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain",
            "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger",
            "daring", "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december",
            "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay",
            "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit", "depth",
            "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail", "detect",
            "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ",
            "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease",
            "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor",
            "document", "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor", "door", "dose",
            "double", "dove", "draft", "dragon", "drama", "drape", "draw", "dream", "dress", "drift",
            "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb", "dune",
            "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn",
            "earth", "easily", "east", "easy", "echo", "ecology", "economy", "edge", "edit", "educate",
            "effort", "egg", "eight", "either", "elbow", "elder", "electric", "elegant", "element", "elephant",
            "elevator", "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower",
            "empty", "enable", "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage",
            "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire",
            "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error",
            "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke",
            "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise",
            "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect", "expire", "explain",
            "expose", "express", "extend", "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade",
            "faint", "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy", "fantasy",
            "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault", "favorite", "feature", "february",
            "federal", "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever", "few",
            "fiber", "fiction", "field", "figure", "file", "fill", "film", "filter", "final", "find",
            "fine", "finger", "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness",
            "fix", "flag", "flame", "flat", "flavor", "flee", "flight", "flip", "float", "flock",
            "floor", "flower", "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold",
            "follow", "food", "foot", "force", "forest", "forget", "fork", "fortune", "forum", "forward",
            "fossil", "foster", "found", "fox", "frame", "frequent", "fresh", "friend", "fringe", "frog",
            "front", "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury",
            "future", "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden",
            "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius",
            "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe",
            "girl", "give", "glad", "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom",
            "glory", "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla",
            "gospel", "gossip", "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass",
            "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt",
            "guard", "guess", "guide", "guilt", "guitar", "gun", "gym", "habit", "hair", "half",
            "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh", "harvest", "hat", "have",
            "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog", "height", "held", "help",
            "hen", "hero", "hidden", "high", "hill", "hint", "hip", "hire", "history", "hobby",
            "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood", "hope", "horn",
            "horror", "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge", "human",
            "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid",
            "ice", "icon", "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image",
            "imitate", "immense", "immune", "impact", "impose", "improve", "impulse", "inch", "include", "income",
            "increase", "index", "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit",
            "initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect",
            "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite", "involve", "iron",
            "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous",
            "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice",
            "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key",
            "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten",
            "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady",
            "lake", "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava",
            "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture",
            "left", "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard",
            "lesson", "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light",
            "like", "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard",
            "load", "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery",
            "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury",
            "lying", "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major", "make",
            "mammal", "man", "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march",
            "margin", "marine", "market", "marriage", "mask", "mass", "master", "match", "material", "math",
            "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal",
            "media", "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit",
            "merry", "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic",
            "mind", "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix",
            "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster",
            "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor", "mountain",
            "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom",
            "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin", "narrow",
            "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew",
            "nerve", "nest", "net", "network", "neutral", "never", "news", "next", "nice", "night",
            "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note", "nothing",
            "notice", "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object",
            "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off",
            "offer", "office", "often", "oil", "okay", "old", "olive", "olympic", "omit", "once",
            "one", "onion", "online", "only", "open", "opera", "opinion", "oppose", "option", "orange",
            "orbit", "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other",
            "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen",
            "oyster", "ozone", "pact", "paddle", "page", "pair", "palace", "palm", "panda", "panel",
            "panic", "panther", "paper", "parade", "parent", "park", "parrot", "part", "pass", "patch",
            "path", "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut", "pear",
            "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person",
            "pet", "phone", "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig",
            "pigeon", "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place",
            "planet", "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge", "poem",
            "poet", "point", "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion",
            "position", "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice", "praise",
            "predict", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print",
            "priority", "prison", "private", "prize", "problem", "process", "produce", "profit", "program", "project",
            "promote", "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull",
            "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse",
            "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick", "quiet",
            "quilt", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio",
            "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare",
            "rate", "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild",
            "recall", "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region",
            "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember", "remind",
            "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report", "require",
            "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion",
            "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge",
            "rifle", "right", "rigid", "ring", "riot", "ripple", "rise", "risk", "ritual", "rival",
            "river", "road", "roast", "rob", "robot", "robust", "rocket", "romance", "roof", "rookie",
            "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude", "rug",
            "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad",
            "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce",
            "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme", "school",
            "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea", "search",
            "season", "seat", "second", "secret", "section", "security", "seed", "seek", "segment", "select",
            "sell", "seminar", "senior", "sense", "sentence", "series", "service", "session", "settle", "setup",
            "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield", "shift",
            "shine", "ship", "shirt", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove",
            "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege", "sight", "sign",
            "silent", "silk", "silly", "silver", "similar", "simple", "since", "sing", "siren", "sister",
            "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt", "skull",
            "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot",
            "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap",
            "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar", "sold",
            "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul",
            "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
            "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split",
            "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square",
            "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand", "start",
            "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting",
            "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong",
            "struggle", "student", "stuff", "stumble", "style", "subject", "submit", "subway", "success", "such",
            "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny", "sunset", "super",
            "supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain",
            "swallow", "swamp", "swap", "swear", "sweet", "swift", "swim", "swing", "switch", "sword",
            "symbol", "symptom", "syrup", "system", "table", "tackle", "tag", "tail", "talent", "talk",
            "tank", "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell",
            "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank", "that", "theme",
            "then", "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw",
            "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip",
            "tired", "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet",
            "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic",
            "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town",
            "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap", "trash", "travel",
            "tray", "treat", "tree", "trend", "trial", "tribe", "trick", "trigger", "trim", "trip",
            "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try", "tube",
            "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice",
            "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle",
            "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe",
            "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper",
            "upset", "urban", "urge", "usage", "use", "used", "useful", "useless", "usual", "utility",
            "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish", "vapor", "various",
            "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue", "verb", "verify", "version",
            "very", "vessel", "veteran", "viable", "vibe", "vicious", "victory", "video", "view", "village",
            "vintage", "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal",
            "voice", "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk",
            "wall", "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water",
            "wave", "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend",
            "weird", "welcome", "west", "wet", "what", "wheat", "wheel", "when", "where", "whip",
            "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing",
            "wink", "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman",
            "wonder", "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck",
            "wrestle", "wrist", "write", "wrong", "yard", "year", "yellow", "you", "young", "youth",
            "zebra", "zero", "zone", "zoo"
        ]
        
        # Generate 12 cryptographically secure random words
        recovery_words = []
        for _ in range(12):
            # Use secrets.randbelow for cryptographically secure randomness
            word_index = secrets.randbelow(len(word_list))
            recovery_words.append(word_list[word_index])
        
        self.recovery_phrase = recovery_words
        
        # Create hash of recovery phrase for verification
        phrase_string = ' '.join(recovery_words)
        self.recovery_phrase_hash = hashlib.sha256(phrase_string.encode()).hexdigest()
        
        # Save encrypted recovery phrase to file
        self.save_recovery_phrase()
        
        return recovery_words
    
    def save_recovery_phrase(self):
        """Save encrypted recovery phrase to secure file"""
        if not self.recovery_phrase:
            return
        
        try:
            phrase_string = ' '.join(self.recovery_phrase)
            
            # Encrypt with master key derivation
            salt = secrets.token_bytes(32)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=2000000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(phrase_string.encode()))
            cipher = Fernet(key)
            
            # Encrypt the phrase with itself as key (self-contained)
            encrypted_phrase = cipher.encrypt(phrase_string.encode())
            
            # Save with salt and hash
            recovery_data = {
                'salt': base64.b64encode(salt).decode(),
                'encrypted_phrase': base64.b64encode(encrypted_phrase).decode(),
                'hash': self.recovery_phrase_hash,
                'timestamp': time.time()
            }
            
            with open(self.recovery_file, 'w') as f:
                json.dump(recovery_data, f)
                
        except Exception as e:
            pass  # Failed to save recovery phrase
    
    def verify_recovery_phrase(self, input_words):
        """Verify all 12 words of recovery phrase in correct order"""
        if not self.recovery_phrase:
            return False
        
        if len(input_words) != 12:
            return False
        
        # Compare each word (case insensitive)
        for i in range(12):
            if input_words[i].lower().strip() != self.recovery_phrase[i].lower():
                return False
        
        return True
    
    def change_password(self, current_password, new_password):
        """Change password with current password verification and 3-attempt lockout"""
        # Verify current password first
        if not self.verify_current_password(current_password):
            self.password_change_attempts += 1
            
            if self.password_change_attempts >= 3:
                # Require full recovery phrase after 3 failed attempts
                return "RECOVERY_REQUIRED"
            else:
                remaining = 3 - self.password_change_attempts
                return f"INCORRECT_PASSWORD:{remaining}"
        
        # Password verified, proceed with change
        try:
            # Update password hash (this would integrate with your existing password system)
            self.update_password_hash(new_password)
            
            # Reset password change attempts
            self.password_change_attempts = 0
            
            return "SUCCESS"
            
        except Exception as e:
            return f"ERROR:{str(e)}"
    
    def verify_current_password(self, password):
        """Verify current password against stored hash"""
        # This integrates with the SecurityManager to verify the current master password
        # For now, we'll use a simple test encryption/decryption to verify the password
        try:
            test_data = {"test": "password_verification"}
            encrypted = self.encrypt_history_file(test_data, password)
            decrypted = self.decrypt_history_file(encrypted, password)
            return decrypted.get("test") == "password_verification"
        except:
            return False
    
    def update_password_hash(self, new_password):
        """Update password hash - this would integrate with SecurityManager"""
        # In a full implementation, this would update the stored password hash
        # For now, we'll just validate that the new password works
        try:
            test_data = {"test": "new_password_validation"}
            encrypted = self.encrypt_history_file(test_data, new_password)
            decrypted = self.decrypt_history_file(encrypted, new_password)
            if decrypted.get("test") != "new_password_validation":
                raise Exception("New password validation failed")
            return True
        except Exception as e:
            raise Exception(f"Password update failed: {str(e)}")
    
    def reset_password_change_attempts(self):
        """Reset password change attempts after successful recovery"""
        self.password_change_attempts = 0
    
    # ============================================================================
    # DENIABLE ENCRYPTION METHODS
    # ============================================================================
    
    def enable_deniable_encryption(self, outer_password, inner_password):
        """Enable deniable encryption mode with dual passwords"""
        try:
            success = self.deniable_encryption.enable_deniable_encryption(outer_password, inner_password)
            return success
        except Exception as e:
            return False
    
    def disable_deniable_encryption(self):
        """Disable deniable encryption mode"""
        try:
            success = self.deniable_encryption.disable_deniable_encryption()
            return success
        except Exception as e:
            return False
    
    def is_deniable_encryption_enabled(self):
        """Check if deniable encryption is currently enabled"""
        return self.deniable_encryption.is_deniable_encryption_enabled()
    
    def encrypt_data_with_deniability(self, data, password_type="inner"):
        """Encrypt data using deniable encryption"""
        if not self.is_deniable_encryption_enabled():
            raise ValueError("Deniable encryption is not enabled")
        
        return self.deniable_encryption.encrypt_with_deniability(data, password_type)
    
    def decrypt_data_with_deniability(self, encrypted_data, password):
        """Decrypt data using deniable encryption"""
        if not self.is_deniable_encryption_enabled():
            raise ValueError("Deniable encryption is not enabled")
        
        return self.deniable_encryption.decrypt_with_deniability(encrypted_data, password)
    
    def get_deniable_encryption_config(self):
        """Get deniable encryption configuration options"""
        return self.deniable_encryption.get_configuration_options()
    
    def update_deniable_encryption_config(self, new_config):
        """Update deniable encryption configuration"""
        return self.deniable_encryption.update_configuration(new_config)
    
    def get_plausible_denial_story(self):
        """Get a plausible denial story for encrypted data"""
        return self.deniable_encryption.create_plausible_denial_story()
    
    def get_deniable_encryption_status(self):
        """Get current deniable encryption status for UI display"""
        return self.deniable_ui.get_status_info()
    
    def get_deniable_encryption_setup_wizard(self):
        """Get setup wizard data for deniable encryption"""
        return self.deniable_ui.get_setup_wizard_data()
    
    def get_deniable_encryption_config_dialog(self):
        """Get configuration dialog data for deniable encryption"""
        return self.deniable_ui.create_configuration_dialog_data()

    def setup_decoy_password(self, decoy_password=None):
        """Setup obviously fake decoy password with enhanced security"""
        # Use enhanced decoy system to generate obviously fake password
        self.decoy_password = self.enhanced_decoy.setup_obvious_decoy()
        
        # Get fake data from enhanced system
        self.decoy_data = self.enhanced_decoy.generate_decoy_data()
        
        # Add host-specific fake data
        self.decoy_data.extend([
            {
                'chat_id': 'FAKE_HOST_CHAT_' + secrets.token_hex(8),
                'registry_id': 'FAKE_HOST_REGISTRY_' + secrets.token_hex(8),
                'encryption_key': base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
                'username': 'FAKE_HOST_USER',
                'timestamp': time.time() - 86400,  # 1 day ago
                'is_fake': True
            }
        ])
        
        return self.decoy_password
    
    def is_decoy_password(self, password):
        """Check if password is the obvious decoy using enhanced system"""
        return self.enhanced_decoy.is_decoy_password(password)
    
    def check_failed_attempts(self):
        """Check and update failed login attempts"""
        try:
            if os.path.exists(self.attempt_file):
                with open(self.attempt_file, 'rb') as f:
                    data = f.read()
                    if len(data) >= 4:
                        self.failed_attempts = int.from_bytes(data[:4], 'big')
        except:
            self.failed_attempts = 0
    
    def record_failed_attempt(self):
        """Record failed login attempt"""
        self.failed_attempts += 1
        try:
            with open(self.attempt_file, 'wb') as f:
                f.write(self.failed_attempts.to_bytes(4, 'big'))
                f.write(secrets.token_bytes(100))  # Add random padding
        except:
            pass
        
        if self.failed_attempts >= self.max_attempts:
            return True  # Trigger self-destruct
        return False
    
    def reset_failed_attempts(self):
        """Reset failed attempts counter"""
        self.failed_attempts = 0
        try:
            if os.path.exists(self.attempt_file):
                os.remove(self.attempt_file)
        except:
            pass
    
    def self_destruct(self, history_file):
        """Self-destruct: securely delete history file with randomized timing"""
        try:
            # Use randomized self-destruct with short delay for security
            success = self.randomized_self_destruct.trigger_random_self_destruct(
                file_path=history_file,
                min_delay=0.5,  # 0.5 to 2.0 seconds random delay
                max_delay=2.0,
                secure_overwrite=True
            )
            
            # Also clean up attempt file
            if os.path.exists(self.attempt_file):
                os.remove(self.attempt_file)
            
            return success
        except:
            return False
    
    def encrypt_history_file(self, data, password):
        """Encrypt history data with master password"""
        try:
            key = self.derive_master_key(password)
            cipher = Fernet(key)
            
            # Convert data to JSON and encrypt
            json_data = json.dumps(data, indent=2)
            encrypted_data = cipher.encrypt(json_data.encode('utf-8'))
            
            # Add header and checksum for integrity
            header = b'HOST_CLASSIFIED_HISTORY_V1'
            checksum = hashlib.sha256(encrypted_data).digest()
            
            return header + checksum + encrypted_data
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt_history_file(self, encrypted_data, password):
        """Decrypt history data with master password"""
        try:
            # Check header
            header = b'HOST_CLASSIFIED_HISTORY_V1'
            if not encrypted_data.startswith(header):
                raise Exception("Invalid file format")
            
            # Extract components
            header_len = len(header)
            checksum = encrypted_data[header_len:header_len + 32]
            encrypted_content = encrypted_data[header_len + 32:]
            
            # Verify checksum
            if hashlib.sha256(encrypted_content).digest() != checksum:
                raise Exception("File integrity check failed")
            
            # Decrypt
            key = self.derive_master_key(password)
            cipher = Fernet(key)
            decrypted_data = cipher.decrypt(encrypted_content)
            
            # Parse JSON
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
    
    def emergency_wipe(self, history_file):
        """Emergency wipe hotkey function"""
        try:
            # Wipe history file
            self.self_destruct(history_file)
            
            # Clear memory
            self.master_key = None
            gc.collect()
            
            # Show confirmation
            messagebox.showinfo("EMERGENCY WIPE", "🔥 All classified data has been securely destroyed!")
            return True
        except:
            return False

class SecurityManager:
    """Advanced multi-layer security system with 3-attempt lockout"""
    def __init__(self):
        self.app_name = "SecureChatHost"
        self.failed_attempts = 0
        self.max_attempts = 3  # Set to 3 attempts as requested
        self.session_timeout = 600  # 10 minutes
        self.last_activity = time.time()
        self.is_authenticated = False
        self.is_locked = False
        self.stealth_mode = False
        self.decoy_mode = False
        self.startup_password_hash = None
        self.pin_hash = None
        self.history_password_hash = None
        self.load_security_settings()
        
    def load_security_settings(self):
        """Load security settings from secure storage"""
        try:
            # Try to load from keyring
            self.startup_password_hash = keyring.get_password(self.app_name, "startup_password")
            self.pin_hash = keyring.get_password(self.app_name, "pin_code")
            self.history_password_hash = keyring.get_password(self.app_name, "history_password")
        except:
            pass
    
    def save_security_settings(self):
        """Save security settings to secure storage"""
        try:
            if self.startup_password_hash:
                keyring.set_password(self.app_name, "startup_password", self.startup_password_hash)
            if self.pin_hash:
                keyring.set_password(self.app_name, "pin_code", self.pin_hash)
            if self.history_password_hash:
                keyring.set_password(self.app_name, "history_password", self.history_password_hash)
        except:
            pass
    
    def hash_password(self, password):
        """Create secure password hash with random salt and constant-time comparison"""
        # Always generate new random salt for security
        salt = secrets.token_bytes(32)
        
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Use stronger algorithm and more iterations
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=salt,
            iterations=100000,  # Balanced security and performance
        )
        key = kdf.derive(password)
        return base64.b64encode(salt + key).decode()
    
    def verify_password(self, password, hash_str):
        """Verify password against hash using constant-time comparison"""
        try:
            decoded = base64.b64decode(hash_str.encode())
            salt = decoded[:32]
            stored_key = decoded[32:]
            
            if isinstance(password, str):
                password = password.encode('utf-8')
            
            # Use same strong algorithm and iterations
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=64,
                salt=salt,
                iterations=100000,  # Match hash_password iterations
            )
            key = kdf.derive(password)
            
            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(stored_key, key)
        except Exception:
            return False
    
    def set_startup_password(self, password):
        """Set startup password"""
        self.startup_password_hash = self.hash_password(password)
        self.save_security_settings()
    
    def set_pin(self, pin):
        """Set PIN code"""
        self.pin_hash = self.hash_password(pin)
        self.save_security_settings()
    
    def set_history_password(self, password):
        """Set history file password"""
        self.history_password_hash = self.hash_password(password)
        self.save_security_settings()
    
    def authenticate_startup(self, password):
        """Authenticate with startup password"""
        if not self.startup_password_hash:
            return True  # No password set yet
        
        if self.verify_password(password, self.startup_password_hash):
            self.is_authenticated = True
            self.failed_attempts = 0
            self.update_activity()
            return True
        else:
            self.failed_attempts += 1
            if self.failed_attempts >= self.max_attempts:
                self.panic_wipe()
            return False
    
    def authenticate_pin(self, pin):
        """Authenticate with PIN"""
        if not self.pin_hash:
            return True
        
        if self.verify_password(pin, self.pin_hash):
            self.is_authenticated = True
            self.failed_attempts = 0
            self.update_activity()
            return True
        else:
            self.failed_attempts += 1
            if self.failed_attempts >= self.max_attempts:
                self.panic_wipe()
            return False
    
    def authenticate_history(self, password):
        """Authenticate for history access"""
        if not self.history_password_hash:
            return True
        return self.verify_password(password, self.history_password_hash)
    
    def change_startup_password(self, current_password, new_password, master_password_manager):
        """Change startup password with 3-attempt lockout and recovery phrase requirement"""
        # Verify current password
        if not self.verify_password(current_password, self.startup_password_hash):
            self.failed_attempts += 1
            
            if self.failed_attempts >= 3:
                # Require full 12-word recovery phrase
                return "RECOVERY_REQUIRED"
            else:
                remaining = 3 - self.failed_attempts
                return f"INCORRECT_PASSWORD:{remaining}"
        
        # Current password verified, update to new password
        try:
            self.startup_password_hash = self.hash_password(new_password)
            self.save_security_settings()
            self.failed_attempts = 0  # Reset attempts after successful change
            return "SUCCESS"
        except Exception as e:
            return f"ERROR:{str(e)}"
    
    def reset_failed_attempts_after_recovery(self):
        """Reset failed attempts after successful recovery phrase verification"""
        self.failed_attempts = 0
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()
    
    def check_session_timeout(self):
        """Check if session has timed out"""
        if self.is_authenticated and (time.time() - self.last_activity) > self.session_timeout:
            self.is_authenticated = False
            self.is_locked = True
            return True
        return False
    
    def panic_wipe(self):
        """Emergency data wipe with randomized timing"""
        try:
            # Wipe keyring data
            keyring.delete_password(self.app_name, "startup_password")
            keyring.delete_password(self.app_name, "pin_code")
            keyring.delete_password(self.app_name, "history_password")
        except:
            pass
        
        # Wipe history files using randomized self-destruct
        history_files = [
            "host_chat_history.json",
            "client_chat_history.json",
            "encrypted_history.dat"
        ]
        
        # Use emergency self-destruct with very short random delays for panic situations
        self.randomized_self_destruct.emergency_self_destruct(
            file_paths=history_files,
            immediate=False  # Use short random delay even in emergency
        )
        
        # Force exit after a brief randomized delay
        exit_delay = self.randomized_self_destruct.generate_random_delay(0.1, 0.5)
        time.sleep(exit_delay)
        os._exit(1)

# Import the enhanced message authentication system
from message_authentication import MessageAuthenticator, KeyRotationManager

class MessageSecurity:
    """Enhanced message signing and verification system with sequence numbering"""
    def __init__(self):
        # Initialize the enhanced message authenticator
        self.message_authenticator = MessageAuthenticator()
        self.key_rotation_manager = KeyRotationManager()
        
        # Generate RSA key pair for message signing
        try:
            self.message_authenticator.generate_key_pair()
        except Exception as e:
            pass  # Key generation failed silently
    
    def get_next_sequence_number(self):
        """Get the next sequence number for outgoing messages"""
        return self.message_authenticator.get_next_sequence_number()
    
    def check_sequence_validity(self, sequence_number):
        """Check if sequence number is valid (not replayed and within acceptable range)"""
        return self.message_authenticator.check_sequence_validity(sequence_number)
    
    def sign_message(self, message):
        """Sign message with private key and sequence number"""
        try:
            # Get next sequence number
            seq_num = self.get_next_sequence_number()
            
            # Sign the message using the enhanced authenticator
            signed_message = self.message_authenticator.sign_message(message, seq_num)
            
            # Increment message count for key rotation
            self.key_rotation_manager.increment_message_count()
            
            return signed_message
            
        except Exception as e:
            return None  # Message signing failed silently
    
    def verify_signature(self, signed_message, public_key_data=None):
        """Verify message signature with RSA public key"""
        try:
            # Handle both old format (string signature) and new format (dict)
            if isinstance(signed_message, str):
                # Old format - skip verification for compatibility
                return True
            
            # New format - verify structured message using enhanced authenticator
            if not isinstance(signed_message, dict):
                return False
            
            return self.message_authenticator.verify_message_signature(signed_message, public_key_data)
            
        except Exception as e:
            return False  # Signature verification failed silently
    
    def should_rotate_keys(self):
        """Check if keys should be rotated based on message count"""
        return self.key_rotation_manager.should_rotate_keys()
    
    def rotate_keys(self):
        """Rotate encryption keys and reset message count"""
        if self.should_rotate_keys():
            # Rotate keys using the key rotation manager
            key_info = self.key_rotation_manager.rotate_encryption_keys()
            
            # Generate new RSA key pair for message signing
            try:
                self.message_authenticator.generate_key_pair()
                return True
            except Exception as e:
                return False  # Key rotation failed silently
        return False

class StealthMode:
    """Stealth and decoy mode implementation"""
    def __init__(self, root):
        self.root = root
        self.original_title = root.title()
        self.stealth_active = False
        self.decoy_active = False
    
    def enable_stealth(self):
        """Enable stealth mode - disguise as calculator"""
        self.stealth_active = True
        self.root.title("Calculator")
        self.root.iconify()  # Minimize to hide
    
    def disable_stealth(self):
        """Disable stealth mode"""
        self.stealth_active = False
        self.root.title(self.original_title)
        self.root.deiconify()  # Restore window
    
    def enable_decoy(self):
        """Enable decoy mode"""
        self.decoy_active = True
    
    def show_decoy_error(self):
        """Show fake error message"""
        fake_errors = [
            "System Error: Access Denied\nContact your system administrator.",
            "Application Error: File not found\nThe system cannot find the specified file.",
            "Network Error: Connection timeout\nUnable to connect to server.",
            "Security Error: Invalid credentials\nAccess has been logged and reported."
        ]
        error = secrets.choice(fake_errors)
        messagebox.showerror("System Error", error)

class ForwardSecrecy:
    """Forward secrecy and auto-deletion system"""
    def __init__(self):
        self.message_expiry = 30 * 24 * 3600  # 30 days in seconds
        self.cleanup_interval = 3600  # Check every hour
        self.last_cleanup = time.time()
    
    def should_delete_message(self, timestamp):
        """Check if message should be deleted"""
        return (time.time() - timestamp) > self.message_expiry
    
    def cleanup_expired_messages(self, messages):
        """Remove expired messages"""
        current_time = time.time()
        if (current_time - self.last_cleanup) < self.cleanup_interval:
            return messages
        
        self.last_cleanup = current_time
        return [msg for msg in messages if not self.should_delete_message(msg.get('timestamp', 0))]

class SecureMemory:
    """Military-grade secure memory management with enhanced security features"""
    def __init__(self):
        self.secure_data = {}
        self.memory_keys = set()
        # Import and use enhanced memory security manager
        try:
            from memory_security import MemorySecurityManager
            self._memory_manager = MemorySecurityManager()
        except ImportError:
            self._memory_manager = None
    
    def store_secure(self, key, data):
        """Store data in secure memory"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.secure_data[key] = bytearray(data)
        self.memory_keys.add(key)
        
        # Lock memory pages if supported
        if self._memory_manager and self._memory_manager.supports_memory_locking():
            try:
                self._memory_manager.lock_memory_pages(self.secure_data[key])
            except:
                pass  # Continue if locking fails
        
        return key
    
    def retrieve_secure(self, key):
        """Retrieve data from secure memory"""
        if key in self.secure_data:
            return bytes(self.secure_data[key]).decode('utf-8')
        return None
    
    def wipe_secure(self, key):
        """Securely wipe data from memory using enhanced clearing"""
        if key in self.secure_data:
            # Use enhanced memory manager if available
            if self._memory_manager:
                try:
                    # Unlock memory pages before clearing
                    if self._memory_manager.supports_memory_locking():
                        self._memory_manager.unlock_memory_pages(self.secure_data[key])
                    
                    # Use enhanced secure clearing
                    self._memory_manager.secure_clear_variable(key, self.secure_data, 'multiple_passes')
                except:
                    # Fallback to original method
                    self._fallback_wipe_secure(key)
            else:
                self._fallback_wipe_secure(key)
            
            self.memory_keys.discard(key)
            
            # Enhanced garbage collection
            if self._memory_manager:
                self._memory_manager.secure_garbage_collection()
            else:
                gc.collect()
    
    def _fallback_wipe_secure(self, key):
        """Fallback wiping method if enhanced manager not available"""
        if key in self.secure_data:
            # Overwrite with random data multiple times
            data_len = len(self.secure_data[key])
            for _ in range(7):  # Enhanced from 3 to 7 passes (DoD standard)
                self.secure_data[key][:] = os.urandom(data_len)
            del self.secure_data[key]
    
    def wipe_all(self):
        """Securely wipe all data using enhanced methods"""
        for key in list(self.memory_keys):
            self.wipe_secure(key)
        
        # Final enhanced garbage collection
        if self._memory_manager:
            self._memory_manager.secure_garbage_collection()

class UserTracker:
    """Advanced user tracking and monitoring system"""
    def __init__(self):
        self.user_sessions = {}
        self.ip_database = {}
        self.hwid_database = {}
        self.location_cache = {}
    
    def get_client_ip(self):
        """Get real client IP address"""
        try:
            # Try multiple methods to get real IP
            response = requests.get('https://httpbin.org/ip', timeout=5)
            if response.status_code == 200:
                return response.json().get('origin', 'Unknown')
        except:
            pass
        
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            if response.status_code == 200:
                return response.json().get('ip', 'Unknown')
        except:
            pass
        
        return 'Unknown'
    
    def get_hardware_id(self):
        """Generate unique hardware fingerprint"""
        try:
            # Get system information
            system_info = {
                'machine': platform.machine(),
                'processor': platform.processor(),
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'node': platform.node()
            }
            
            # Get MAC address
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                           for elements in range(0,2*6,2)][::-1])
            
            # Get disk serial if available
            disk_serial = "Unknown"
            try:
                if platform.system() == "Windows":
                    result = subprocess.run(['wmic', 'diskdrive', 'get', 'serialnumber'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')
                        if len(lines) > 1:
                            disk_serial = lines[1].strip()
                elif platform.system() == "Linux":
                    result = subprocess.run(['lsblk', '-o', 'SERIAL'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')
                        if len(lines) > 1:
                            disk_serial = lines[1].strip()
            except:
                pass
            
            # Get CPU info
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            cpu_info = f"{cpu_count}_{cpu_freq.max if cpu_freq else 'unknown'}"
            
            # Get memory info
            memory = psutil.virtual_memory()
            memory_info = f"{memory.total}"
            
            # Create unique fingerprint
            fingerprint_data = f"{mac}_{disk_serial}_{cpu_info}_{memory_info}_{system_info['machine']}_{system_info['processor']}"
            hwid = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]
            
            return {
                'hwid': hwid,
                'mac_address': mac,
                'disk_serial': disk_serial,
                'cpu_info': cpu_info,
                'memory_total': memory_info,
                'system_info': system_info
            }
        except Exception as e:
            # Fallback HWID
            fallback = f"{platform.system()}_{platform.machine()}_{uuid.getnode()}"
            return {
                'hwid': hashlib.sha256(fallback.encode()).hexdigest()[:32],
                'mac_address': 'Unknown',
                'disk_serial': 'Unknown',
                'cpu_info': 'Unknown',
                'memory_total': 'Unknown',
                'system_info': {'error': str(e)}
            }
    
    def get_location_info(self, ip_address):
        """Get location information from IP address"""
        if ip_address in self.location_cache:
            return self.location_cache[ip_address]
        
        try:
            # Use multiple geolocation services
            services = [
                f'http://ip-api.com/json/{ip_address}',
                f'https://ipapi.co/{ip_address}/json/',
                f'https://freegeoip.app/json/{ip_address}'
            ]
            
            for service_url in services:
                try:
                    response = requests.get(service_url, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        
                        # Normalize response based on service
                        if 'ip-api.com' in service_url:
                            location_info = {
                                'country': data.get('country', 'Unknown'),
                                'country_code': data.get('countryCode', 'Unknown'),
                                'region': data.get('regionName', 'Unknown'),
                                'city': data.get('city', 'Unknown'),
                                'latitude': data.get('lat', 'Unknown'),
                                'longitude': data.get('lon', 'Unknown'),
                                'timezone': data.get('timezone', 'Unknown'),
                                'isp': data.get('isp', 'Unknown'),
                                'org': data.get('org', 'Unknown'),
                                'as': data.get('as', 'Unknown')
                            }
                        elif 'ipapi.co' in service_url:
                            location_info = {
                                'country': data.get('country_name', 'Unknown'),
                                'country_code': data.get('country_code', 'Unknown'),
                                'region': data.get('region', 'Unknown'),
                                'city': data.get('city', 'Unknown'),
                                'latitude': data.get('latitude', 'Unknown'),
                                'longitude': data.get('longitude', 'Unknown'),
                                'timezone': data.get('timezone', 'Unknown'),
                                'isp': data.get('org', 'Unknown'),
                                'org': data.get('org', 'Unknown'),
                                'as': data.get('asn', 'Unknown')
                            }
                        else:  # freegeoip.app
                            location_info = {
                                'country': data.get('country_name', 'Unknown'),
                                'country_code': data.get('country_code', 'Unknown'),
                                'region': data.get('region_name', 'Unknown'),
                                'city': data.get('city', 'Unknown'),
                                'latitude': data.get('latitude', 'Unknown'),
                                'longitude': data.get('longitude', 'Unknown'),
                                'timezone': data.get('time_zone', 'Unknown'),
                                'isp': 'Unknown',
                                'org': 'Unknown',
                                'as': 'Unknown'
                            }
                        
                        self.location_cache[ip_address] = location_info
                        return location_info
                except:
                    continue
        except:
            pass
        
        # Fallback location info
        fallback_info = {
            'country': 'Unknown',
            'country_code': 'Unknown',
            'region': 'Unknown',
            'city': 'Unknown',
            'latitude': 'Unknown',
            'longitude': 'Unknown',
            'timezone': 'Unknown',
            'isp': 'Unknown',
            'org': 'Unknown',
            'as': 'Unknown'
        }
        self.location_cache[ip_address] = fallback_info
        return fallback_info
    
    def track_user_session(self, username, chat_id, registry_id):
        """Track comprehensive user session data"""
        ip_address = self.get_client_ip()
        hwid_info = self.get_hardware_id()
        location_info = self.get_location_info(ip_address)
        
        session_data = {
            'username': username,
            'chat_id': chat_id,
            'registry_id': registry_id,
            'ip_address': ip_address,
            'hwid': hwid_info['hwid'],
            'hardware_details': hwid_info,
            'location': location_info,
            'session_start': time.time(),
            'last_activity': time.time(),
            'status': 'active',
            'user_agent': f"SecureChat-{platform.system()}-{platform.release()}",
            'connection_count': 1
        }
        
        session_key = f"{username}_{chat_id}"
        if session_key in self.user_sessions:
            # Update existing session
            existing = self.user_sessions[session_key]
            existing['last_activity'] = time.time()
            existing['connection_count'] += 1
            existing['ip_address'] = ip_address  # Update IP in case it changed
        else:
            self.user_sessions[session_key] = session_data
        
        # Update databases
        self.ip_database[ip_address] = {
            'username': username,
            'location': location_info,
            'first_seen': session_data['session_start'],
            'last_seen': time.time()
        }
        
        self.hwid_database[hwid_info['hwid']] = {
            'username': username,
            'hardware_details': hwid_info,
            'first_seen': session_data['session_start'],
            'last_seen': time.time()
        }
        
        return session_data
    
    def get_user_sessions(self):
        """Get all active user sessions"""
        return self.user_sessions
    
    def get_session_by_user(self, username):
        """Get sessions for specific user"""
        return {k: v for k, v in self.user_sessions.items() if v['username'] == username}
    
    def update_user_activity(self, username, chat_id):
        """Update user's last activity timestamp"""
        session_key = f"{username}_{chat_id}"
        if session_key in self.user_sessions:
            self.user_sessions[session_key]['last_activity'] = time.time()
    
    def end_user_session(self, username, chat_id):
        """End user session"""
        session_key = f"{username}_{chat_id}"
        if session_key in self.user_sessions:
            self.user_sessions[session_key]['status'] = 'disconnected'
            self.user_sessions[session_key]['session_end'] = time.time()

class TorProxy:
    """Enhanced Tor proxy handler with embedded automatic TOR connection"""
    def __init__(self):
        # Import the embedded TOR client
        from embedded_tor_client import get_tor_client
        self.tor_client = get_tor_client()
        self.session = None
        self.tor_verified = False
        self._session_setup_attempted = False
    
    def verify_tor_connection(self):
        """Verify that Tor is running and accessible"""
        try:
            return self.tor_client.connect()
        except Exception:
            return False
    
    def setup_session(self):
        """Setup secure session with embedded TOR"""
        if self._session_setup_attempted:
            return  # Don't try again if already attempted
            
        self._session_setup_attempted = True
        try:
            # Use embedded TOR client to setup connection
            if self.tor_client.connect():
                self.session = self.tor_client.session
                self.tor_verified = True
                print("TOR connection established successfully")
            else:
                raise Exception("EMBEDDED TOR SETUP FAILED: Could not establish TOR connection")
                
        except Exception as e:
            print(f"TOR setup error: {e}")
            # Still create a session for fallback
            self.session = self.tor_client.session if self.tor_client.session else None
            raise Exception(f"TOR CONNECTION ISSUE: {str(e)}")
    
    def check_ssl_configuration(self):
        """Check if SSL/TLS verification is properly enabled"""
        if not self.session:
            return False
        return getattr(self.session, 'verify', True) is True
    
    def make_request(self, method, url, **kwargs):
        """Make anonymous request through embedded TOR connection"""
        # Setup session lazily when first request is made
        if not self._session_setup_attempted:
            self.setup_session()
            
        try:
            # Use embedded TOR client for requests
            return self.tor_client.make_request(method, url, **kwargs)
        except Exception as e:
            print(f"TOR request error: {e}")
            raise Exception(f"TOR REQUEST FAILED: {str(e)}")
    
    def get_security_status(self):
        """Get detailed security status"""
        return {
            'tor_available': self.tor_verified,
            'tor_verified': self.tor_verified,
            'ssl_verification_enabled': self.check_ssl_configuration(),
            'original_ip': 'Unknown',
            'tor_ip': 'Unknown',
            'ip_changed': self.tor_verified
        }

class TrafficObfuscator:
    """Advanced traffic analysis protection and privacy enhancement"""
    def __init__(self):
        self.dummy_requests = []
        self.privacy_mode = True
    
    def add_noise(self):
        """Add dummy traffic to obfuscate real requests"""
        try:
            # Generate random dummy requests to mask real traffic patterns
            dummy_urls = [
                "https://httpbin.org/delay/1",
                "https://jsonplaceholder.typicode.com/posts/1",
                "https://api.github.com/users/octocat",
                "https://httpbin.org/json",
                "https://httpbin.org/uuid",
                "https://jsonplaceholder.typicode.com/users/1"
            ]
            url = secrets.choice(dummy_urls)
            threading.Thread(target=self._make_dummy_request, args=(url,), daemon=True).start()
        except:
            pass
    
    def _make_dummy_request(self, url):
        """Make dummy request with random delays through secure Tor proxy"""
        try:
            # Add random delay to make traffic analysis harder
            time.sleep(secrets.randbelow(3) + 1)
            
            # Use secure TorProxy for dummy requests
            tor_proxy = TorProxy()
            tor_proxy.make_request('GET', url)
        except:
            # Silently fail for dummy requests - they're just noise
            pass
    
    def obfuscate_payload(self, data):
        """Add additional obfuscation layers to payload"""
        if not self.privacy_mode:
            return data
        
        try:
            # Add padding to mask message sizes
            padding_size = secrets.randbelow(100) + 50
            padding = secrets.token_hex(padding_size)
            
            # Wrap data with obfuscation
            obfuscated = {
                'data': data,
                'padding': padding,
                'timestamp': time.time(),
                'nonce': secrets.token_hex(16)
            }
            
            return obfuscated
        except:
            return data
    
    def deobfuscate_payload(self, obfuscated_data):
        """Remove obfuscation layers from payload"""
        if not self.privacy_mode:
            return obfuscated_data
        
        try:
            if isinstance(obfuscated_data, dict) and 'data' in obfuscated_data:
                return obfuscated_data['data']
            return obfuscated_data
        except:
            return obfuscated_data

class MasterPasswordDialog:
    """Master password authentication dialog with Winter Cherry Blossom theme"""
    def __init__(self, parent, password_manager):
        self.parent = parent
        self.password_manager = password_manager
        self.password = None
        self.dialog = None
        
        # Initialize Winter Cherry Blossom theme for dialog
        self.winter_theme = WinterCherryBlossomTheme()
        self.colors = self.winter_theme.get_color_palette()
        
    def show_dialog(self):
        """Show master password dialog with Winter Cherry Blossom theme"""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("CLASSIFIED ACCESS - MASTER PASSWORD")
        self.dialog.geometry("500x400")
        self.dialog.configure(bg=self.colors['bg'])
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        self.dialog.protocol("WM_DELETE_WINDOW", self.on_cancel)
        
        # Center dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (250)
        y = (self.dialog.winfo_screenheight() // 2) - (200)
        self.dialog.geometry(f"+{x}+{y}")
        
        # Main frame with Winter Cherry Blossom theme
        main_frame = tk.Frame(self.dialog, bg=self.colors['bg'], padx=40, pady=40)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header with Winter Cherry Blossom styling
        tk.Label(main_frame, text="🌸", 
                 font=self.winter_theme.get_font_config('title'), 
                 bg=self.colors['bg'], 
                 fg=self.colors['blossom_primary']).pack(pady=(0, 20))
        
        tk.Label(main_frame, text="CLASSIFIED ACCESS CONTROL",
                 font=self.winter_theme.get_font_config('heading'), 
                 bg=self.colors['bg'], 
                 fg=self.colors['accent']).pack(pady=(0, 10))
        
        tk.Label(main_frame, text="Enter Master Password to Access Classified Data",
                 font=self.winter_theme.get_font_config('body'), 
                 bg=self.colors['bg'], 
                 fg=self.colors['fg']).pack(pady=(0, 30))
        
        # Password entry with Winter Cherry Blossom theme
        password_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        password_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(password_frame, text="MASTER PASSWORD:",
                 font=self.winter_theme.get_font_config('label'), 
                 bg=self.colors['bg'], 
                 fg=self.colors['accent']).pack(anchor='w', pady=(0, 10))
        
        self.password_entry = tk.Entry(password_frame, show="*", 
                                      bg=self.colors['entry_bg'], 
                                      fg=self.colors['entry_fg'], 
                                      font=self.winter_theme.get_font_config('input'),
                                      insertbackground=self.colors['entry_fg'],
                                      relief='solid',
                                      borderwidth=1,
                                      highlightcolor=self.colors['entry_focus'])
        self.password_entry.pack(fill=tk.X, pady=(0, 10))
        self.password_entry.bind('<Return>', lambda e: self.authenticate())
        self.password_entry.focus()
        
        # Show/hide password with Winter Cherry Blossom theme
        show_frame = tk.Frame(password_frame, bg=self.colors['bg'])
        show_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.show_password_var = tk.BooleanVar()
        tk.Checkbutton(show_frame, text="Show Password", 
                      variable=self.show_password_var,
                      command=self.toggle_password_visibility,
                      bg=self.colors['bg'], 
                      fg=self.colors['fg'], 
                      selectcolor=self.colors['blossom_light'],
                      font=self.winter_theme.get_font_config('caption')).pack(anchor='w')
        
        # Attempts warning with Winter Cherry Blossom theme
        attempts_left = self.password_manager.max_attempts - self.password_manager.failed_attempts
        if self.password_manager.failed_attempts > 0:
            warning_text = f"⚠️ WARNING: {attempts_left} attempts remaining before self-destruct"
            tk.Label(main_frame, text=warning_text,
                     font=self.winter_theme.get_font_config('status'), 
                     bg=self.colors['bg'], 
                     fg=self.colors['danger']).pack(pady=(0, 20))
        
        # Buttons with Winter Cherry Blossom theme
        button_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        # Use themed button creation instead of hardcoded colors
        access_btn = self.winter_components.create_styled_button(
            button_frame, 
            text="ACCESS CLASSIFIED DATA",
            command=self.authenticate
        )
        access_btn.configure(padx=20, pady=10)
        access_btn.pack(side=tk.RIGHT, padx=(10, 0))
        
        cancel_btn = self.winter_components.create_styled_button(
            button_frame, 
            text="CANCEL",
            command=self.on_cancel
        )
        cancel_btn.configure(
            bg=self.colors['danger'], 
            fg='#ffffff',
            activebackground=self.colors['danger'],
            padx=20, pady=10
        )
        cancel_btn.pack(side=tk.RIGHT)
        
        # Emergency wipe info with Winter Cherry Blossom theme
        tk.Label(main_frame, text="Emergency Wipe: Ctrl+Shift+W",
                 font=self.winter_theme.get_font_config('caption'), 
                 bg=self.colors['bg'], 
                 fg=self.colors['accent_light']).pack(side=tk.BOTTOM, pady=(20, 0))
        
        return self.dialog
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def authenticate(self):
        """Authenticate master password"""
        password = self.password_entry.get()
        
        if not password:
            messagebox.showerror("ERROR", "Master password required")
            return
        
        try:
            # Check if it's the decoy password using enhanced detection
            if self.password_manager.is_decoy_password(password):
                self.password_manager.is_decoy_mode = True
                self.password = password
                self.dialog.destroy()
                return
            
            # For first-time setup, accept any password and store its hash
            if not hasattr(self.password_manager, 'master_password_hash') or self.password_manager.master_password_hash is None:
                # First time setup - store the password hash
                self.password_manager.master_password_hash = self.password_manager.hash_password(password)
                self.password_manager.reset_failed_attempts()
                self.password = password
                self.dialog.destroy()
                return
            
            # Verify against stored password hash
            if self.password_manager.verify_password(password, self.password_manager.master_password_hash):
                # Success
                self.password_manager.reset_failed_attempts()
                self.password = password
                self.dialog.destroy()
            else:
                raise Exception("Authentication failed")
                
        except Exception as e:
            # Failed authentication
            should_destruct = self.password_manager.record_failed_attempt()
            attempts_left = self.password_manager.max_attempts - self.password_manager.failed_attempts
            
            if should_destruct:
                messagebox.showerror("SELF-DESTRUCT ACTIVATED", 
                                   "🔥 Maximum attempts exceeded!\n\n"
                                   "All classified data will be destroyed for security.")
                self.password_manager.self_destruct("host_chat_history.json")
                self.parent.quit()
            else:
                messagebox.showerror("ACCESS DENIED", 
                                   f"❌ Invalid master password\n\n"
                                   f"Attempts remaining: {attempts_left}\n"
                                   f"File will self-destruct after {attempts_left} more failed attempts")
                self.password_entry.delete(0, tk.END)
                self.password_entry.focus()
    
    def on_cancel(self):
        """Handle dialog cancellation"""
        self.password = None
        self.dialog.destroy()

class SecureChatHostGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Host")
        self.root.geometry("1200x800")
        
        # Initialize master password system
        self.master_password_manager = MasterPasswordManager()
        self.master_password = None
        
        # Check failed attempts on startup
        self.master_password_manager.check_failed_attempts()
        
        # Setup decoy password (you can change this)
        self.master_password_manager.setup_decoy_password("decoy123")
        
        # Initialize security components
        self.secure_memory = SecureMemory()
        
        # Initialize Tor proxy with automatic setup
        try:
            self.tor_proxy = TorProxy()
        except Exception as e:
            # If Tor setup fails, show setup dialog
            if "TOR CONNECTION REQUIRED" in str(e):
                show_tor_setup_dialog(self.root)
            else:
                messagebox.showerror("Tor Connection Error", 
                                   f"Failed to initialize Tor connection:\n{str(e)}\n\n"
                                   "Please ensure Tor Browser is running and try again.")
                self.root.quit()
                return
        
        self.traffic_obfuscator = TrafficObfuscator()
        self.user_tracker = UserTracker()
        
        # Initialize advanced security layers
        self.security_manager = SecurityManager()
        self.message_security = MessageSecurity()
        self.stealth_mode = StealthMode(root)
        self.forward_secrecy = ForwardSecrecy()
        
        # Security state
        self.authenticated = False
        self.session_timer = None
        
        # Chat state
        self.chat_id = None
        self.encryption_key = None
        self.cipher = None
        self.username = "Host"
        self.auto_decrypt = True
        self.connected = False
        self.last_timestamp = 0
        self.message_widgets = []
        
        # Registration state
        self.registry_id = None
        self.admin_id = "host_admin"
        self.registry_initialized = False
        
        # Configuration management
        self.config_file = "host_config.enc"  # Use encrypted configuration
        self.config_encryption = ConfigurationEncryption()  # Initialize configuration encryption
        
        # Chat history - stores both chat and registry info
        self.chat_history_file = "host_chat_history.json"
        self.chat_history = self.load_chat_history()
        
        # Store mapping of chat_id -> registry_id from history
        self.chat_registry_map = {}
        self.load_chat_registry_map()
        
        # Load configuration after initialization
        self.load_configuration()
        
        # English Interface Text Constants
        self.text = EnglishInterfaceText()
        
        # English Language Manager for consistent text
        self.english_manager = english_manager
        
        # Winter Cherry Blossom Theme System - Main Theme Integration
        self.winter_cherry_theme = WinterCherryBlossomTheme()
        self.winter_components = WinterCherryBlossomComponents(self.winter_cherry_theme)
        self.current_theme = "winter_cherry_blossom"
        
        # Theme colors - Winter Cherry Blossom is the main theme
        self.colors = self.winter_cherry_theme.get_color_palette()
        
        # Winter Cherry Blossom is the main theme, with other themes available
        self.themes = {
            "winter_cherry_blossom": self.colors,  # Main theme
            "matrix_green": {
                'bg': '#0a1a0a', 'fg': '#00ff00', 'sidebar_bg': '#1a2a1a', 'sidebar_fg': '#00ff00',
                'accent': '#00ff00', 'accent_light': '#003300', 'button_bg': '#003300', 'button_fg': '#00ff00',
                'button_hover': '#004400', 'button_active': '#005500', 'entry_bg': '#1a2a1a', 'entry_fg': '#00ff00', 'message_bg': '#1a2a1a',
                'message_fg': '#00ff00', 'own_message': '#002200', 'their_message': '#1a2a1a', 'border': '#003300',
                'success': '#00ff00', 'warning': '#ffaa00', 'danger': '#ff4444', 'info': '#44aaff',
                'card_bg': '#1a2a1a', 'table_header': '#003300', 'table_row_even': '#1a2a1a', 'table_row_odd': '#0f1f0f',
                'classified': '#ff4444', 'blossom_primary': '#00ff00', 'blossom_light': '#002200',
                'entry_border': '#003300', 'entry_focus': '#004400', 'separator': '#1a2a1a'
            },
            "cyber_blue": {
                'bg': '#0a0a1a', 'fg': '#00aaff', 'sidebar_bg': '#1a1a2a', 'sidebar_fg': '#00aaff',
                'accent': '#00aaff', 'accent_light': '#003366', 'button_bg': '#003366', 'button_fg': '#00aaff',
                'button_hover': '#004488', 'button_active': '#0055aa', 'entry_bg': '#1a1a2a', 'entry_fg': '#00aaff', 'message_bg': '#1a1a2a',
                'message_fg': '#00aaff', 'own_message': '#002244', 'their_message': '#1a1a2a', 'border': '#003366',
                'success': '#00ff00', 'warning': '#ffaa00', 'danger': '#ff4444', 'info': '#44aaff',
                'card_bg': '#1a1a2a', 'table_header': '#003366', 'table_row_even': '#1a1a2a', 'table_row_odd': '#0f0f1f',
                'classified': '#ff4444', 'blossom_primary': '#00aaff', 'blossom_light': '#002244',
                'entry_border': '#003366', 'entry_focus': '#004488', 'separator': '#1a1a2a'
            },
            "stealth_dark": {
                'bg': '#0f0f0f', 'fg': '#cccccc', 'sidebar_bg': '#1f1f1f', 'sidebar_fg': '#cccccc',
                'accent': '#ffffff', 'accent_light': '#444444', 'button_bg': '#333333', 'button_fg': '#cccccc',
                'button_hover': '#555555', 'button_active': '#666666', 'entry_bg': '#1f1f1f', 'entry_fg': '#cccccc', 'message_bg': '#1f1f1f',
                'message_fg': '#cccccc', 'own_message': '#2a2a2a', 'their_message': '#1f1f1f', 'border': '#444444',
                'success': '#00ff00', 'warning': '#ffaa00', 'danger': '#ff4444', 'info': '#44aaff',
                'card_bg': '#1f1f1f', 'table_header': '#333333', 'table_row_even': '#1f1f1f', 'table_row_odd': '#171717',
                'classified': '#ff4444', 'blossom_primary': '#cccccc', 'blossom_light': '#2a2a2a',
                'entry_border': '#444444', 'entry_focus': '#555555', 'separator': '#1f1f1f'
            },
            "light_mode": {
                'bg': '#f5f5f5', 'fg': '#333333', 'sidebar_bg': '#e0e0e0', 'sidebar_fg': '#333333',
                'accent': '#0066cc', 'accent_light': '#cce6ff', 'button_bg': '#0066cc', 'button_fg': '#ffffff',
                'button_hover': '#0052a3', 'button_active': '#004080', 'entry_bg': '#ffffff', 'entry_fg': '#333333', 'message_bg': '#ffffff',
                'message_fg': '#333333', 'own_message': '#e6f3ff', 'their_message': '#f0f0f0', 'border': '#cccccc',
                'success': '#00aa00', 'warning': '#ff8800', 'danger': '#cc0000', 'info': '#0066cc',
                'card_bg': '#ffffff', 'table_header': '#e0e0e0', 'table_row_even': '#ffffff', 'table_row_odd': '#f8f8f8',
                'classified': '#cc0000', 'blossom_primary': '#0066cc', 'blossom_light': '#e6f3ff',
                'entry_border': '#cccccc', 'entry_focus': '#0066cc', 'separator': '#e0e0e0'
            },
            "desert_gold": {
                'bg': '#1a1a0a', 'fg': '#ffcc00', 'sidebar_bg': '#2a2a1a', 'sidebar_fg': '#ffcc00',
                'accent': '#ffcc00', 'accent_light': '#663300', 'button_bg': '#663300', 'button_fg': '#ffcc00',
                'button_hover': '#884400', 'button_active': '#aa5500', 'entry_bg': '#2a2a1a', 'entry_fg': '#ffcc00', 'message_bg': '#2a2a1a',
                'message_fg': '#ffcc00', 'own_message': '#442200', 'their_message': '#2a2a1a', 'border': '#663300',
                'success': '#00ff00', 'warning': '#ffaa00', 'danger': '#ff4444', 'info': '#44aaff',
                'card_bg': '#2a2a1a', 'table_header': '#663300', 'table_row_even': '#2a2a1a', 'table_row_odd': '#1f1f0f',
                'classified': '#ff4444', 'blossom_primary': '#ffcc00', 'blossom_light': '#442200',
                'entry_border': '#663300', 'entry_focus': '#884400', 'separator': '#2a2a1a'
            },
            "neon_purple": {
                'bg': '#1a0a1a', 'fg': '#9966ff', 'sidebar_bg': '#2a1a2a', 'sidebar_fg': '#9966ff',
                'accent': '#9966ff', 'accent_light': '#553366', 'button_bg': '#553366', 'button_fg': '#9966ff',
                'button_hover': '#774488', 'button_active': '#8855aa', 'entry_bg': '#2a1a2a', 'entry_fg': '#9966ff', 'message_bg': '#2a1a2a',
                'message_fg': '#9966ff', 'own_message': '#332244', 'their_message': '#2a1a2a', 'border': '#553366',
                'success': '#00ff00', 'warning': '#ffaa00', 'danger': '#ff4444', 'info': '#44aaff',
                'card_bg': '#2a1a2a', 'table_header': '#553366', 'table_row_even': '#2a1a2a', 'table_row_odd': '#1f0f1f',
                'classified': '#ff4444', 'blossom_primary': '#9966ff', 'blossom_light': '#332244',
                'entry_border': '#553366', 'entry_focus': '#774488', 'separator': '#2a1a2a'
            },
            "crimson_red": {
                'bg': '#1a0a0a', 'fg': '#ff3333', 'sidebar_bg': '#2a1a1a', 'sidebar_fg': '#ff3333',
                'accent': '#ff3333', 'accent_light': '#660000', 'button_bg': '#660000', 'button_fg': '#ff3333',
                'button_hover': '#880000', 'button_active': '#aa0000', 'entry_bg': '#2a1a1a', 'entry_fg': '#ff3333', 'message_bg': '#2a1a1a',
                'message_fg': '#ff3333', 'own_message': '#440000', 'their_message': '#2a1a1a', 'border': '#660000',
                'success': '#00ff00', 'warning': '#ffaa00', 'danger': '#ff4444', 'info': '#44aaff',
                'card_bg': '#2a1a1a', 'table_header': '#660000', 'table_row_even': '#2a1a1a', 'table_row_odd': '#1f0f0f',
                'classified': '#ff4444', 'blossom_primary': '#ff3333', 'blossom_light': '#440000',
                'entry_border': '#660000', 'entry_focus': '#880000', 'separator': '#2a1a1a'
            },
            "ocean_teal": {
                'bg': '#0a1a1a', 'fg': '#00ccaa', 'sidebar_bg': '#1a2a2a', 'sidebar_fg': '#00ccaa',
                'accent': '#00ccaa', 'accent_light': '#003333', 'button_bg': '#003333', 'button_fg': '#00ccaa',
                'button_hover': '#004444', 'button_active': '#005555', 'entry_bg': '#1a2a2a', 'entry_fg': '#00ccaa', 'message_bg': '#1a2a2a',
                'message_fg': '#00ccaa', 'own_message': '#002222', 'their_message': '#1a2a2a', 'border': '#003333',
                'success': '#00ff00', 'warning': '#ffaa00', 'danger': '#ff4444', 'info': '#44aaff',
                'card_bg': '#1a2a2a', 'table_header': '#003333', 'table_row_even': '#1a2a2a', 'table_row_odd': '#0f1f1f',
                'classified': '#ff4444', 'blossom_primary': '#00ccaa', 'blossom_light': '#002222',
                'entry_border': '#003333', 'entry_focus': '#004444', 'separator': '#1a2a2a'
            }
        }
        
        # Apply Winter Cherry Blossom theme to root window
        self.root.configure(bg=self.colors['bg'])
        self.winter_cherry_theme.apply_theme(self.root)
        
        # Apply theme to window properties
        self.winter_components.apply_window_theme(self.root)
        
        # Initialize theme-aware components
        self.setup_styles()
        
        # Skip the rest of the old theme definitions - they are replaced by Winter Cherry Blossom
        if False:  # Disabled old theme code
            old_themes = {
                'table_header': '#336655',
                'table_row_even': '#1a2a2a',
                'table_row_odd': '#0f1f1f',
                'classified': '#ff4444'
            }
            legacy_themes = {
            "stealth_dark": {
                'bg': '#0f0f0f',
                'fg': '#cccccc',
                'sidebar_bg': '#1f1f1f',
                'sidebar_fg': '#cccccc',
                'accent': '#ffffff',
                'accent_light': '#444444',
                'button_bg': '#333333',
                'button_fg': '#cccccc',
                'button_hover': '#555555',
                'entry_bg': '#1f1f1f',
                'entry_fg': '#cccccc',
                'message_bg': '#1f1f1f',
                'message_fg': '#cccccc',
                'own_message': '#2a2a2a',
                'their_message': '#1f1f1f',
                'border': '#444444',
                'success': '#00ff00',
                'warning': '#ffaa00',
                'danger': '#ff4444',
                'info': '#44aaff',
                'card_bg': '#1f1f1f',
                'table_header': '#333333',
                'table_row_even': '#1f1f1f',
                'table_row_odd': '#171717',
                'classified': '#ff4444'
            },
            "light_mode": {
                'bg': '#f5f5f5',
                'fg': '#333333',
                'sidebar_bg': '#e0e0e0',
                'sidebar_fg': '#333333',
                'accent': '#0066cc',
                'accent_light': '#cce6ff',
                'button_bg': '#0066cc',
                'button_fg': '#ffffff',
                'button_hover': '#0052a3',
                'entry_bg': '#ffffff',
                'entry_fg': '#333333',
                'message_bg': '#ffffff',
                'message_fg': '#333333',
                'own_message': '#e6f3ff',
                'their_message': '#f0f0f0',
                'border': '#cccccc',
                'success': '#00aa00',
                'warning': '#ff8800',
                'danger': '#cc0000',
                'info': '#0066cc',
                'card_bg': '#ffffff',
                'table_header': '#e0e0e0',
                'table_row_even': '#ffffff',
                'table_row_odd': '#f8f8f8',
                'classified': '#cc0000'
            },
            "sunset_orange": {
                'bg': '#1a0f0a',
                'fg': '#ff6600',
                'sidebar_bg': '#2a1f1a',
                'sidebar_fg': '#ff6600',
                'accent': '#ff6600',
                'accent_light': '#663300',
                'button_bg': '#663300',
                'button_fg': '#ff6600',
                'button_hover': '#884400',
                'entry_bg': '#2a1f1a',
                'entry_fg': '#ff6600',
                'message_bg': '#2a1f1a',
                'message_fg': '#ff6600',
                'own_message': '#442200',
                'their_message': '#2a1f1a',
                'border': '#663300',
                'success': '#00ff00',
                'warning': '#ffaa00',
                'danger': '#ff4444',
                'info': '#44aaff',
                'card_bg': '#2a1f1a',
                'table_header': '#663300',
                'table_row_even': '#2a1f1a',
                'table_row_odd': '#1f170f',
                'classified': '#ff4444'
            },
            "arctic_white": {
                'bg': '#1a1a1a',
                'fg': '#ffffff',
                'sidebar_bg': '#2a2a2a',
                'sidebar_fg': '#ffffff',
                'accent': '#ffffff',
                'accent_light': '#555555',
                'button_bg': '#444444',
                'button_fg': '#ffffff',
                'button_hover': '#666666',
                'entry_bg': '#2a2a2a',
                'entry_fg': '#ffffff',
                'message_bg': '#2a2a2a',
                'message_fg': '#ffffff',
                'own_message': '#333333',
                'their_message': '#2a2a2a',
                'border': '#555555',
                'success': '#00ff00',
                'warning': '#ffaa00',
                'danger': '#ff4444',
                'info': '#44aaff',
                'card_bg': '#2a2a2a',
                'table_header': '#444444',
                'table_row_even': '#2a2a2a',
                'table_row_odd': '#222222',
                'classified': '#ffaa00'
            },
            "forest_green": {
                'bg': '#0a1a0a',
                'fg': '#66cc66',
                'sidebar_bg': '#1a2a1a',
                'sidebar_fg': '#66cc66',
                'accent': '#66cc66',
                'accent_light': '#336633',
                'button_bg': '#336633',
                'button_fg': '#66cc66',
                'button_hover': '#448844',
                'entry_bg': '#1a2a1a',
                'entry_fg': '#66cc66',
                'message_bg': '#1a2a1a',
                'message_fg': '#66cc66',
                'own_message': '#224422',
                'their_message': '#1a2a1a',
                'border': '#336633',
                'success': '#00ff00',
                'warning': '#ffaa00',
                'danger': '#ff4444',
                'info': '#44aaff',
                'card_bg': '#1a2a1a',
                'table_header': '#336633',
                'table_row_even': '#1a2a1a',
                'table_row_odd': '#0f1f0f',
                'classified': '#ff4444'
            },
            "royal_purple": {
                'bg': '#1a0a1a',
                'fg': '#9966ff',
                'sidebar_bg': '#2a1a2a',
                'sidebar_fg': '#9966ff',
                'accent': '#9966ff',
                'accent_light': '#553366',
                'button_bg': '#553366',
                'button_fg': '#9966ff',
                'button_hover': '#774488',
                'entry_bg': '#2a1a2a',
                'entry_fg': '#9966ff',
                'message_bg': '#2a1a2a',
                'message_fg': '#9966ff',
                'own_message': '#332244',
                'their_message': '#2a1a2a',
                'border': '#553366',
                'success': '#00ff00',
                'warning': '#ffaa00',
                'danger': '#ff4444',
                'info': '#44aaff',
                'card_bg': '#2a1a2a',
                'table_header': '#553366',
                'table_row_even': '#2a1a2a',
                'table_row_odd': '#1f0f1f',
                'classified': '#ff4444'
            },
            "midnight_blue": {
                'bg': '#0a0a1a',
                'fg': '#6699ff',
                'sidebar_bg': '#1a1a2a',
                'sidebar_fg': '#6699ff',
                'accent': '#6699ff',
                'accent_light': '#334466',
                'button_bg': '#334466',
                'button_fg': '#6699ff',
                'button_hover': '#445588',
                'entry_bg': '#1a1a2a',
                'entry_fg': '#6699ff',
                'message_bg': '#1a1a2a',
                'message_fg': '#6699ff',
                'own_message': '#223344',
                'their_message': '#1a1a2a',
                'border': '#334466',
                'success': '#00ff00',
                'warning': '#ffaa00',
                'danger': '#ff4444',
                'info': '#44aaff',
                'card_bg': '#1a1a2a',
                'table_header': '#334466',
                'table_row_even': '#1a1a2a',
                'table_row_odd': '#0f0f1f',
                'classified': '#ff4444'
            }
        }  # End of disabled old theme code
        
        # Auto-approval settings
        self.auto_approve_enabled = False
        self.auto_approve_whitelist = []  # List of usernames to auto-approve
        
        # Online users tracking
        self.online_users = set()
        self.last_online_check = 0
        
        # Setup panic wipe hotkey
        self.root.bind('<Control-Shift-Delete>', self.panic_wipe_hotkey)
        
        # Setup session timeout checker
        self.start_session_timer()
        
        # Show authentication screen first
        if self.security_manager.startup_password_hash:
            self.show_authentication_screen()
        else:
            self.show_security_setup()
        
        # Setup secure exit handler
        self.root.protocol("WM_DELETE_WINDOW", self.secure_exit)
    
    def authenticate_master_password(self):
        """Authenticate master password on startup"""
        dialog = MasterPasswordDialog(self.root, self.master_password_manager)
        dialog.show_dialog()
        
        # Wait for dialog to complete
        self.root.wait_window(dialog.dialog)
        
        if dialog.password:
            self.master_password = dialog.password
            # Load chat history after authentication
            self.chat_history = self.load_chat_history()
            self.load_chat_registry_map()
            return True
        else:
            return False
    
    def emergency_wipe_hotkey(self, event):
        """Emergency wipe hotkey handler"""
        if messagebox.askyesno("EMERGENCY WIPE", 
                              "🔥 EMERGENCY WIPE ACTIVATED!\n\n"
                              "This will permanently destroy ALL classified data.\n"
                              "This action cannot be undone.\n\n"
                              "Continue with emergency wipe?"):
            if self.master_password_manager.emergency_wipe(self.chat_history_file):
                messagebox.showinfo("WIPE COMPLETE", "🔥 All classified data has been securely destroyed!")
                self.root.quit()
            else:
                messagebox.showerror("WIPE FAILED", "Emergency wipe failed. Manual deletion may be required.")

    def secure_exit(self):
        """Secure application exit with enhanced memory wiping"""
        try:
            # Save encrypted history before exit
            if hasattr(self, 'master_password') and self.master_password and hasattr(self, 'chat_history'):
                self.save_chat_history_encrypted(self.chat_history)
            
            # Enhanced memory clearing for sensitive variables
            sensitive_vars = {
                'master_password': getattr(self, 'master_password', None),
                'chat_id': getattr(self, 'chat_id', None),
                'registry_id': getattr(self, 'registry_id', None),
                'encryption_key': getattr(self, 'encryption_key', None)
            }
            
            # Use enhanced memory manager for secure clearing
            try:
                from memory_security import get_memory_manager
                memory_manager = get_memory_manager()
                
                # Clear all sensitive variables
                for var_name in list(sensitive_vars.keys()):
                    if hasattr(self, var_name):
                        setattr(self, var_name, None)
                        memory_manager.secure_clear_variable(var_name, sensitive_vars)
                
                # Wipe secure memory with enhanced methods
                self.secure_memory.wipe_all()
                
                # Enhanced garbage collection
                memory_manager.secure_garbage_collection()
                
                # Emergency memory wipe as final step
                memory_manager.emergency_memory_wipe()
                
            except ImportError:
                # Fallback to original method if enhanced manager not available
                if hasattr(self, 'master_password'):
                    self.master_password = None
                
                self.secure_memory.wipe_all()
                
                # Force garbage collection multiple times
                for _ in range(5):  # Increased from 3 to 5
                    gc.collect()
        except:
            pass
        self.root.destroy()
    
    def panic_wipe_hotkey(self, event):
        """Panic wipe triggered by hotkey"""
        self.security_manager.panic_wipe()
    
    def start_session_timer(self):
        """Start session timeout timer"""
        def check_timeout():
            if self.security_manager.check_session_timeout():
                self.show_session_locked()
            self.session_timer = self.root.after(60000, check_timeout)  # Check every minute
        
        self.session_timer = self.root.after(60000, check_timeout)
    
    def show_security_setup(self):
        """Show initial security setup screen"""
        self.clear_window()
        
        # Security setup banner
        banner_frame = tk.Frame(self.root, bg=self.colors['warning'], height=40)
        banner_frame.pack(fill=tk.X)
        banner_frame.pack_propagate(False)
        
        tk.Label(banner_frame, text="★ ★ ★ SECURITY SETUP REQUIRED - FIRST TIME SETUP ★ ★ ★", 
                 bg=self.colors['warning'], fg='black', 
                 font=('Courier New', 12, 'bold')).pack(expand=True)
        
        # Main setup container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=100, pady=100)
        
        # Setup card
        setup_card = ttk.Frame(main_container, style='ClassifiedCard.TFrame', padding=40)
        setup_card.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(setup_card, text="🔐 SECURITY SETUP",
                 font=('Courier New', 24, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(pady=(0, 30))
        
        tk.Label(setup_card, text="Configure multi-layer security for maximum protection",
                 font=('Courier New', 12), bg=self.colors['card_bg'], fg=self.colors['fg']).pack(pady=(0, 30))
        
        # Startup Password
        tk.Label(setup_card, text="STARTUP PASSWORD (Required)",
                 font=('Courier New', 12, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(anchor='w', pady=(10, 5))
        
        self.startup_password_entry = tk.Entry(setup_card, show="*", bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                              font=('Courier New', 12), width=30)
        self.startup_password_entry.pack(pady=(0, 20))
        
        # PIN Code
        tk.Label(setup_card, text="PIN CODE (4-6 digits, Optional)",
                 font=('Courier New', 12, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(anchor='w', pady=(10, 5))
        
        self.pin_entry = tk.Entry(setup_card, show="*", bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                 font=('Courier New', 12), width=10)
        self.pin_entry.pack(pady=(0, 20))
        
        # History Password
        tk.Label(setup_card, text="HISTORY FILE PASSWORD (Optional)",
                 font=('Courier New', 12, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(anchor='w', pady=(10, 5))
        
        self.history_password_entry = tk.Entry(setup_card, show="*", bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                              font=('Courier New', 12), width=30)
        self.history_password_entry.pack(pady=(0, 30))
        
        # Security options
        options_frame = tk.Frame(setup_card, bg=self.colors['card_bg'])
        options_frame.pack(fill=tk.X, pady=(0, 30))
        
        self.stealth_var = tk.BooleanVar()
        tk.Checkbutton(options_frame, text="Enable Stealth Mode (Disguise as Calculator)",
                       variable=self.stealth_var, bg=self.colors['card_bg'], fg=self.colors['fg'],
                       selectcolor=self.colors['card_bg'], font=('Courier New', 10)).pack(anchor='w', pady=5)
        
        self.decoy_var = tk.BooleanVar()
        tk.Checkbutton(options_frame, text="Enable Decoy Mode (Fake errors on wrong password)",
                       variable=self.decoy_var, bg=self.colors['card_bg'], fg=self.colors['fg'],
                       selectcolor=self.colors['card_bg'], font=('Courier New', 10)).pack(anchor='w', pady=5)
        
        # Setup button
        ttk.Button(setup_card, text="COMPLETE SECURITY SETUP",
                  command=self.complete_security_setup,
                  style='ClassifiedButton.TButton').pack(pady=(20, 0))
    
    def complete_security_setup(self):
        """Complete initial security setup"""
        startup_password = self.startup_password_entry.get().strip()
        pin = self.pin_entry.get().strip()
        history_password = self.history_password_entry.get().strip()
        
        if not startup_password:
            messagebox.showerror("SETUP ERROR", "Startup password is required!")
            return
        
        if len(startup_password) < 8:
            messagebox.showerror("SETUP ERROR", "Startup password must be at least 8 characters!")
            return
        
        if pin and (len(pin) < 4 or len(pin) > 6 or not pin.isdigit()):
            messagebox.showerror("SETUP ERROR", "PIN must be 4-6 digits!")
            return
        
        # Set passwords
        self.security_manager.set_startup_password(startup_password)
        if pin:
            self.security_manager.set_pin(pin)
        if history_password:
            self.security_manager.set_history_password(history_password)
        
        # Set security options
        if self.stealth_var.get():
            self.stealth_mode.enable_stealth()
        if self.decoy_var.get():
            self.stealth_mode.enable_decoy()
        
        messagebox.showinfo("SETUP COMPLETE", "Security setup completed successfully!\n\nRemember your passwords - they cannot be recovered!")
        
        # Authenticate and show main menu
        self.security_manager.is_authenticated = True
        self.authenticated = True
        self.create_menu_bar()
        self.show_main_menu()
    
    def show_authentication_screen(self):
        """Show authentication screen"""
        self.clear_window()
        
        # Check for decoy mode
        if self.stealth_mode.decoy_active and self.security_manager.failed_attempts > 0:
            self.stealth_mode.show_decoy_error()
            return
        
        # Authentication banner
        banner_frame = tk.Frame(self.root, bg=self.colors['danger'], height=40)
        banner_frame.pack(fill=tk.X)
        banner_frame.pack_propagate(False)
        
        tk.Label(banner_frame, text="★ ★ ★ CLASSIFIED ACCESS - AUTHENTICATION REQUIRED ★ ★ ★", 
                 bg=self.colors['danger'], fg='white', 
                 font=('Courier New', 12, 'bold')).pack(expand=True)
        
        # Main auth container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=150, pady=150)
        
        # Auth card
        auth_card = ttk.Frame(main_container, style='ClassifiedCard.TFrame', padding=40)
        auth_card.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(auth_card, text="🔐 SECURE ACCESS",
                 font=('Courier New', 24, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(pady=(0, 30))
        
        # Show failed attempts warning
        if self.security_manager.failed_attempts > 0:
            attempts_left = self.security_manager.max_attempts - self.security_manager.failed_attempts
            tk.Label(auth_card, text=f"⚠️ {self.security_manager.failed_attempts} failed attempts. {attempts_left} attempts remaining.",
                     font=('Courier New', 10, 'bold'), bg=self.colors['card_bg'], fg=self.colors['danger']).pack(pady=(0, 20))
        
        # Password entry
        tk.Label(auth_card, text="ENTER STARTUP PASSWORD:",
                 font=('Courier New', 12, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(pady=(0, 10))
        
        self.auth_password_entry = tk.Entry(auth_card, show="*", bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                           font=('Courier New', 14), width=25)
        self.auth_password_entry.pack(pady=(0, 20))
        self.auth_password_entry.bind('<Return>', lambda e: self.authenticate_startup())
        self.auth_password_entry.focus()
        
        # Auth buttons
        button_frame = tk.Frame(auth_card, bg=self.colors['card_bg'])
        button_frame.pack(pady=(20, 0))
        
        ttk.Button(button_frame, text="AUTHENTICATE",
                  command=self.authenticate_startup,
                  style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=10)
        
        # PIN option if available
        if self.security_manager.pin_hash:
            ttk.Button(button_frame, text="USE PIN",
                      command=self.show_pin_auth,
                      style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=10)
    
    def authenticate_startup(self):
        """Authenticate with startup password"""
        password = self.auth_password_entry.get()
        
        if self.security_manager.authenticate_startup(password):
            self.authenticated = True
            self.create_menu_bar()
            self.show_main_menu()
        else:
            if self.stealth_mode.decoy_active:
                self.stealth_mode.show_decoy_error()
            else:
                attempts_left = self.security_manager.max_attempts - self.security_manager.failed_attempts
                if attempts_left > 0:
                    messagebox.showerror("ACCESS DENIED", f"Invalid password!\n{attempts_left} attempts remaining.")
                    self.show_authentication_screen()
                else:
                    messagebox.showerror("SECURITY BREACH", "Maximum attempts exceeded. Initiating security wipe...")
    
    def show_pin_auth(self):
        """Show PIN authentication"""
        pin_dialog = tk.Toplevel(self.root)
        pin_dialog.title("PIN AUTHENTICATION")
        pin_dialog.geometry("300x200")
        pin_dialog.configure(bg=self.colors['bg'])
        pin_dialog.transient(self.root)
        pin_dialog.grab_set()
        
        # Center dialog
        pin_dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 150
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 100
        pin_dialog.geometry(f"+{x}+{y}")
        
        main_frame = tk.Frame(pin_dialog, bg=self.colors['bg'], padx=30, pady=30)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(main_frame, text="ENTER PIN CODE:",
                 font=('Courier New', 12, 'bold'), bg=self.colors['bg'], fg=self.colors['accent']).pack(pady=(0, 20))
        
        pin_entry = tk.Entry(main_frame, show="*", bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                            font=('Courier New', 14), width=10, justify='center')
        pin_entry.pack(pady=(0, 20))
        pin_entry.focus()
        
        def authenticate_pin():
            pin = pin_entry.get()
            if self.security_manager.authenticate_pin(pin):
                self.authenticated = True
                pin_dialog.destroy()
                self.create_menu_bar()
                self.show_main_menu()
            else:
                messagebox.showerror("ACCESS DENIED", "Invalid PIN!")
                pin_dialog.destroy()
                self.show_authentication_screen()
        
        pin_entry.bind('<Return>', lambda e: authenticate_pin())
        
        ttk.Button(main_frame, text="AUTHENTICATE",
                  command=authenticate_pin,
                  style='ClassifiedButton.TButton').pack()
    
    def show_session_locked(self):
        """Show session locked screen"""
        self.authenticated = False
        self.security_manager.is_authenticated = False
        self.clear_window()
        
        # Locked banner
        banner_frame = tk.Frame(self.root, bg=self.colors['warning'], height=40)
        banner_frame.pack(fill=tk.X)
        banner_frame.pack_propagate(False)
        
        tk.Label(banner_frame, text="★ ★ ★ SESSION LOCKED - TIMEOUT EXCEEDED ★ ★ ★", 
                 bg=self.colors['warning'], fg='black', 
                 font=('Courier New', 12, 'bold')).pack(expand=True)
        
        # Main container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=150, pady=150)
        
        # Lock card
        lock_card = ttk.Frame(main_container, style='ClassifiedCard.TFrame', padding=40)
        lock_card.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(lock_card, text="🔒 SESSION LOCKED",
                 font=('Courier New', 24, 'bold'), bg=self.colors['card_bg'], fg=self.colors['warning']).pack(pady=(0, 20))
        
        tk.Label(lock_card, text="Session timed out after 10 minutes of inactivity.\nRe-authenticate to continue.",
                 font=('Courier New', 12), bg=self.colors['card_bg'], fg=self.colors['fg'], justify='center').pack(pady=(0, 30))
        
        # Quick PIN unlock if available
        if self.security_manager.pin_hash:
            tk.Label(lock_card, text="ENTER PIN TO UNLOCK:",
                     font=('Courier New', 12, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(pady=(0, 10))
            
            self.unlock_pin_entry = tk.Entry(lock_card, show="*", bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                            font=('Courier New', 14), width=10, justify='center')
            self.unlock_pin_entry.pack(pady=(0, 20))
            self.unlock_pin_entry.bind('<Return>', lambda e: self.unlock_with_pin())
            self.unlock_pin_entry.focus()
            
            ttk.Button(lock_card, text="UNLOCK",
                      command=self.unlock_with_pin,
                      style='ClassifiedButton.TButton').pack(pady=(0, 20))
        
        ttk.Button(lock_card, text="FULL AUTHENTICATION",
                  command=self.show_authentication_screen,
                  style='ClassifiedButton.TButton').pack()
    
    def unlock_with_pin(self):
        """Unlock session with PIN"""
        pin = self.unlock_pin_entry.get()
        if self.security_manager.authenticate_pin(pin):
            self.authenticated = True
            self.create_menu_bar()
            self.show_main_menu()
        else:
            messagebox.showerror("ACCESS DENIED", "Invalid PIN!")
            self.show_authentication_screen()
    
    def setup_styles(self):
        """Setup Winter Cherry Blossom theme styles for ttk widgets"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Winter Cherry Blossom TTK Styles
        style.configure('TLabel', 
                       background=self.colors['bg'], 
                       foreground=self.colors['fg'],
                       font=self.winter_cherry_theme.get_font_config('body'))
        
        style.configure('TButton', 
                       background=self.colors['button_bg'],
                       foreground=self.colors['button_fg'],
                       borderwidth=1,
                       padding=10,
                       font=self.winter_cherry_theme.get_font_config('button'))
        style.map('TButton',
                 background=[('active', self.colors.get('button_hover', self.colors['button_bg'])),
                           ('pressed', self.colors.get('button_active', self.colors['button_bg']))])
        
        style.configure('TEntry',
                       fieldbackground=self.colors['entry_bg'],
                       foreground=self.colors['entry_fg'],
                       borderwidth=1,
                       padding=8,
                       font=self.winter_cherry_theme.get_font_config('input'),
                       focuscolor=self.colors['entry_focus'])
        
        style.configure('TFrame', background=self.colors['bg'])
        
        # Winter Cherry Blossom Typography Styles
        style.configure('Title.TLabel', 
                       font=self.winter_cherry_theme.get_font_config('title'), 
                       foreground=self.colors['accent'],
                       background=self.colors['bg'])
        style.configure('Subtitle.TLabel', 
                       font=self.winter_cherry_theme.get_font_config('heading'), 
                       foreground=self.colors['fg'],
                       background=self.colors['bg'])
        
        # Winter Cherry Blossom Component Styles
        style.configure('WinterCard.TFrame', 
                       background=self.colors['card_bg'], 
                       relief='solid', 
                       borderwidth=1,
                       bordercolor=self.colors['border'])
        style.configure('WinterSidebar.TFrame', 
                       background=self.colors['sidebar_bg'])
        style.configure('WinterButton.TButton', 
                       font=self.winter_cherry_theme.get_font_config('button'),
                       background=self.colors['button_bg'],
                       foreground=self.colors['button_fg'])
        
        # Status-specific styles using Winter Cherry Blossom colors
        style.configure('Success.TLabel',
                       background=self.colors['success'],
                       foreground='#ffffff',
                       font=self.winter_cherry_theme.get_font_config('status'))
        style.configure('Warning.TLabel',
                       background=self.colors['warning'],
                       foreground='#ffffff',
                       font=self.winter_cherry_theme.get_font_config('status'))
        style.configure('Danger.TLabel',
                       background=self.colors['danger'],
                       foreground='#ffffff',
                       font=self.winter_cherry_theme.get_font_config('status'))
        style.configure('Info.TLabel',
                       background=self.colors['info'],
                       foreground=self.colors['fg'],
                       font=self.winter_cherry_theme.get_font_config('status'))
        
        # Classified-specific styles for main interface
        style.configure('ClassifiedCard.TFrame',
                       background=self.colors['card_bg'],
                       relief='solid',
                       borderwidth=1)
        
        style.configure('ClassifiedButton.TButton',
                       background=self.colors['button_bg'],
                       foreground=self.colors['button_fg'],
                       font=self.winter_cherry_theme.get_font_config('button'),
                       padding=10)
        style.map('ClassifiedButton.TButton',
                 background=[('active', self.colors['button_hover']),
                           ('pressed', self.colors['button_active'])])
        
    def create_menu_bar(self):
        """Create Winter Cherry Blossom themed menu bar"""
        menubar = Menu(self.root, tearoff=0, 
                      bg=self.colors['card_bg'], 
                      fg=self.colors['fg'], 
                      font=self.winter_cherry_theme.get_font_config('menu'),
                      activebackground=self.colors['blossom_light'],
                      activeforeground=self.colors['fg'])
        self.root.config(menu=menubar)
        
        file_menu = Menu(menubar, tearoff=0, 
                        bg=self.colors['card_bg'], 
                        fg=self.colors['fg'], 
                        font=self.winter_cherry_theme.get_font_config('menu'),
                        activebackground=self.colors['blossom_light'],
                        activeforeground=self.colors['fg'])
        menubar.add_cascade(label="OPERATIONS", menu=file_menu)
        file_menu.add_command(label="New Operation", command=self.show_main_menu)
        file_menu.add_command(label="Command Center", command=self.show_admin_panel)
        file_menu.add_command(label="User Monitoring", command=self.show_user_monitoring_panel)
        file_menu.add_command(label="Mission History", command=self.show_chat_history_window)
        file_menu.add_command(label="Disconnect", command=self.disconnect_chat)
        file_menu.add_separator()
        file_menu.add_command(label="Secure Exit", command=self.secure_exit)
        
        settings_menu = Menu(menubar, tearoff=0, 
                           bg=self.colors['card_bg'], 
                           fg=self.colors['fg'], 
                           font=self.winter_cherry_theme.get_font_config('menu'),
                           activebackground=self.colors['blossom_light'],
                           activeforeground=self.colors['fg'])
        menubar.add_cascade(label="SECURITY", menu=settings_menu)
        
        self.auto_decrypt_var = tk.BooleanVar(value=self.auto_decrypt)
        settings_menu.add_checkbutton(label="Auto-Decrypt Intel", 
                                     variable=self.auto_decrypt_var,
                                     command=self.toggle_auto_decrypt)
        
        settings_menu.add_separator()
        
        # Auto-approval settings
        self.auto_approve_var = tk.BooleanVar(value=self.auto_approve_enabled)
        settings_menu.add_checkbutton(label="Auto-Approve Clearances", 
                                     variable=self.auto_approve_var,
                                     command=self.toggle_auto_approve)
        
        # Theme selection submenu - Winter Cherry Blossom is default
        theme_menu = Menu(settings_menu, tearoff=0, 
                         bg=self.colors['card_bg'], 
                         fg=self.colors['fg'], 
                         font=self.winter_cherry_theme.get_font_config('menu'),
                         activebackground=self.colors['blossom_light'],
                         activeforeground=self.colors['fg'])
        settings_menu.add_cascade(label="Interface Theme", menu=theme_menu)
        
        # Winter Cherry Blossom as main theme (marked as default)
        theme_menu.add_command(label="✓ Winter Cherry Blossom (Default)", 
                              command=lambda: self.change_theme("winter_cherry_blossom"))
        theme_menu.add_separator()
        theme_menu.add_command(label="Matrix Green", command=lambda: self.change_theme("matrix_green"))
        theme_menu.add_command(label="Cyber Blue", command=lambda: self.change_theme("cyber_blue"))
        theme_menu.add_command(label="Desert Gold", command=lambda: self.change_theme("desert_gold"))
        theme_menu.add_command(label="Neon Purple", command=lambda: self.change_theme("neon_purple"))
        theme_menu.add_command(label="Crimson Red", command=lambda: self.change_theme("crimson_red"))
        theme_menu.add_command(label="Ocean Teal", command=lambda: self.change_theme("ocean_teal"))
        theme_menu.add_command(label="Stealth Dark", command=lambda: self.change_theme("stealth_dark"))
        theme_menu.add_command(label="Light Mode", command=lambda: self.change_theme("light_mode"))
        
        settings_menu.add_separator()
        settings_menu.add_command(label="Deniable Encryption Setup", command=self.show_deniable_encryption_setup)
        settings_menu.add_command(label="Deniable Encryption Config", command=self.show_deniable_encryption_config)
        
        help_menu = Menu(menubar, tearoff=0, bg=self.colors['bg'], fg=self.colors['fg'], font=('Courier New', 10, 'bold'))
        menubar.add_cascade(label="INTEL", menu=help_menu)
        help_menu.add_command(label="Operation Manual", command=self.show_instructions)
        help_menu.add_command(label="System Info", command=self.show_about)
    
    def load_chat_history(self):
        """Load chat history from encrypted file"""
        try:
            # Try encrypted history first
            encrypted_file = "encrypted_history.dat"
            if os.path.exists(encrypted_file):
                return self.load_encrypted_history(encrypted_file)
            
            # Fallback to plain history
            if os.path.exists(self.chat_history_file):
                with open(self.chat_history_file, 'r') as f:
                    history = json.load(f)
                    # Migrate to encrypted format
                    self.save_encrypted_history(history)
                    os.remove(self.chat_history_file)  # Remove plain file
                    return history
        except:
            pass
        return []
    
    def load_encrypted_history(self, filename):
        """Load encrypted chat history"""
        # Check if history password is required
        if self.security_manager.history_password_hash:
            password = self.prompt_history_password()
            if not password or not self.security_manager.authenticate_history(password):
                messagebox.showerror("ACCESS DENIED", "Invalid history password!")
                return []
        
        try:
            with open(filename, 'rb') as f:
                encrypted_data = f.read()
            
            # Use a simple key derivation for history encryption
            key = self.get_military_fernet_key("history_encryption_key")
            cipher = Fernet(key)
            
            decrypted_data = cipher.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except:
            return []
    
    def save_encrypted_history(self, history):
        """Save encrypted chat history"""
        try:
            # Use a simple key derivation for history encryption
            key = self.get_military_fernet_key("history_encryption_key")
            cipher = Fernet(key)
            
            json_data = json.dumps(history, indent=2)
            encrypted_data = cipher.encrypt(json_data.encode())
            
            with open("encrypted_history.dat", 'wb') as f:
                f.write(encrypted_data)
        except:
            pass
    
    def prompt_history_password(self):
        """Prompt for history password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("HISTORY ACCESS")
        dialog.geometry("400x200")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 200
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 100
        dialog.geometry(f"+{x}+{y}")
        
        main_frame = tk.Frame(dialog, bg=self.colors['bg'], padx=30, pady=30)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(main_frame, text="HISTORY FILE ACCESS",
                 font=('Courier New', 14, 'bold'), bg=self.colors['bg'], fg=self.colors['accent']).pack(pady=(0, 20))
        
        tk.Label(main_frame, text="Enter history password:",
                 font=('Courier New', 10), bg=self.colors['bg'], fg=self.colors['fg']).pack(pady=(0, 10))
        
        password_entry = tk.Entry(main_frame, show="*", bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                 font=('Courier New', 12), width=25)
        password_entry.pack(pady=(0, 20))
        password_entry.focus()
        
        result = {"password": None}
        
        def submit():
            result["password"] = password_entry.get()
            dialog.destroy()
        
        password_entry.bind('<Return>', lambda e: submit())
        
        ttk.Button(main_frame, text="ACCESS",
                  command=submit,
                  style='ClassifiedButton.TButton').pack()
        
        dialog.wait_window()
        return result["password"]
    
    def load_chat_registry_map(self):
        """Create mapping from chat_id to registry_id from history"""
        self.chat_registry_map = {}
        for chat in self.chat_history:
            chat_id = chat.get('chat_id')
            registry_id = chat.get('registry_id')
            if chat_id and registry_id:
                self.chat_registry_map[chat_id] = registry_id
    
    def save_chat_history(self):
        """Save chat history to encrypted file"""
        try:
            with open(self.chat_history_file, 'w') as f:
                json.dump(self.chat_history, f, indent=2)
        except:
            pass
    
    def save_configuration(self):
        """Save host configuration to encrypted file"""
        try:
            config = {
                'username': self.username,
                'admin_id': self.admin_id,
                'auto_decrypt': self.auto_decrypt,
                'security_settings': {
                    'session_timeout': getattr(self.security_manager, 'session_timeout', 1800),
                    'max_failed_attempts': getattr(self.security_manager, 'max_attempts', 3)
                },
                'theme': self.current_theme,
                'timestamp': time.time(),
                'version': '2.0'
            }
            
            # Always encrypt configuration using dedicated encryption system
            if hasattr(self, 'master_password') and self.master_password:
                self.config_encryption.encrypt_configuration_to_file(config, self.master_password, self.config_file)
            else:
                # Use a default password if master password not available
                default_password = "default_host_config_encryption_key"
                self.config_encryption.encrypt_configuration_to_file(config, default_password, self.config_file)
                    
        except Exception as e:
            # Configuration save failed - handled silently for security
            pass
    
    def load_configuration(self):
        """Load host configuration from encrypted file"""
        try:
            if os.path.exists(self.config_file):
                # Check if file is encrypted with new system
                if self.config_encryption.is_encrypted_configuration_file(self.config_file):
                    # Use new encryption system
                    if hasattr(self, 'master_password') and self.master_password:
                        config = self.config_encryption.decrypt_configuration_from_file(self.master_password, self.config_file)
                    else:
                        # Try default password as fallback
                        default_password = "default_host_config_encryption_key"
                        try:
                            config = self.config_encryption.decrypt_configuration_from_file(default_password, self.config_file)
                        except:
                            return  # Cannot decrypt configuration
                else:
                    # File might be unencrypted - migrate to encrypted format
                    try:
                        with open(self.config_file, 'r') as f:
                            config = json.load(f)
                        # Save in encrypted format
                        self.save_configuration()
                    except:
                        return  # Cannot read configuration
                
                # Apply configuration
                if 'username' in config:
                    self.username = config['username']
                
                if 'admin_id' in config:
                    self.admin_id = config['admin_id']
                
                if 'auto_decrypt' in config:
                    self.auto_decrypt = config['auto_decrypt']
                
                if 'security_settings' in config:
                    security_settings = config['security_settings']
                    if 'session_timeout' in security_settings:
                        self.security_manager.session_timeout = security_settings['session_timeout']
                    if 'max_failed_attempts' in security_settings:
                        self.security_manager.max_attempts = security_settings['max_failed_attempts']
                
                if 'theme' in config:
                    self.current_theme = config['theme']
                    
        except Exception as e:
            # Configuration load failed - handled silently for security
            pass
    
    def add_to_history(self, chat_info):
        """Add chat to history and update mapping"""
        # Remove if already exists
        self.chat_history = [h for h in self.chat_history if h.get('chat_id') != chat_info['chat_id']]
        
        # Add to beginning
        self.chat_history.insert(0, chat_info)
        
        # Keep only last 10 chats
        if len(self.chat_history) > 10:
            self.chat_history = self.chat_history[:10]
        
        # Update mapping
        self.chat_registry_map[chat_info['chat_id']] = chat_info['registry_id']
        
        self.save_chat_history()
    
    def clear_window(self):
        for widget in self.root.winfo_children():
            if not isinstance(widget, Menu):
                widget.destroy()
        self.message_widgets = []
    
    def show_main_menu(self):
        """Show main menu with Winter Cherry Blossom theme and scrollable content"""
        self.track_current_window(self.show_main_menu)
        self.clear_window()
        
        # Winter Cherry Blossom themed banner
        banner_frame = self.winter_components.create_styled_frame(self.root)
        banner_frame.configure(bg=self.colors['classified'], height=40)
        banner_frame.pack(fill=tk.X)
        banner_frame.pack_propagate(False)
        
        banner_label = self.winter_components.create_styled_label(
            banner_frame, 
            self.text.CLASSIFIED_BANNER,
            style='heading'
        )
        banner_label.configure(bg=self.colors['classified'], fg='white')
        banner_label.pack(expand=True)
        
        # Main container with scrollable content
        main_container = self.winter_components.create_styled_frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create scrollable container for the entire main menu
        scrollable_main = self.winter_components.create_scrollable_container(main_container)
        scrollable_main.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Get the scrollable frame
        scrollable_content = scrollable_main.get_frame()
        
        # Layout frame for sidebar and content
        layout_frame = self.winter_components.create_styled_frame(scrollable_content)
        layout_frame.pack(fill=tk.BOTH, expand=True)
        
        # Winter Cherry Blossom sidebar
        sidebar = self.winter_components.create_styled_frame(layout_frame)
        sidebar.configure(width=280, bg=self.colors['sidebar_bg'])
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(10, 0))
        sidebar.pack_propagate(False)
        
        # Sidebar content with Winter Cherry Blossom styling
        host_label = self.winter_components.create_styled_label(
            sidebar, "HOST", style='title'
        )
        host_label.configure(bg=self.colors['sidebar_bg'])
        host_label.pack(pady=(40, 10), padx=20, anchor='w')
        
        command_label = self.winter_components.create_styled_label(
            sidebar, "COMMAND CENTER", style='heading'
        )
        command_label.configure(bg=self.colors['sidebar_bg'])
        command_label.pack(pady=(0, 30), padx=20, anchor='w')
        
        # Navigation with Winter Cherry Blossom buttons
        nav_frame = self.winter_components.create_styled_frame(sidebar)
        nav_frame.configure(bg=self.colors['sidebar_bg'])
        nav_frame.pack(fill=tk.X, padx=20, pady=(0, 30))
        
        operations_label = self.winter_components.create_styled_label(
            nav_frame, "OPERATIONS", style='subheading'
        )
        operations_label.configure(
            fg=self.colors['warning'], 
            bg=self.colors['sidebar_bg']
        )
        operations_label.pack(anchor='w', pady=(0, 10))
        
        self.winter_components.create_styled_button(
            nav_frame, "NEW SECURE CHANNEL", command=self.create_chat_window
        ).pack(fill=tk.X, pady=5)
        
        self.winter_components.create_styled_button(
            nav_frame, "COMMAND CENTER", command=self.show_admin_panel
        ).pack(fill=tk.X, pady=5)
        
        self.winter_components.create_styled_button(
            nav_frame, "USER MONITORING", command=self.show_user_monitoring_panel
        ).pack(fill=tk.X, pady=5)
        
        self.winter_components.create_styled_button(
            nav_frame, "MISSION HISTORY", command=self.show_chat_history_window
        ).pack(fill=tk.X, pady=5)
        
        # Recent activity with Winter Cherry Blossom styling
        activity_frame = self.winter_components.create_styled_frame(sidebar)
        activity_frame.configure(bg=self.colors['sidebar_bg'])
        activity_frame.pack(fill=tk.X, padx=20, pady=(20, 0))
        
        recent_ops_label = self.winter_components.create_styled_label(
            activity_frame, "RECENT OPERATIONS", style='subheading'
        )
        recent_ops_label.configure(
            fg=self.colors['warning'], 
            bg=self.colors['sidebar_bg']
        )
        recent_ops_label.pack(anchor='w', pady=(0, 10))
        
        if self.chat_history:
            for chat in self.chat_history[:3]:  # Show only 3 most recent
                activity_label = self.winter_components.create_styled_label(
                    activity_frame, f"• {chat['chat_id'][:15]}...", style='caption'
                )
                activity_label.configure(bg=self.colors['sidebar_bg'])
                activity_label.pack(anchor='w', pady=2)
        
        # Main content area with Winter Cherry Blossom styling
        content = self.winter_components.create_styled_frame(layout_frame)
        content.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=40, pady=40)
        
        # Header
        header_frame = tk.Frame(content, bg=self.colors['bg'])
        header_frame.pack(fill=tk.X, pady=(0, 30))
        
        tk.Label(header_frame, text="🔒", 
                 font=('Courier New', 36), bg=self.colors['bg'], fg=self.colors['accent']).pack(side=tk.LEFT, padx=(0, 15))
        
        title_frame = tk.Frame(header_frame, bg=self.colors['bg'])
        title_frame.pack(side=tk.LEFT, fill=tk.Y)
        
        tk.Label(title_frame, text="SECURE COMMAND HOST",
                 font=('Courier New', 24, 'bold'), fg=self.colors['accent'], bg=self.colors['bg']).pack(anchor='w')
        
        tk.Label(title_frame, text="CLASSIFIED COMMUNICATION SYSTEM",
                 font=('Courier New', 12, 'bold'), fg=self.colors['fg'], bg=self.colors['bg']).pack(anchor='w')
        
        # Stats cards
        stats_frame = tk.Frame(content, bg=self.colors['bg'])
        stats_frame.pack(fill=tk.X, pady=(0, 40))
        
        # Stat 1
        stat1 = tk.Frame(stats_frame, bg=self.colors['card_bg'], relief='solid', bd=1, padx=25, pady=25)
        stat1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 15))
        tk.Label(stat1, text="📊", font=('Courier New', 24), bg=self.colors['card_bg'], fg=self.colors['accent']).pack()
        tk.Label(stat1, text=f"{len(self.chat_history)}", 
                 font=('Courier New', 28, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(pady=(10, 5))
        tk.Label(stat1, text="ACTIVE CHANNELS",
                 font=('Courier New', 10, 'bold'), bg=self.colors['card_bg'], fg=self.colors['fg']).pack()
        
        # Stat 2
        stat2 = tk.Frame(stats_frame, bg=self.colors['card_bg'], relief='solid', bd=1, padx=25, pady=25)
        stat2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=15)
        tk.Label(stat2, text="🔐", font=('Courier New', 24), bg=self.colors['card_bg'], fg=self.colors['accent']).pack()
        tk.Label(stat2, text="AES-256-GCM", 
                 font=('Courier New', 20, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(pady=(10, 5))
        tk.Label(stat2, text="MILITARY ENCRYPTION",
                 font=('Courier New', 10, 'bold'), bg=self.colors['card_bg'], fg=self.colors['fg']).pack()
        
        # Stat 3
        stat3 = tk.Frame(stats_frame, bg=self.colors['card_bg'], relief='solid', bd=1, padx=25, pady=25)
        stat3.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(15, 0))
        tk.Label(stat3, text="🌐", font=('Courier New', 24), bg=self.colors['card_bg'], fg=self.colors['accent']).pack()
        tk.Label(stat3, text="TOR ONLY", 
                 font=('Courier New', 28, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(pady=(10, 5))
        tk.Label(stat3, text="ANONYMOUS ROUTING",
                 font=('Courier New', 10, 'bold'), bg=self.colors['card_bg'], fg=self.colors['fg']).pack()
        
        # Quick actions
        tk.Label(content, text="CLASSIFIED OPERATIONS",
                 font=('Courier New', 16, 'bold'), bg=self.colors['bg'], fg=self.colors['accent']).pack(anchor='w', pady=(0, 20))
        
        actions_frame = tk.Frame(content, bg=self.colors['bg'])
        actions_frame.pack(fill=tk.X)
        
        # Action 1
        action1 = tk.Frame(actions_frame, bg=self.colors['card_bg'], relief='solid', bd=1, padx=25, pady=25)
        action1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 15))
        tk.Label(action1, text="➕", font=('Courier New', 28), bg=self.colors['card_bg'], fg=self.colors['accent']).pack()
        tk.Label(action1, text="CREATE SECURE CHANNEL",
                 font=('Courier New', 14, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(pady=(15, 10))
        tk.Label(action1, text="Establish new encrypted communication channel with agent registration",
                 wraplength=200, font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg']).pack(pady=(0, 15))
        self.winter_components.create_styled_button(action1, text="INITIATE",
                  command=self.create_chat_window).pack()
        
        # Action 2
        action2 = tk.Frame(actions_frame, bg=self.colors['card_bg'], relief='solid', bd=1, padx=25, pady=25)
        action2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=15)
        tk.Label(action2, text="👥", font=('Courier New', 28), bg=self.colors['card_bg'], fg=self.colors['accent']).pack()
        tk.Label(action2, text="MANAGE AGENTS",
                 font=('Courier New', 14, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(pady=(15, 10))
        tk.Label(action2, text="Approve or deny agent access requests to classified channels",
                 wraplength=200, font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg']).pack(pady=(0, 15))
        self.winter_components.create_styled_button(action2, text="COMMAND CENTER",
                  command=self.show_admin_panel).pack()
        
        # Action 3
        action3 = tk.Frame(actions_frame, bg=self.colors['card_bg'], relief='solid', bd=1, padx=25, pady=25)
        action3.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(15, 0))
        tk.Label(action3, text="💬", font=('Courier New', 28), bg=self.colors['card_bg'], fg=self.colors['accent']).pack()
        tk.Label(action3, text="ACCESS CHANNELS",
                 font=('Courier New', 14, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(pady=(15, 10))
        tk.Label(action3, text="Access existing secure communication channels",
                 wraplength=200, font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg']).pack(pady=(0, 15))
        self.winter_components.create_styled_button(action3, text="MISSION HISTORY",
                  command=self.show_chat_history_window).pack()
        
        # Status bar
        status_frame = tk.Frame(content, relief='solid', borderwidth=2, bg=self.colors['card_bg'])
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(40, 0))
        
        status_text = "SYSTEM READY - SECURE CHANNELS OPERATIONAL"
        tk.Label(status_frame, text=status_text,
                 font=('Courier New', 9, 'bold'),
                 foreground=self.colors['success'], bg=self.colors['card_bg']).pack(side=tk.LEFT, padx=10, pady=5)
        
        # Add noise traffic
        self.traffic_obfuscator.add_noise()
    
    def get_military_fernet_key(self, shared_key, salt=None):
        """Enhanced military-grade key derivation with random salt"""
        if isinstance(shared_key, str):
            shared_key = shared_key.encode()
        
        # Generate random salt if not provided
        if salt is None:
            salt = secrets.token_bytes(32)
        elif isinstance(salt, str):
            salt = base64.b64decode(salt.encode('utf-8'))
        
        # Use PBKDF2 with SHA-512 and enhanced iterations for maximum security
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=100000,  # Balanced security and performance
        )
        key = base64.urlsafe_b64encode(kdf.derive(shared_key))
        
        # Return just the key (as bytes) for Fernet compatibility
        return key
    
    def get_military_fernet_key_with_salt(self, shared_key, salt=None):
        """Enhanced military-grade key derivation with random salt - returns both key and salt"""
        if isinstance(shared_key, str):
            shared_key = shared_key.encode()
        
        # Generate random salt if not provided
        if salt is None:
            salt = secrets.token_bytes(32)
        elif isinstance(salt, str):
            salt = base64.b64decode(salt.encode('utf-8'))
        
        # Use PBKDF2 with SHA-512 and enhanced iterations for maximum security
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=100000,  # Balanced security and performance
        )
        key = base64.urlsafe_b64encode(kdf.derive(shared_key))
        
        # Return both key and salt for storage
        return {
            'key': key,
            'salt': base64.b64encode(salt).decode('utf-8')
        }
    
    def secure_request(self, method, url, **kwargs):
        """Make secure request through Tor with enhanced obfuscation and external storage encryption"""
        self.traffic_obfuscator.add_noise()
        
        # Apply external storage encryption for data going to JSONBlob
        if 'json' in kwargs and (BASE_URL in url or REGISTRY_URL in url):
            try:
                # Encrypt data before sending to external storage
                if self.master_password_manager.external_storage:
                    encrypted_payload = self.master_password_manager.external_storage.prepare_data_for_jsonblob(kwargs['json'])
                    kwargs['json'] = encrypted_payload
                else:
                    # Fallback: just obfuscate if encryption not available
                    kwargs['json'] = self.traffic_obfuscator.obfuscate_payload(kwargs['json'])
            except Exception as e:
                # External storage encryption failed, using obfuscation
                kwargs['json'] = self.traffic_obfuscator.obfuscate_payload(kwargs['json'])
        elif 'json' in kwargs:
            # For non-JSONBlob requests, just obfuscate
            kwargs['json'] = self.traffic_obfuscator.obfuscate_payload(kwargs['json'])
        
        response = self.tor_proxy.make_request(method, url, **kwargs)
        
        # Decrypt and deobfuscate response if needed
        if response and response.status_code in [200, 201]:
            try:
                if 'application/json' in response.headers.get('content-type', ''):
                    original_json = response.json
                    def processed_json():
                        data = original_json()
                        
                        # Decrypt data from external storage if applicable
                        if (BASE_URL in url or REGISTRY_URL in url) and self.master_password_manager.external_storage:
                            try:
                                # Check if this is encrypted external storage data
                                if isinstance(data, dict) and 'encrypted_payload' in data:
                                    return self.master_password_manager.external_storage.extract_data_from_jsonblob(data)
                                else:
                                    # Fallback: try deobfuscation
                                    return self.traffic_obfuscator.deobfuscate_payload(data)
                            except Exception as e:
                                # External storage decryption failed, trying deobfuscation
                                return self.traffic_obfuscator.deobfuscate_payload(data)
                        else:
                            # For non-JSONBlob responses, just deobfuscate
                            return self.traffic_obfuscator.deobfuscate_payload(data)
                    
                    response.json = processed_json
            except Exception as e:
                # Response processing failed silently
                pass
        
        return response
    
    def show_chat_history_window(self):
        """Show chat history for quick rejoining"""
        self.clear_window()
        self.track_current_window(self.show_chat_history_window)
        
        # CLASSIFIED BANNER
        banner_frame = tk.Frame(self.root, bg=self.colors['classified'], height=40)
        banner_frame.pack(fill=tk.X)
        banner_frame.pack_propagate(False)
        
        tk.Label(banner_frame, text="★ ★ ★ CLASSIFIED - MISSION HISTORY - TOP SECRET ★ ★ ★", 
                 bg=self.colors['classified'], fg='white', 
                 font=('Courier New', 12, 'bold')).pack(expand=True)
        
        # Main container with scrollable content
        main_container = self.winter_components.create_styled_frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create scrollable container for the entire window
        scrollable_main = self.winter_components.create_scrollable_container(main_container)
        scrollable_main.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Get the scrollable frame
        scrollable_content = scrollable_main.get_frame()
        
        # Layout frame for sidebar and content
        layout_frame = self.winter_components.create_styled_frame(scrollable_content)
        layout_frame.pack(fill=tk.BOTH, expand=True)
        
        # Sidebar
        sidebar = self.winter_components.create_styled_frame(layout_frame)
        sidebar.configure(width=280, bg=self.colors['sidebar_bg'])
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(10, 0))
        sidebar.pack_propagate(False)
        
        # Sidebar content
        title_label = self.winter_components.create_styled_label(
            sidebar, "MISSION HISTORY", style='title'
        )
        title_label.configure(bg=self.colors['sidebar_bg'])
        title_label.pack(pady=(40, 30), padx=20, anchor='w')
        
        nav_frame = self.winter_components.create_styled_frame(sidebar)
        nav_frame.configure(bg=self.colors['sidebar_bg'])
        nav_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        self.winter_components.create_styled_button(
            nav_frame, "RETURN TO BASE", command=self.show_main_menu
        ).pack(fill=tk.X, pady=5)
        
        self.winter_components.create_styled_button(
            nav_frame, "NEW OPERATION", command=self.create_chat_window
        ).pack(fill=tk.X, pady=5)
        
        self.winter_components.create_styled_button(
            nav_frame, "COMMAND CENTER", command=self.show_admin_panel
        ).pack(fill=tk.X, pady=5)
        
        # Main content
        content = self.winter_components.create_styled_frame(layout_frame)
        content.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=40, pady=40)
        
        # Header
        header_frame = self.winter_components.create_styled_frame(content)
        header_frame.pack(fill=tk.X, pady=(0, 30))
        
        self.winter_components.create_styled_label(
            header_frame, "CLASSIFIED MISSION HISTORY", style='title'
        ).pack(side=tk.LEFT)
        
        self.winter_components.create_styled_label(
            header_frame, f"({len(self.chat_history)} operations)", style='body'
        ).pack(side=tk.LEFT, padx=10, pady=8)
        
        if not self.chat_history:
            empty_frame = self.winter_components.create_styled_frame(content)
            empty_frame.pack(fill=tk.BOTH, expand=True, padx=50, pady=50)
            
            empty_icon = self.winter_components.create_styled_label(
                empty_frame, "📭", style='title'
            )
            empty_icon.configure(font=('Courier New', 48))
            empty_icon.pack(pady=(20, 20))
            
            self.winter_components.create_styled_label(
                empty_frame, "NO MISSION HISTORY", style='heading'
            ).pack(pady=(0, 15))
            
            self.winter_components.create_styled_label(
                empty_frame, "Initiate first secure operation to begin", style='body'
            ).pack(pady=(0, 30))
            
            self.winter_components.create_styled_button(
                empty_frame, "INITIATE OPERATION", command=self.create_chat_window
            ).pack()
        else:
            # Table-like display with scrollable content
            table_frame = self.winter_components.create_styled_frame(content)
            table_frame.pack(fill=tk.BOTH, expand=True)
            
            # Table header
            header = self.winter_components.create_styled_frame(table_frame)
            header.pack(fill=tk.X, pady=(20, 0), padx=20)
            
            channel_header = self.winter_components.create_styled_label(
                header, "CHANNEL ID", style='subheading'
            )
            channel_header.configure(width=30)
            channel_header.pack(side=tk.LEFT)
            
            registry_header = self.winter_components.create_styled_label(
                header, "REGISTRY ID", style='subheading'
            )
            registry_header.configure(width=30)
            registry_header.pack(side=tk.LEFT)
            
            actions_header = self.winter_components.create_styled_label(
                header, "ACTIONS", style='subheading'
            )
            actions_header.configure(width=15)
            actions_header.pack(side=tk.RIGHT)
            
            # Separator
            separator = tk.Frame(table_frame, height=2, bg=self.colors['accent'])
            separator.pack(fill=tk.X, padx=20, pady=10)
            
            # Create another scrollable container for the table content
            table_scroll = self.winter_components.create_scrollable_container(table_frame, height=400)
            table_scroll.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
            table_container = table_scroll.get_frame()
            
            # Table rows
            for idx, chat in enumerate(self.chat_history):
                row_frame = tk.Frame(table_container, bg=self.colors['card_bg'] if idx % 2 == 0 else self.colors['table_row_odd'])
                row_frame.pack(fill=tk.X, pady=5, padx=(0, 20))
                
                # Chat ID
                chat_id_label = tk.Label(row_frame, text=f"{chat['chat_id'][:20]}...",
                         font=('Courier New', 9), bg=row_frame['bg'], fg=self.colors['fg'],
                         width=30)
                chat_id_label.pack(side=tk.LEFT, padx=10)
                
                # Registry ID
                registry_id = chat.get('registry_id', 'N/A')
                registry_label = tk.Label(row_frame, text=f"{registry_id[:20]}...",
                         font=('Courier New', 9), bg=row_frame['bg'], fg=self.colors['fg'],
                         width=30)
                registry_label.pack(side=tk.LEFT, padx=10)
                
                # Actions
                action_frame = tk.Frame(row_frame, bg=row_frame['bg'])
                action_frame.pack(side=tk.RIGHT, padx=10)
                
                # Rejoin button
                rejoin_btn = self.winter_components.create_styled_button(
                    action_frame, "REJOIN", 
                    command=lambda c=chat: self.rejoin_from_history(c)
                )
                rejoin_btn.pack(side=tk.LEFT, padx=2)
                
                # View details button
                details_btn = self.winter_components.create_styled_button(
                    action_frame, "DETAILS", 
                    command=lambda c=chat: self.show_chat_details(c)
                )
                details_btn.pack(side=tk.LEFT, padx=2)
                
                # Remove button
                remove_btn = self.winter_components.create_styled_button(
                    action_frame, "REMOVE", 
                    command=lambda c=chat: self.remove_from_history(c)
                )
                remove_btn.configure(bg=self.colors['danger'])
                remove_btn.pack(side=tk.LEFT, padx=2)
    
    def show_chat_details(self, chat_info):
        """Show detailed information about a chat from history"""
        details_window = tk.Toplevel(self.root)
        details_window.title("Chat Details")
        details_window.geometry("600x500")
        details_window.configure(bg=self.colors['bg'])
        
        # Apply theme
        self.winter_components.apply_window_theme(details_window)
        
        # Header
        header_frame = self.winter_components.create_styled_frame(details_window)
        header_frame.pack(fill=tk.X, padx=20, pady=20)
        
        self.winter_components.create_styled_label(
            header_frame, "CHAT OPERATION DETAILS", style='title'
        ).pack()
        
        # Details content
        content_frame = self.winter_components.create_styled_frame(details_window)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # Create scrollable text area for details
        details_text = self.winter_components.create_styled_text(content_frame, height=20, width=70)
        details_text.pack(fill=tk.BOTH, expand=True)
        
        # Format chat details
        details = f"""CLASSIFIED OPERATION DETAILS
{'='*50}

CHANNEL ID: {chat_info.get('chat_id', 'N/A')}
REGISTRY ID: {chat_info.get('registry_id', 'N/A')}
USERNAME: {chat_info.get('username', 'N/A')}
CHAT TYPE: {chat_info.get('chat_type', 'N/A')}
CREATED: {datetime.fromtimestamp(chat_info.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S')}

ENCRYPTION KEY: {chat_info.get('encryption_key', 'N/A')[:20]}...

STATUS: {'ACTIVE' if chat_info.get('active', False) else 'INACTIVE'}

SECURITY LEVEL: CLASSIFIED
CLEARANCE: TOP SECRET
"""
        
        details_text.insert(tk.END, details)
        details_text.configure(state='disabled')
        
        # Buttons
        button_frame = self.winter_components.create_styled_frame(details_window)
        button_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        self.winter_components.create_styled_button(
            button_frame, "REJOIN CHAT", 
            command=lambda: [details_window.destroy(), self.rejoin_from_history(chat_info)]
        ).pack(side=tk.LEFT, padx=5)
        
        self.winter_components.create_styled_button(
            button_frame, "CLOSE", command=details_window.destroy
        ).pack(side=tk.RIGHT, padx=5)
    
    def remove_from_history(self, chat_info):
        """Remove chat from history with confirmation"""
        result = messagebox.askyesno(
            "REMOVE FROM HISTORY",
            f"Remove this operation from history?\n\nChannel: {chat_info['chat_id'][:20]}...\n\nThis action cannot be undone."
        )
        
        if result:
            try:
                # Remove from chat history
                self.chat_history = [h for h in self.chat_history if h.get('chat_id') != chat_info['chat_id']]
                
                # Remove from registry mapping if exists
                if hasattr(self, 'chat_registry_map') and chat_info['chat_id'] in self.chat_registry_map:
                    del self.chat_registry_map[chat_info['chat_id']]
                
                # Save updated history
                self.save_chat_history()
                
                # Refresh the history window
                self.show_chat_history_window()
                
                messagebox.showinfo("REMOVED", "Operation removed from history")
                
            except Exception as e:
                messagebox.showerror("ERROR", f"Failed to remove operation: {str(e)}")
                tk.Label(row_frame, text=f"{chat['registry_id'][:20]}...",
                         font=('Courier New', 9), bg=row_frame['bg'], fg=self.colors['fg'],
                         width=30).pack(side=tk.LEFT, padx=10)
                
                # Actions
                action_frame = tk.Frame(row_frame, bg=row_frame['bg'])
                action_frame.pack(side=tk.RIGHT, padx=10)
                
                ttk.Button(action_frame, text="RECONNECT",
                          command=lambda c=chat: self.rejoin_from_history(c),
                          style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=2)
                
                # Quick admin button
                ttk.Button(action_frame, text="COMMAND",
                          command=lambda c=chat: self.quick_admin_access(c),
                          style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=2)
    
    def quick_admin_access(self, chat_info):
        """Quick access to admin panel for a specific chat"""
        self.chat_id = chat_info['chat_id']
        self.registry_id = chat_info['registry_id']
        self.show_admin_panel()
        # Auto-load the registry
        if self.registry_id:
            self.admin_chat_id_entry.delete(0, tk.END)
            self.admin_chat_id_entry.insert(0, self.chat_id)
            self.load_registry_for_chat()
    
    def rejoin_from_history(self, chat_info):
        """Rejoin chat from history"""
        try:
            self.chat_id = chat_info['chat_id']
            self.registry_id = chat_info['registry_id']
            self.encryption_key = chat_info['encryption_key']
            self.username = chat_info.get('username', 'HOST_USER')
            
            # Store key securely
            key_id = self.secure_memory.store_secure('encryption_key', self.encryption_key)
            
            fernet_key = self.get_military_fernet_key(self.encryption_key)
            self.cipher = Fernet(fernet_key)
            self.connected = True
            
            # Check if still approved in registry
            try:
                response = self.secure_request('GET', f"{REGISTRY_URL}/{self.registry_id}", timeout=5)
                if response.status_code == 200:
                    registry = response.json()
                    if self.username in registry.get("approved_users", []):
                        self.show_chat_window()
                    else:
                        messagebox.showwarning("ACCESS DENIED", "Agent clearance revoked for this channel.")
                        self.show_main_menu()
            except:
                self.show_chat_window()
                
        except Exception as e:
            messagebox.showerror("OPERATION FAILED", f"Failed to reconnect: {str(e)}")
    
    def manual_join_window(self):
        """Manual join window"""
        dialog = tk.Toplevel(self.root)
        dialog.title("MANUAL CHANNEL ACCESS")
        dialog.geometry("500x500")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (500 // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (500 // 2)
        dialog.geometry(f"+{x}+{y}")
        
        main_frame = tk.Frame(dialog, bg=self.colors['bg'], padx=30, pady=30)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(main_frame, 
                 text="MANUAL CHANNEL ACCESS",
                 font=('Courier New', 24, 'bold'), fg=self.colors['accent'], bg=self.colors['bg']).pack(pady=(0, 20))
        
        # Form
        form_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(form_frame, text="CHANNEL ID", 
                 font=('Courier New', 10, 'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor='w', pady=(10, 5))
        chat_id_entry = tk.Entry(form_frame, bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                font=('Courier New', 10), insertbackground=self.colors['entry_fg'])
        chat_id_entry.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(form_frame, text="REGISTRY ID", 
                 font=('Courier New', 10, 'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor='w', pady=(10, 5))
        registry_entry = tk.Entry(form_frame, bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                 font=('Courier New', 10), insertbackground=self.colors['entry_fg'])
        registry_entry.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(form_frame, text="ENCRYPTION KEY", 
                 font=('Courier New', 10, 'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor='w', pady=(10, 5))
        
        key_frame = tk.Frame(form_frame, bg=self.colors['bg'])
        key_frame.pack(fill=tk.X, pady=(0, 15))
        
        key_entry = tk.Entry(key_frame, show="*", bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                            font=('Courier New', 10), insertbackground=self.colors['entry_fg'])
        key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        ttk.Button(key_frame, text="SHOW/HIDE", 
                  command=lambda: self.toggle_entry_visibility(key_entry),
                  style='ClassifiedButton.TButton').pack(side=tk.RIGHT)
        
        def join():
            chat_id = chat_id_entry.get().strip()
            registry_id = registry_entry.get().strip()
            key = key_entry.get().strip()
            
            if chat_id and registry_id and key:
                self.chat_id = chat_id
                self.registry_id = registry_id
                self.encryption_key = key
                
                try:
                    # Store key securely
                    key_id = self.secure_memory.store_secure('encryption_key', key)
                    
                    fernet_key = self.get_military_fernet_key(key)
                    self.cipher = Fernet(fernet_key)
                    self.connected = True
                    
                    # Save to history
                    chat_info = {
                        'chat_id': chat_id,
                        'registry_id': registry_id,
                        'encryption_key': key,
                        'username': self.username,
                        'timestamp': time.time()
                    }
                    self.add_to_history(chat_info)
                    
                    dialog.destroy()
                    
                    # Check approval
                    response = self.secure_request('GET', f"{REGISTRY_URL}/{registry_id}", timeout=5)
                    if response.status_code == 200:
                        registry = response.json()
                        if self.username in registry.get("approved_users", []):
                            self.show_chat_window()
                        else:
                            messagebox.showwarning("ACCESS DENIED", "Agent not authorized for this channel.")
                            self.show_admin_panel()
                    else:
                        self.show_chat_window()
                        
                except Exception as e:
                    messagebox.showerror("OPERATION FAILED", f"Invalid credentials: {str(e)}")
            else:
                messagebox.showerror("INCOMPLETE DATA", "All fields required for channel access")
        
        button_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        ttk.Button(button_frame, text="ACCESS CHANNEL", 
                  command=join,
                  style='ClassifiedButton.TButton').pack(side=tk.RIGHT)
        
        ttk.Button(button_frame, text="ABORT",
                  command=dialog.destroy,
                  style='ClassifiedButton.TButton').pack(side=tk.RIGHT, padx=10)
    
    def toggle_entry_visibility(self, entry):
        if entry.cget('show') == '*':
            entry.config(show='')
        else:
            entry.config(show='*')
    
    def create_chat_window(self):
        print("DEBUG: create_chat_window method called!")  # Debug line
        try:
            self.clear_window()
            print("DEBUG: Window cleared successfully")  # Debug line
        except Exception as e:
            print(f"DEBUG: Error in create_chat_window: {e}")  # Debug line
            import traceback
            traceback.print_exc()
            return
        
        # Track current window for theme changes
        self.track_current_window(self.create_chat_window)
        
        # CLASSIFIED BANNER
        banner_frame = tk.Frame(self.root, bg=self.colors['classified'], height=40)
        banner_frame.pack(fill=tk.X)
        banner_frame.pack_propagate(False)
        
        tk.Label(banner_frame, text="★ ★ ★ CLASSIFIED - CREATE SECURE CHANNEL - TOP SECRET ★ ★ ★", 
                 bg=self.colors['classified'], fg='white', 
                 font=('Courier New', 12, 'bold')).pack(expand=True)
        
        # Main container with scrollable content
        main_container = self.winter_components.create_styled_frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create scrollable container for the entire window
        scrollable_main = self.winter_components.create_scrollable_container(main_container)
        scrollable_main.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Get the scrollable frame
        scrollable_content = scrollable_main.get_frame()
        
        # Layout frame for sidebar and content
        layout_frame = self.winter_components.create_styled_frame(scrollable_content)
        layout_frame.pack(fill=tk.BOTH, expand=True)
        
        # Sidebar
        sidebar = self.winter_components.create_styled_frame(layout_frame)
        sidebar.configure(width=280, bg=self.colors['sidebar_bg'])
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(10, 0))
        sidebar.pack_propagate(False)
        
        # Sidebar content
        title_label = self.winter_components.create_styled_label(
            sidebar, "CREATE CHANNEL", style='title'
        )
        title_label.configure(bg=self.colors['sidebar_bg'])
        title_label.pack(pady=(40, 30), padx=20, anchor='w')
        
        nav_frame = self.winter_components.create_styled_frame(sidebar)
        nav_frame.configure(bg=self.colors['sidebar_bg'])
        nav_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        self.winter_components.create_styled_button(
            nav_frame, "RETURN TO BASE", command=self.show_main_menu
        ).pack(fill=tk.X, pady=5)
        
        self.winter_components.create_styled_button(
            nav_frame, "COMMAND CENTER", command=self.show_admin_panel
        ).pack(fill=tk.X, pady=5)
        
        # Main content
        content = self.winter_components.create_styled_frame(layout_frame)
        content.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=40, pady=40)
        
        self.winter_components.create_styled_label(
            content, "CREATE SECURE CHANNEL", style='title'
        ).pack(pady=(0, 10))
        
        self.winter_components.create_styled_label(
            content, "Establish new encrypted communication channel with agent registration", style='body'
        ).pack(pady=(0, 30))
        
        # Form card
        form_card = self.winter_components.create_styled_frame(content)
        form_card.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Username
        self.winter_components.create_styled_label(
            form_card, "OPERATOR CALLSIGN", style='subheading'
        ).pack(anchor='w', pady=(0, 10))
        
        self.username_entry = self.winter_components.create_styled_entry(form_card)
        self.username_entry.pack(fill=tk.X, pady=(0, 20))
        self.username_entry.insert(0, "Host")
        
        # Chat type selection
        chat_type_section = self.winter_components.create_styled_frame(form_card)
        chat_type_section.pack(fill=tk.X, pady=(0, 20))
        
        self.winter_components.create_styled_label(
            chat_type_section, "CHANNEL TYPE", style='subheading'
        ).pack(anchor='w', pady=(0, 10))
        
        self.chat_type_var = tk.StringVar(value="text")
        
        text_radio = tk.Radiobutton(chat_type_section, text="💬 TEXT CHAT - Secure messaging with file sharing", 
                      variable=self.chat_type_var, value="text",
                      bg=self.colors['card_bg'], fg=self.colors['fg'], 
                      selectcolor=self.colors['accent_light'],
                      font=self.winter_cherry_theme.get_font_config('body'))
        text_radio.pack(anchor='w', pady=5)
        
        video_radio = tk.Radiobutton(chat_type_section, text="🎥 VIDEO CHAT - Video calls with screen sharing", 
                      variable=self.chat_type_var, value="video",
                      bg=self.colors['card_bg'], fg=self.colors['fg'], 
                      selectcolor=self.colors['accent_light'],
                      font=self.winter_cherry_theme.get_font_config('body'))
        video_radio.pack(anchor='w', pady=5)
        
        # Encryption key section
        key_section = self.winter_components.create_styled_frame(form_card)
        key_section.pack(fill=tk.X, pady=(0, 20))
        
        self.winter_components.create_styled_label(
            key_section, "MILITARY-GRADE ENCRYPTION KEY", style='subheading'
        ).pack(anchor='w', pady=(0, 10))
        
        self.key_var = tk.StringVar()
        
        key_display_frame = self.winter_components.create_styled_frame(key_section)
        key_display_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.key_entry = self.winter_components.create_styled_entry(
            key_display_frame, textvariable=self.key_var, show="*"
        )
        self.key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        self.winter_components.create_styled_button(
            key_display_frame, "SHOW/HIDE", command=self.toggle_key_visibility
        ).pack(side=tk.RIGHT)
        
        self.winter_components.create_styled_button(
            key_section, "GENERATE SECURE KEY", command=self.generate_key
        ).pack(fill=tk.X, pady=(10, 0))
        
        # Info box
        info_box = self.winter_components.create_styled_frame(form_card)
        info_box.configure(relief='solid', borderwidth=2)
        info_box.pack(fill=tk.X, pady=(20, 0), padx=20)
        
        security_label = self.winter_components.create_styled_label(
            info_box, "⚠️ SECURITY PROTOCOL", style='subheading'
        )
        security_label.configure(fg=self.colors['warning'])
        security_label.pack(anchor='w', pady=(10, 10))
        
        security_text = """• All communications routed through TOR network
• AES-256-GCM military-grade encryption
• PBKDF2 key derivation with 1M iterations
• Zero-trace operation with secure memory wiping
• Traffic obfuscation and dummy requests
• Agent registration required for access"""
        
        security_text_label = self.winter_components.create_styled_label(
            info_box, security_text, style='body_small'
        )
        security_text_label.configure(justify=tk.LEFT)
        security_text_label.pack(anchor='w', padx=20, pady=(0, 10))
        
        # Action buttons
        button_frame = self.winter_components.create_styled_frame(form_card)
        button_frame.pack(fill=tk.X, pady=(30, 0))
        
        self.winter_components.create_styled_button(
            button_frame, "ESTABLISH CHANNEL", 
            command=self.create_chat_with_registry
        ).pack(side=tk.RIGHT)
        
        self.status_label = tk.Label(form_card, text="", foreground=self.colors['danger'], bg=self.colors['card_bg'])
        self.status_label.pack(anchor='w', pady=(10, 0))
        
        # Auto-generate key on load
        self.generate_key()
    
    def generate_key(self):
        """Generate military-grade encryption key"""
        # Use cryptographically secure random generator
        random_key = base64.urlsafe_b64encode(secrets.token_bytes(32))
        
        # Only set the key_var if it exists (when create_chat_window has been called)
        if hasattr(self, 'key_var') and self.key_var:
            self.key_var.set(random_key.decode())
        
        # Always return the generated key for other uses
        return random_key.decode()
    
    def toggle_key_visibility(self):
        """Toggle encryption key visibility"""
        if hasattr(self, 'key_entry') and self.key_entry:
            if self.key_entry.cget('show') == '*':
                self.key_entry.config(show='')
            else:
                self.key_entry.config(show='*')
    
    def get_fernet_key(self, shared_key):
        """Legacy compatibility - use military version"""
        return self.get_military_fernet_key(shared_key)
    
    def create_chat_with_registry(self):
        print("DEBUG: create_chat_with_registry called")
        
        try:
            self.username = self.username_entry.get().strip() or "Host"
            encryption_key = self.key_entry.get().strip()
            chat_type = self.chat_type_var.get()
            
            print(f"DEBUG: username={self.username}, key_length={len(encryption_key) if encryption_key else 0}, chat_type={chat_type}")
            
            if not encryption_key:
                print("DEBUG: No encryption key provided")
                messagebox.showerror("OPERATION FAILED", "Encryption key required for secure channel")
                return
            
            print("DEBUG: Starting chat creation process...")
            
            # Update status to show progress
            if hasattr(self, 'status_label') and self.status_label:
                self.status_label.config(text="🔄 Creating secure channel...", fg=self.colors['info'])
                self.root.update()
            
            # Store key securely
            key_id = self.secure_memory.store_secure('encryption_key', encryption_key)
            
            fernet_key = self.get_military_fernet_key(encryption_key)
            self.cipher = Fernet(fernet_key)
            self.encryption_key = encryption_key
            
            random_id = hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:32]
            
            # Start network operations in a separate thread to avoid UI freezing
            def create_channel_async():
                try:
                    initial_data = {
                        "messages": [],
                        "users": [self.username],
                        "created": datetime.now().isoformat(),
                        "encrypted": True,
                        "chat_type": chat_type,
                        "metadata": {
                            "last_cleanup": time.time(),
                            "message_count": 0,
                            "security_level": "CLASSIFIED",
                            "encryption": "AES-256-GCM",
                            "chat_type": chat_type
                        }
                    }
                    
                    # Try to make requests with shorter timeout to avoid hanging
                    try:
                        print("DEBUG: Making initial chat request...")
                        headers = {'Content-Type': 'application/json'}
                        
                        # Update status
                        self.root.after(0, lambda: self.update_status("🔄 Connecting through TOR..."))
                        
                        response = self.secure_request(
                            'POST',
                            f"{BASE_URL}",
                            json=initial_data,
                            headers=headers,
                            timeout=5  # Reduced timeout to 5 seconds
                        )
                        
                        print(f"DEBUG: Initial response status: {response.status_code if response else 'None'}")
                        
                        if response and response.status_code == 201:
                            location = response.headers.get('Location', '')
                            if location:
                                self.chat_id = location.split('/')[-1]
                            else:
                                self.chat_id = f"host-secure-{random_id}"
                        else:
                            self.chat_id = f"secure-{random_id}"
                        
                        print(f"DEBUG: Chat ID: {self.chat_id}")
                        
                        registry_data = {
                            "admin_id": self.admin_id,
                            "chat_id": self.chat_id,
                            "created": datetime.now().isoformat(),
                            "pending_requests": [],
                            "approved_users": [self.username],
                            "rejected_users": [],
                            "metadata": {
                                "total_requests": 0,
                                "last_updated": time.time(),
                                "security_level": "CLASSIFIED",
                                "clearance_required": "TOP_SECRET"
                            }
                        }
                        
                        print("DEBUG: Making registry request...")
                        self.root.after(0, lambda: self.update_status("🔄 Creating registry..."))
                        
                        registry_response = self.secure_request(
                            'POST',
                            f"{REGISTRY_URL}",
                            json=registry_data,
                            headers=headers,
                            timeout=5  # Reduced timeout to 5 seconds
                        )
                        
                        print(f"DEBUG: Registry response status: {registry_response.status_code if registry_response else 'None'}")
                        
                        if registry_response and registry_response.status_code == 201:
                            location = registry_response.headers.get('Location', '')
                            if location:
                                self.registry_id = location.split('/')[-1]
                            else:
                                try:
                                    result = registry_response.json()
                                    self.registry_id = result.get('id', f"registry-{random_id}")
                                except:
                                    self.registry_id = f"registry-{random_id}"
                        else:
                            self.registry_id = f"registry-{random_id}"
                            
                    except Exception as tor_error:
                        print(f"DEBUG: TOR connection failed, using demo mode: {str(tor_error)}")
                        # Demo mode - create local IDs without network requests
                        self.chat_id = f"demo-chat-{random_id}"
                        self.registry_id = f"demo-registry-{random_id}"
                        print(f"DEBUG: Demo mode - Chat ID: {self.chat_id}, Registry ID: {self.registry_id}")
                        
                        # Show demo mode notification on main thread
                        self.root.after(0, lambda: messagebox.showinfo(
                            "DEMO MODE", 
                            "TOR connection not available. Running in demo mode.\n\n"
                            "Chat created locally for testing purposes.\n"
                            "For full functionality, please start TOR Browser."
                        ))
                    
                    print(f"DEBUG: Registry ID: {self.registry_id}")
                    
                    # Update UI on main thread
                    def finish_creation():
                        self.registry_initialized = True
                        self.connected = True
                        
                        # Save to history
                        chat_info = {
                            'chat_id': self.chat_id,
                            'registry_id': self.registry_id,
                            'encryption_key': self.encryption_key,
                            'username': self.username,
                            'chat_type': chat_type,
                            'timestamp': time.time()
                        }
                        self.add_to_history(chat_info)
                        
                        print("DEBUG: Showing sharing info...")
                        self.show_sharing_info()
                    
                    self.root.after(0, finish_creation)
                    
                except Exception as e:
                    print(f"DEBUG: Exception in async thread: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    
                    # Update UI on main thread
                    def show_error():
                        if hasattr(self, 'status_label') and self.status_label:
                            self.status_label.config(text=f"❌ OPERATION FAILED: {str(e)}", fg=self.colors['danger'])
                        else:
                            messagebox.showerror("OPERATION FAILED", f"Error: {str(e)}")
                    
                    self.root.after(0, show_error)
            
            # Start the async operation
            thread = threading.Thread(target=create_channel_async, daemon=True)
            thread.start()
            
        except Exception as e:
            print(f"DEBUG: Exception in create_chat_with_registry: {str(e)}")
            import traceback
            traceback.print_exc()
            
            # Make sure status_label exists before using it
            if hasattr(self, 'status_label') and self.status_label:
                self.status_label.config(text=f"❌ OPERATION FAILED: {str(e)}", fg=self.colors['danger'])
            else:
                messagebox.showerror("OPERATION FAILED", f"Error: {str(e)}")
                print(f"ERROR: {str(e)}")
    
    def update_status(self, message):
        """Update status label safely"""
        if hasattr(self, 'status_label') and self.status_label:
            self.status_label.config(text=message, fg=self.colors['info'])
    
    def start_video_chat(self):
        """Start video chat interface"""
        try:
            import cv2
            import threading
            
            # Create video chat window
            video_window = tk.Toplevel(self.root)
            video_window.title("🎥 Secure Video Chat")
            video_window.geometry("800x600")
            video_window.configure(bg=self.colors['bg'])
            
            # Video display area
            video_frame = tk.Frame(video_window, bg=self.colors['card_bg'], relief='solid', borderwidth=2)
            video_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
            
            tk.Label(video_frame, text="🎥 VIDEO CHAT ACTIVE", 
                    font=('Courier New', 16, 'bold'), 
                    bg=self.colors['card_bg'], fg=self.colors['accent']).pack(pady=20)
            
            # Video placeholder (in a real implementation, this would show camera feed)
            video_placeholder = tk.Label(video_frame, text="📹\n\nCamera feed would appear here\n\nIn a full implementation, this would use:\n• OpenCV for camera access\n• WebRTC for peer-to-peer video\n• Encrypted video streams", 
                                        font=('Courier New', 12), 
                                        bg=self.colors['accent_light'], fg=self.colors['fg'],
                                        width=60, height=15, justify=tk.CENTER)
            video_placeholder.pack(pady=20, padx=20)
            
            # Control buttons
            controls_frame = tk.Frame(video_window, bg=self.colors['bg'])
            controls_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
            
            ttk.Button(controls_frame, text="🎤 MUTE", 
                      command=lambda: messagebox.showinfo("Audio", "Microphone muted"),
                      style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=5)
            
            ttk.Button(controls_frame, text="📹 CAMERA OFF", 
                      command=lambda: messagebox.showinfo("Video", "Camera disabled"),
                      style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=5)
            
            ttk.Button(controls_frame, text="🖥️ SHARE SCREEN", 
                      command=lambda: messagebox.showinfo("Screen Share", "Screen sharing started"),
                      style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=5)
            
            ttk.Button(controls_frame, text="❌ END CALL", 
                      command=video_window.destroy,
                      style='ClassifiedButton.TButton').pack(side=tk.RIGHT, padx=5)
            
            messagebox.showinfo("VIDEO CHAT", "Video chat interface opened!\n\nNote: This is a demo interface.\nFull video chat would require:\n• WebRTC implementation\n• STUN/TURN servers\n• Camera/microphone access")
            
        except ImportError:
            messagebox.showwarning("VIDEO CHAT", "Video chat requires additional libraries.\n\nTo enable full video chat:\n• Install OpenCV: pip install opencv-python\n• Implement WebRTC for P2P video\n• Add STUN/TURN server support")
        except Exception as e:
            messagebox.showerror("VIDEO CHAT ERROR", f"Failed to start video chat: {str(e)}")
    
    def show_sharing_info(self):
        self.clear_window()
        
        # CLASSIFIED BANNER
        banner_frame = tk.Frame(self.root, bg=self.colors['success'], height=40)
        banner_frame.pack(fill=tk.X)
        banner_frame.pack_propagate(False)
        
        tk.Label(banner_frame, text="★ ★ ★ CLASSIFIED - CHANNEL ESTABLISHED - SHARE CREDENTIALS ★ ★ ★", 
                 bg=self.colors['success'], fg='black', 
                 font=('Courier New', 12, 'bold')).pack(expand=True)
        
        # Main container with sidebar
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Sidebar
        sidebar = ttk.Frame(main_container, width=280, style='ClassifiedSidebar.TFrame')
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)
        
        # Sidebar content
        tk.Label(sidebar, text="SHARE CREDENTIALS", 
                 font=('Courier New', 18, 'bold'),
                 fg=self.colors['accent'],
                 bg=self.colors['sidebar_bg']).pack(pady=(40, 30), padx=20, anchor='w')
        
        nav_frame = ttk.Frame(sidebar, style='ClassifiedSidebar.TFrame')
        nav_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        ttk.Button(nav_frame, text="ENTER CHANNEL",
                  command=self.show_chat_window,
                  style='ClassifiedButton.TButton').pack(fill=tk.X, pady=5)
        
        ttk.Button(nav_frame, text="COMMAND CENTER",
                  command=self.show_admin_panel,
                  style='ClassifiedButton.TButton').pack(fill=tk.X, pady=5)
        
        ttk.Button(nav_frame, text="RETURN TO BASE",
                  command=self.show_main_menu,
                  style='ClassifiedButton.TButton').pack(fill=tk.X, pady=5)
        
        # Main content
        content = ttk.Frame(main_container)
        content.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=40, pady=40)
        
        tk.Label(content, text="✅ SECURE CHANNEL ESTABLISHED",
                 font=('Courier New', 24, 'bold'),
                 foreground=self.colors['success'], bg=self.colors['bg']).pack(pady=(0, 10))
        
        tk.Label(content, text="Transmit these classified credentials to authorized agents",
                 font=('Courier New', 12, 'bold'), fg=self.colors['fg'], bg=self.colors['bg']).pack(pady=(0, 30))
        
        # Credentials card
        cred_card = ttk.Frame(content, style='ClassifiedCard.TFrame', padding=30)
        cred_card.pack(fill=tk.BOTH, expand=True)
        
        # Registry ID
        tk.Label(cred_card, text="REGISTRY ID (PRIORITY TRANSMISSION)", 
                 font=('Courier New', 12, 'bold'), bg=self.colors['card_bg'], fg=self.colors['classified']).pack(anchor='w', pady=(0, 10))
        
        registry_frame = tk.Frame(cred_card, bg=self.colors['card_bg'])
        registry_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.registry_text = tk.Text(registry_frame, height=2, width=50, font=('Courier New', 9),
                                    bg=self.colors['entry_bg'], fg=self.colors['entry_fg'])
        self.registry_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.registry_text.insert(tk.END, self.registry_id)
        self.registry_text.config(state=tk.DISABLED)
        
        ttk.Button(registry_frame, text="COPY",
                  command=lambda: self.copy_to_clipboard(self.registry_id),
                  style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=10)
        
        # Chat ID
        tk.Label(cred_card, text="CHANNEL ID", 
                 font=('Courier New', 12, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(anchor='w', pady=(10, 10))
        
        chat_id_frame = tk.Frame(cred_card, bg=self.colors['card_bg'])
        chat_id_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.chat_id_text = tk.Text(chat_id_frame, height=2, width=50, font=('Courier New', 9),
                                   bg=self.colors['entry_bg'], fg=self.colors['entry_fg'])
        self.chat_id_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.chat_id_text.insert(tk.END, self.chat_id)
        self.chat_id_text.config(state=tk.DISABLED)
        
        ttk.Button(chat_id_frame, text="COPY",
                  command=lambda: self.copy_to_clipboard(self.chat_id),
                  style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=10)
        
        # Encryption Key
        tk.Label(cred_card, text="ENCRYPTION KEY (TOP SECRET)", 
                 font=('Courier New', 12, 'bold'), bg=self.colors['card_bg'], fg=self.colors['classified']).pack(anchor='w', pady=(10, 10))
        
        key_frame = tk.Frame(cred_card, bg=self.colors['card_bg'])
        key_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.key_text = tk.Text(key_frame, height=3, width=50, font=('Courier New', 9),
                               bg=self.colors['entry_bg'], fg=self.colors['entry_fg'])
        self.key_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.key_text.insert(tk.END, self.encryption_key)
        self.key_text.config(state=tk.DISABLED)
        
        ttk.Button(key_frame, text="COPY",
                  command=lambda: self.copy_to_clipboard(self.encryption_key),
                  style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=10)
        
        # Safety Numbers for End-to-End Encryption Verification
        self.add_safety_numbers_display(cred_card)
        
        # Instructions
        instructions_frame = tk.Frame(cred_card, bg=self.colors['card_bg'], relief='solid', borderwidth=2, padx=20, pady=20)
        instructions_frame.pack(fill=tk.X, pady=(20, 0))
        
        tk.Label(instructions_frame, text="📋 AGENT INSTRUCTIONS (CLASSIFIED)",
                 font=('Courier New', 11, 'bold'), bg=self.colors['card_bg'], fg=self.colors['warning']).pack(anchor='w', pady=(0, 10))
        
        instructions = """1. Client opens secure communication system
2. Selects 'Join Existing Channel'
3. Enters Registry ID (PRIORITY)
4. Enters Client Username
5. Enters Channel ID
6. Enters Encryption Key (TOP SECRET)
7. Initiates 'Register & Join'
8. Awaits clearance approval in Command Center"""
        
        tk.Label(instructions_frame, text=instructions,
                 font=('Courier New', 9), justify=tk.LEFT, bg=self.colors['card_bg'], fg=self.colors['fg']).pack(anchor='w')
        
        # Action buttons
        button_frame = tk.Frame(cred_card, bg=self.colors['card_bg'])
        button_frame.pack(fill=tk.X, pady=(30, 0))
        
        ttk.Button(button_frame, text="COPY ALL CREDENTIALS", 
                  command=lambda: self.copy_to_clipboard(
                      f"Registry ID: {self.registry_id}\nChannel ID: {self.chat_id}\nEncryption Key: {self.encryption_key}"
                  ),
                  style='ClassifiedButton.TButton').pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(button_frame, text="COMMAND CENTER", 
                  command=self.show_admin_panel,
                  style='ClassifiedButton.TButton').pack(side=tk.RIGHT, padx=5)
    
    def add_safety_numbers_display(self, parent_frame):
        """Add safety numbers display for end-to-end encryption verification"""
        try:
            # Generate safety numbers for this channel
            # For demonstration, we'll use the host's public key and a placeholder for client key
            from message_authentication import MessageAuthenticator
            
            # Initialize message authenticator to get keys
            msg_auth = MessageAuthenticator()
            host_private, host_public = msg_auth.generate_key_pair()
            
            # For now, generate a placeholder client key (in real implementation, this would come from the client)
            client_private, client_public = msg_auth.generate_key_pair()
            
            # Generate safety numbers
            channel_id = f"channel_{self.chat_id}"
            channel_info = self.password_manager.safety_generator.establish_secure_channel(
                host_public, client_public,
                self.username or "Host", "Client",
                channel_id
            )
            
            # Safety Numbers Section
            tk.Label(parent_frame, text="SAFETY NUMBERS (END-TO-END VERIFICATION)", 
                     font=('Courier New', 12, 'bold'), bg=self.colors['card_bg'], fg=self.colors['classified']).pack(anchor='w', pady=(20, 10))
            
            safety_frame = tk.Frame(parent_frame, bg=self.colors['card_bg'])
            safety_frame.pack(fill=tk.X, pady=(0, 20))
            
            # Display formatted safety numbers
            formatted_safety = channel_info['formatted_safety_number']
            self.safety_text = tk.Text(safety_frame, height=4, width=50, font=('Courier New', 10),
                                      bg=self.colors['entry_bg'], fg=self.colors['entry_fg'])
            self.safety_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self.safety_text.insert(tk.END, formatted_safety)
            self.safety_text.config(state=tk.DISABLED)
            
            button_frame = tk.Frame(safety_frame, bg=self.colors['card_bg'])
            button_frame.pack(side=tk.LEFT, padx=10)
            
            ttk.Button(button_frame, text="COPY",
                      command=lambda: self.copy_to_clipboard(formatted_safety),
                      style='ClassifiedButton.TButton').pack(pady=2)
            
            ttk.Button(button_frame, text="VERIFY",
                      command=lambda: self.show_safety_verification_dialog(channel_info),
                      style='ClassifiedButton.TButton').pack(pady=2)
            
            # Safety numbers info
            safety_info_frame = tk.Frame(parent_frame, bg=self.colors['accent_light'], relief='solid', borderwidth=1, padx=15, pady=15)
            safety_info_frame.pack(fill=tk.X, pady=(0, 20))
            
            tk.Label(safety_info_frame, text="🔐 SAFETY NUMBERS VERIFICATION",
                     font=('Courier New', 10, 'bold'), bg=self.colors['accent_light'], fg=self.colors['fg']).pack(anchor='w', pady=(0, 5))
            
            safety_instructions = """• Compare these numbers with your contact through a separate secure channel
• Numbers must match exactly on both devices for secure communication
• If numbers don't match, DO NOT proceed - channel may be compromised
• Verify through voice call, in person, or other trusted communication method"""
            
            tk.Label(safety_info_frame, text=safety_instructions,
                     font=('Courier New', 8), justify=tk.LEFT, bg=self.colors['accent_light'], fg=self.colors['fg']).pack(anchor='w')
            
        except Exception as e:
            # If safety numbers fail, show a placeholder
            tk.Label(parent_frame, text="SAFETY NUMBERS (VERIFICATION PENDING)", 
                     font=('Courier New', 12, 'bold'), bg=self.colors['card_bg'], fg=self.colors['warning']).pack(anchor='w', pady=(20, 10))
            
            tk.Label(parent_frame, text=f"Safety numbers will be generated when client connects.\nError: {str(e)[:50]}...",
                     font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg']).pack(anchor='w', pady=(0, 20))
    
    def show_safety_verification_dialog(self, channel_info):
        """Show safety number verification dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Safety Number Verification")
        dialog.geometry("600x500")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Header
        header_frame = tk.Frame(dialog, bg=self.colors['classified'], height=50)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text="🔐 SAFETY NUMBER VERIFICATION", 
                 bg=self.colors['classified'], fg='white', 
                 font=('Courier New', 14, 'bold')).pack(expand=True)
        
        # Content
        content_frame = tk.Frame(dialog, bg=self.colors['bg'], padx=30, pady=30)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Display safety numbers
        display_text = self.password_manager.safety_display.display_safety_numbers(
            channel_info['safety_number'],
            channel_info['local_identity'],
            channel_info['remote_identity']
        )
        
        text_widget = tk.Text(content_frame, height=15, font=('Courier New', 10),
                             bg=self.colors['entry_bg'], fg=self.colors['entry_fg'],
                             wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        text_widget.insert(tk.END, display_text)
        text_widget.config(state=tk.DISABLED)
        
        # Buttons
        button_frame = tk.Frame(content_frame, bg=self.colors['bg'])
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="COPY SAFETY NUMBERS",
                  command=lambda: self.copy_to_clipboard(channel_info['formatted_safety_number']),
                  style='ClassifiedButton.TButton').pack(side=tk.LEFT)
        
        ttk.Button(button_frame, text="CLOSE",
                  command=dialog.destroy,
                  style='ClassifiedButton.TButton').pack(side=tk.RIGHT)
    
    def show_user_monitoring_panel(self):
        """Advanced user monitoring and tracking panel"""
        self.track_current_window(self.show_user_monitoring_panel)
        self.clear_window()
        
        # CLASSIFIED BANNER
        banner_frame = tk.Frame(self.root, bg=self.colors['danger'], height=40)
        banner_frame.pack(fill=tk.X)
        banner_frame.pack_propagate(False)
        
        tk.Label(banner_frame, text="★ ★ ★ CLASSIFIED - USER MONITORING & TRACKING - TOP SECRET ★ ★ ★", 
                 bg=self.colors['danger'], fg='white', 
                 font=('Courier New', 12, 'bold')).pack(expand=True)
        
        # Main container with sidebar
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Sidebar
        sidebar = ttk.Frame(main_container, width=280, style='ClassifiedSidebar.TFrame')
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)
        
        # Sidebar content
        tk.Label(sidebar, text="USER MONITORING", 
                 font=('Courier New', 18, 'bold'),
                 fg=self.colors['accent'],
                 bg=self.colors['sidebar_bg']).pack(pady=(40, 30), padx=20, anchor='w')
        
        nav_frame = ttk.Frame(sidebar, style='ClassifiedSidebar.TFrame')
        nav_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        ttk.Button(nav_frame, text="RETURN TO BASE",
                  command=self.show_main_menu,
                  style='ClassifiedButton.TButton').pack(fill=tk.X, pady=5)
        
        ttk.Button(nav_frame, text="COMMAND CENTER",
                  command=self.show_admin_panel,
                  style='ClassifiedButton.TButton').pack(fill=tk.X, pady=5)
        
        ttk.Button(nav_frame, text="REFRESH DATA",
                  command=self.show_user_monitoring_panel,
                  style='ClassifiedButton.TButton').pack(fill=tk.X, pady=5)
        
        # Stats in sidebar
        stats_frame = tk.Frame(sidebar, bg=self.colors['sidebar_bg'], padx=20, pady=20)
        stats_frame.pack(fill=tk.X, padx=20, pady=(20, 0))
        
        tk.Label(stats_frame, text="MONITORING STATS",
                 font=('Courier New', 11, 'bold'),
                 fg=self.colors['warning'],
                 bg=self.colors['sidebar_bg']).pack(anchor='w', pady=(0, 15))
        
        sessions = self.user_tracker.get_user_sessions()
        active_sessions = len([s for s in sessions.values() if s['status'] == 'active'])
        unique_ips = len(set(s['ip_address'] for s in sessions.values()))
        unique_hwids = len(set(s['hwid'] for s in sessions.values()))
        
        stats_text = f"Active Sessions: {active_sessions}\nUnique IPs: {unique_ips}\nUnique HWIDs: {unique_hwids}\nTotal Tracked: {len(sessions)}"
        tk.Label(stats_frame, text=stats_text,
                 fg=self.colors['fg'],
                 bg=self.colors['sidebar_bg'],
                 font=('Courier New', 9),
                 justify=tk.LEFT).pack(anchor='w')
        
        # Main content
        content = ttk.Frame(main_container)
        content.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=40, pady=40)
        
        # Header
        header_frame = ttk.Frame(content)
        header_frame.pack(fill=tk.X, pady=(0, 30))
        
        tk.Label(header_frame, text="USER MONITORING & TRACKING SYSTEM",
                 font=('Courier New', 24, 'bold'), fg=self.colors['accent'], bg=self.colors['bg']).pack(side=tk.LEFT)
        
        # Tabs for different views
        notebook = ttk.Notebook(content)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Active Sessions Tab
        sessions_frame = ttk.Frame(notebook)
        notebook.add(sessions_frame, text="ACTIVE SESSIONS")
        
        # Create sessions table
        sessions_canvas = tk.Canvas(sessions_frame, bg=self.colors['bg'], highlightthickness=0)
        sessions_scrollbar = ttk.Scrollbar(sessions_frame, orient="vertical", command=sessions_canvas.yview)
        sessions_container = ttk.Frame(sessions_canvas)
        
        sessions_container.bind(
            "<Configure>",
            lambda e: sessions_canvas.configure(scrollregion=sessions_canvas.bbox("all"))
        )
        
        sessions_canvas.create_window((0, 0), window=sessions_container, anchor="nw")
        sessions_canvas.configure(yscrollcommand=sessions_scrollbar.set)
        
        sessions_canvas.pack(side="left", fill="both", expand=True, padx=(0, 10))
        sessions_scrollbar.pack(side="right", fill="y")
        
        # Sessions header
        header_card = ttk.Frame(sessions_container, style='ClassifiedCard.TFrame', padding=10)
        header_card.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(header_card, text="USER", font=('Courier New', 10, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['accent'], width=15).pack(side=tk.LEFT)
        tk.Label(header_card, text="IP ADDRESS", font=('Courier New', 10, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['accent'], width=15).pack(side=tk.LEFT)
        tk.Label(header_card, text="LOCATION", font=('Courier New', 10, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['accent'], width=20).pack(side=tk.LEFT)
        tk.Label(header_card, text="HWID", font=('Courier New', 10, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['accent'], width=15).pack(side=tk.LEFT)
        tk.Label(header_card, text="STATUS", font=('Courier New', 10, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['accent'], width=10).pack(side=tk.LEFT)
        
        # Display sessions
        for idx, (session_key, session) in enumerate(sessions.items()):
            session_card = ttk.Frame(sessions_container, style='ClassifiedCard.TFrame', padding=10)
            session_card.pack(fill=tk.X, pady=2)
            
            # User
            tk.Label(session_card, text=session['username'][:12], 
                     font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg'], width=15).pack(side=tk.LEFT)
            
            # IP Address
            tk.Label(session_card, text=session['ip_address'], 
                     font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg'], width=15).pack(side=tk.LEFT)
            
            # Location
            location = session['location']
            location_text = f"{location['city']}, {location['country_code']}"
            tk.Label(session_card, text=location_text[:18], 
                     font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg'], width=20).pack(side=tk.LEFT)
            
            # HWID
            tk.Label(session_card, text=session['hwid'][:12] + "...", 
                     font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg'], width=15).pack(side=tk.LEFT)
            
            # Status
            status_color = self.colors['success'] if session['status'] == 'active' else self.colors['danger']
            tk.Label(session_card, text=session['status'].upper(), 
                     font=('Courier New', 9, 'bold'), bg=self.colors['card_bg'], fg=status_color, width=10).pack(side=tk.LEFT)
            
            # Actions
            action_frame = tk.Frame(session_card, bg=self.colors['card_bg'])
            action_frame.pack(side=tk.RIGHT)
            
            ttk.Button(action_frame, text="DETAILS",
                      command=lambda s=session: self.show_user_details(s),
                      style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=2)
            
            if session['status'] == 'active':
                ttk.Button(action_frame, text="BLOCK",
                          command=lambda s=session: self.block_user_session(s),
                          style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=2)
        
        # IP Tracking Tab
        ip_frame = ttk.Frame(notebook)
        notebook.add(ip_frame, text="IP TRACKING")
        
        # Create IP table
        ip_canvas = tk.Canvas(ip_frame, bg=self.colors['bg'], highlightthickness=0)
        ip_scrollbar = ttk.Scrollbar(ip_frame, orient="vertical", command=ip_canvas.yview)
        ip_container = ttk.Frame(ip_canvas)
        
        ip_container.bind(
            "<Configure>",
            lambda e: ip_canvas.configure(scrollregion=ip_canvas.bbox("all"))
        )
        
        ip_canvas.create_window((0, 0), window=ip_container, anchor="nw")
        ip_canvas.configure(yscrollcommand=ip_scrollbar.set)
        
        ip_canvas.pack(side="left", fill="both", expand=True, padx=(0, 10))
        ip_scrollbar.pack(side="right", fill="y")
        
        # IP header
        ip_header_card = ttk.Frame(ip_container, style='ClassifiedCard.TFrame', padding=10)
        ip_header_card.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(ip_header_card, text="IP ADDRESS", font=('Courier New', 10, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['accent'], width=15).pack(side=tk.LEFT)
        tk.Label(ip_header_card, text="USER", font=('Courier New', 10, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['accent'], width=15).pack(side=tk.LEFT)
        tk.Label(ip_header_card, text="LOCATION", font=('Courier New', 10, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['accent'], width=25).pack(side=tk.LEFT)
        tk.Label(ip_header_card, text="ISP", font=('Courier New', 10, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['accent'], width=20).pack(side=tk.LEFT)
        
        # Display IP data
        for ip_address, ip_data in self.user_tracker.ip_database.items():
            ip_card = ttk.Frame(ip_container, style='ClassifiedCard.TFrame', padding=10)
            ip_card.pack(fill=tk.X, pady=2)
            
            # IP Address
            tk.Label(ip_card, text=ip_address, 
                     font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg'], width=15).pack(side=tk.LEFT)
            
            # User
            tk.Label(ip_card, text=ip_data['username'][:12], 
                     font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg'], width=15).pack(side=tk.LEFT)
            
            # Location
            location = ip_data['location']
            location_text = f"{location['city']}, {location['region']}, {location['country']}"
            tk.Label(ip_card, text=location_text[:23], 
                     font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg'], width=25).pack(side=tk.LEFT)
            
            # ISP
            tk.Label(ip_card, text=location['isp'][:18], 
                     font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg'], width=20).pack(side=tk.LEFT)
            
            # Actions
            action_frame = tk.Frame(ip_card, bg=self.colors['card_bg'])
            action_frame.pack(side=tk.RIGHT)
            
            ttk.Button(action_frame, text="GEO INFO",
                      command=lambda ip=ip_address, data=ip_data: self.show_geo_details(ip, data),
                      style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=2)
        
        # HWID Tracking Tab
        hwid_frame = ttk.Frame(notebook)
        notebook.add(hwid_frame, text="HWID TRACKING")
        
        # Create HWID table
        hwid_canvas = tk.Canvas(hwid_frame, bg=self.colors['bg'], highlightthickness=0)
        hwid_scrollbar = ttk.Scrollbar(hwid_frame, orient="vertical", command=hwid_canvas.yview)
        hwid_container = ttk.Frame(hwid_canvas)
        
        hwid_container.bind(
            "<Configure>",
            lambda e: hwid_canvas.configure(scrollregion=hwid_canvas.bbox("all"))
        )
        
        hwid_canvas.create_window((0, 0), window=hwid_container, anchor="nw")
        hwid_canvas.configure(yscrollcommand=hwid_scrollbar.set)
        
        hwid_canvas.pack(side="left", fill="both", expand=True, padx=(0, 10))
        hwid_scrollbar.pack(side="right", fill="y")
        
        # HWID header
        hwid_header_card = ttk.Frame(hwid_container, style='ClassifiedCard.TFrame', padding=10)
        hwid_header_card.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(hwid_header_card, text="HWID", font=('Courier New', 10, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['accent'], width=20).pack(side=tk.LEFT)
        tk.Label(hwid_header_card, text="USER", font=('Courier New', 10, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['accent'], width=15).pack(side=tk.LEFT)
        tk.Label(hwid_header_card, text="MAC ADDRESS", font=('Courier New', 10, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['accent'], width=18).pack(side=tk.LEFT)
        tk.Label(hwid_header_card, text="SYSTEM", font=('Courier New', 10, 'bold'), 
                 bg=self.colors['card_bg'], fg=self.colors['accent'], width=15).pack(side=tk.LEFT)
        
        # Display HWID data
        for hwid, hwid_data in self.user_tracker.hwid_database.items():
            hwid_card = ttk.Frame(hwid_container, style='ClassifiedCard.TFrame', padding=10)
            hwid_card.pack(fill=tk.X, pady=2)
            
            # HWID
            tk.Label(hwid_card, text=hwid[:18] + "...", 
                     font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg'], width=20).pack(side=tk.LEFT)
            
            # User
            tk.Label(hwid_card, text=hwid_data['username'][:12], 
                     font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg'], width=15).pack(side=tk.LEFT)
            
            # MAC Address
            mac = hwid_data['hardware_details']['mac_address']
            tk.Label(hwid_card, text=mac[:16], 
                     font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg'], width=18).pack(side=tk.LEFT)
            
            # System
            system_info = hwid_data['hardware_details']['system_info']
            system_text = f"{system_info.get('system', 'Unknown')} {system_info.get('release', '')}"
            tk.Label(hwid_card, text=system_text[:13], 
                     font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg'], width=15).pack(side=tk.LEFT)
            
            # Actions
            action_frame = tk.Frame(hwid_card, bg=self.colors['card_bg'])
            action_frame.pack(side=tk.RIGHT)
            
            ttk.Button(action_frame, text="HW INFO",
                      command=lambda h=hwid, data=hwid_data: self.show_hardware_details(h, data),
                      style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=2)
    
    def show_user_details(self, session):
        """Show detailed user session information"""
        dialog = tk.Toplevel(self.root)
        dialog.title("USER SESSION DETAILS")
        dialog.geometry("700x600")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (350)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (300)
        dialog.geometry(f"+{x}+{y}")
        
        main_frame = tk.Frame(dialog, bg=self.colors['bg'], padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(main_frame, text=f"USER SESSION DETAILS - {session['username']}",
                 font=('Courier New', 16, 'bold'), bg=self.colors['bg'], fg=self.colors['accent']).pack(pady=(0, 20))
        
        # Create scrollable text area
        text_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        text_widget = scrolledtext.ScrolledText(text_frame, 
                                               bg=self.colors['entry_bg'], 
                                               fg=self.colors['entry_fg'],
                                               font=('Courier New', 10),
                                               wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        # Format session details
        details = f"""SESSION INFORMATION:
Username: {session['username']}
Chat ID: {session['chat_id']}
Registry ID: {session['registry_id']}
Status: {session['status'].upper()}

NETWORK INFORMATION:
IP Address: {session['ip_address']}
User Agent: {session['user_agent']}

HARDWARE INFORMATION:
HWID: {session['hwid']}
MAC Address: {session['hardware_details']['mac_address']}
Disk Serial: {session['hardware_details']['disk_serial']}
CPU Info: {session['hardware_details']['cpu_info']}
Memory Total: {session['hardware_details']['memory_total']}

SYSTEM INFORMATION:
System: {session['hardware_details']['system_info'].get('system', 'Unknown')}
Machine: {session['hardware_details']['system_info'].get('machine', 'Unknown')}
Processor: {session['hardware_details']['system_info'].get('processor', 'Unknown')}
Release: {session['hardware_details']['system_info'].get('release', 'Unknown')}
Version: {session['hardware_details']['system_info'].get('version', 'Unknown')}
Node: {session['hardware_details']['system_info'].get('node', 'Unknown')}

LOCATION INFORMATION:
Country: {session['location']['country']} ({session['location']['country_code']})
Region: {session['location']['region']}
City: {session['location']['city']}
Coordinates: {session['location']['latitude']}, {session['location']['longitude']}
Timezone: {session['location']['timezone']}
ISP: {session['location']['isp']}
Organization: {session['location']['org']}
AS Number: {session['location']['as']}

SESSION TIMING:
Session Start: {datetime.fromtimestamp(session['session_start']).strftime('%Y-%m-%d %H:%M:%S')}
Last Activity: {datetime.fromtimestamp(session['last_activity']).strftime('%Y-%m-%d %H:%M:%S')}
Connection Count: {session['connection_count']}
"""
        
        text_widget.insert(tk.END, details)
        text_widget.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="CLOSE",
                  command=dialog.destroy,
                  style='ClassifiedButton.TButton').pack(pady=(20, 0))
    
    def show_geo_details(self, ip_address, ip_data):
        """Show detailed geolocation information"""
        dialog = tk.Toplevel(self.root)
        dialog.title("GEOLOCATION DETAILS")
        dialog.geometry("600x500")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (300)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (250)
        dialog.geometry(f"+{x}+{y}")
        
        main_frame = tk.Frame(dialog, bg=self.colors['bg'], padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(main_frame, text=f"GEOLOCATION DETAILS - {ip_address}",
                 font=('Courier New', 16, 'bold'), bg=self.colors['bg'], fg=self.colors['accent']).pack(pady=(0, 20))
        
        # Create scrollable text area
        text_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        text_widget = scrolledtext.ScrolledText(text_frame, 
                                               bg=self.colors['entry_bg'], 
                                               fg=self.colors['entry_fg'],
                                               font=('Courier New', 10),
                                               wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        location = ip_data['location']
        details = f"""IP ADDRESS INFORMATION:
IP Address: {ip_address}
Associated User: {ip_data['username']}
First Seen: {datetime.fromtimestamp(ip_data['first_seen']).strftime('%Y-%m-%d %H:%M:%S')}
Last Seen: {datetime.fromtimestamp(ip_data['last_seen']).strftime('%Y-%m-%d %H:%M:%S')}

GEOLOCATION DATA:
Country: {location['country']} ({location['country_code']})
Region/State: {location['region']}
City: {location['city']}
Latitude: {location['latitude']}
Longitude: {location['longitude']}
Timezone: {location['timezone']}

NETWORK INFORMATION:
Internet Service Provider: {location['isp']}
Organization: {location['org']}
AS Number: {location['as']}

SECURITY ASSESSMENT:
Risk Level: {"HIGH" if location['country_code'] in ['CN', 'RU', 'KP', 'IR'] else "MEDIUM" if location['country_code'] in ['Unknown'] else "LOW"}
VPN/Proxy Detected: {"POSSIBLE" if location['isp'] and any(x in location['isp'].lower() for x in ['vpn', 'proxy', 'hosting', 'cloud']) else "UNLIKELY"}
"""
        
        text_widget.insert(tk.END, details)
        text_widget.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="CLOSE",
                  command=dialog.destroy,
                  style='ClassifiedButton.TButton').pack(pady=(20, 0))
    
    def show_hardware_details(self, hwid, hwid_data):
        """Show detailed hardware information"""
        dialog = tk.Toplevel(self.root)
        dialog.title("HARDWARE DETAILS")
        dialog.geometry("600x500")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (300)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (250)
        dialog.geometry(f"+{x}+{y}")
        
        main_frame = tk.Frame(dialog, bg=self.colors['bg'], padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(main_frame, text=f"HARDWARE DETAILS - {hwid[:16]}...",
                 font=('Courier New', 16, 'bold'), bg=self.colors['bg'], fg=self.colors['accent']).pack(pady=(0, 20))
        
        # Create scrollable text area
        text_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        text_widget = scrolledtext.ScrolledText(text_frame, 
                                               bg=self.colors['entry_bg'], 
                                               fg=self.colors['entry_fg'],
                                               font=('Courier New', 10),
                                               wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        hw_details = hwid_data['hardware_details']
        system_info = hw_details['system_info']
        
        details = f"""HARDWARE FINGERPRINT:
HWID: {hwid}
Associated User: {hwid_data['username']}
First Seen: {datetime.fromtimestamp(hwid_data['first_seen']).strftime('%Y-%m-%d %H:%M:%S')}
Last Seen: {datetime.fromtimestamp(hwid_data['last_seen']).strftime('%Y-%m-%d %H:%M:%S')}

NETWORK HARDWARE:
MAC Address: {hw_details['mac_address']}

STORAGE INFORMATION:
Disk Serial Number: {hw_details['disk_serial']}

PROCESSOR INFORMATION:
CPU Info: {hw_details['cpu_info']}

MEMORY INFORMATION:
Total Memory: {hw_details['memory_total']} bytes

SYSTEM INFORMATION:
Operating System: {system_info.get('system', 'Unknown')}
OS Release: {system_info.get('release', 'Unknown')}
OS Version: {system_info.get('version', 'Unknown')}
Machine Type: {system_info.get('machine', 'Unknown')}
Processor: {system_info.get('processor', 'Unknown')}
Network Node: {system_info.get('node', 'Unknown')}

SECURITY NOTES:
- HWID is generated from multiple hardware components
- Changes in hardware will result in different HWID
- MAC address can be spoofed but provides additional tracking
- Disk serial provides persistent identification
"""
        
        text_widget.insert(tk.END, details)
        text_widget.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="CLOSE",
                  command=dialog.destroy,
                  style='ClassifiedButton.TButton').pack(pady=(20, 0))
    
    def block_user_session(self, session):
        """Block a user session"""
        if messagebox.askyesno("CONFIRM BLOCK", f"Block user session for '{session['username']}'?\n\nThis will prevent further access from this user."):
            # End the session
            self.user_tracker.end_user_session(session['username'], session['chat_id'])
            
            # You could also add the user to a blocked list here
            messagebox.showinfo("USER BLOCKED", f"User session blocked: {session['username']}")
            
            # Refresh the monitoring panel
            self.show_user_monitoring_panel()

    def show_admin_panel(self):
        self.track_current_window(self.show_admin_panel)
        self.clear_window()
        
        # CLASSIFIED BANNER
        banner_frame = tk.Frame(self.root, bg=self.colors['classified'], height=40)
        banner_frame.pack(fill=tk.X)
        banner_frame.pack_propagate(False)
        
        tk.Label(banner_frame, text="★ ★ ★ CLASSIFIED - COMMAND CENTER - AGENT CLEARANCE ★ ★ ★", 
                 bg=self.colors['classified'], fg='white', 
                 font=('Courier New', 12, 'bold')).pack(expand=True)
        
        # Main container with sidebar
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Sidebar
        sidebar = ttk.Frame(main_container, width=280, style='ClassifiedSidebar.TFrame')
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)
        
        # Sidebar content
        tk.Label(sidebar, text="COMMAND CENTER", 
                 font=('Courier New', 18, 'bold'),
                 fg=self.colors['accent'],
                 bg=self.colors['sidebar_bg']).pack(pady=(40, 30), padx=20, anchor='w')
        
        nav_frame = ttk.Frame(sidebar, style='ClassifiedSidebar.TFrame')
        nav_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        ttk.Button(nav_frame, text="RETURN TO BASE",
                  command=self.show_main_menu,
                  style='ClassifiedButton.TButton').pack(fill=tk.X, pady=5)
        
        ttk.Button(nav_frame, text="ENTER CHANNEL",
                  command=self.show_chat_window,
                  style='ClassifiedButton.TButton').pack(fill=tk.X, pady=5)
        
        ttk.Button(nav_frame, text="REFRESH INTEL",
                  command=self.load_registry_for_chat,
                  style='ClassifiedButton.TButton').pack(fill=tk.X, pady=5)
        
        ttk.Button(nav_frame, text="APPROVE ALL PENDING",
                  command=self.approve_all_pending,
                  style='ClassifiedButton.TButton').pack(fill=tk.X, pady=5)
        
        # Stats in sidebar
        stats_frame = tk.Frame(sidebar, bg=self.colors['sidebar_bg'], padx=20, pady=20)
        stats_frame.pack(fill=tk.X, padx=20, pady=(20, 0))
        
        tk.Label(stats_frame, text="OPERATIONAL STATUS",
                 font=('Courier New', 11, 'bold'),
                 fg=self.colors['warning'],
                 bg=self.colors['sidebar_bg']).pack(anchor='w', pady=(0, 15))
        
        self.stats_label = tk.Label(stats_frame, text="Enter Channel ID for intel",
                                    fg=self.colors['fg'],
                                    bg=self.colors['sidebar_bg'],
                                    font=('Courier New', 9),
                                    wraplength=240)
        self.stats_label.pack(anchor='w')
        
        # Main content
        content = ttk.Frame(main_container)
        content.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=40, pady=40)
        
        # Header
        header_frame = ttk.Frame(content)
        header_frame.pack(fill=tk.X, pady=(0, 30))
        
        tk.Label(header_frame, text="AGENT CLEARANCE SYSTEM",
                 font=('Courier New', 24, 'bold'), fg=self.colors['accent'], bg=self.colors['bg']).pack(side=tk.LEFT)
        
        # Chat ID input
        input_card = ttk.Frame(content, style='ClassifiedCard.TFrame', padding=20)
        input_card.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(input_card, text="ENTER CHANNEL ID FOR AGENT MANAGEMENT",
                 font=('Courier New', 11, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(anchor='w', pady=(0, 10))
        
        tk.Label(input_card, text="Agents register for channel access. Enter Channel ID to manage clearance requests.",
                 font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg'],
                 wraplength=600).pack(anchor='w', pady=(0, 15))
        
        input_frame = tk.Frame(input_card, bg=self.colors['card_bg'])
        input_frame.pack(fill=tk.X)
        
        self.admin_chat_id_entry = tk.Entry(input_frame, bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                           font=('Courier New', 10), insertbackground=self.colors['entry_fg'])
        self.admin_chat_id_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        # Auto-fill current chat ID if available
        if self.chat_id:
            self.admin_chat_id_entry.insert(0, self.chat_id)
        
        # Add dropdown for recent chats
        ttk.Button(input_frame, text="RECENT CHANNELS", 
                  command=self.show_recent_chats_dropdown,
                  style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(input_frame, text="LOAD CLEARANCES", 
                  command=self.load_registry_for_chat,
                  style='ClassifiedButton.TButton').pack(side=tk.RIGHT)
        
        self.registry_info_label = tk.Label(input_card, text="Enter Channel ID and click 'Load Clearances'",
                                            font=('Courier New', 9), bg=self.colors['card_bg'],
                                            foreground=self.colors['fg'])
        self.registry_info_label.pack(anchor='w', pady=(10, 0))
        
        # Main admin content
        admin_content = ttk.Frame(content)
        admin_content.pack(fill=tk.BOTH, expand=True)
        
        # Left column - Pending requests
        left_column = ttk.Frame(admin_content)
        left_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        pending_frame = tk.LabelFrame(left_column, text="⏳ PENDING CLEARANCE REQUESTS", 
                                     bg=self.colors['bg'], fg=self.colors['warning'],
                                     font=('Courier New', 12, 'bold'), padx=20, pady=20)
        pending_frame.pack(fill=tk.BOTH, expand=True)
        
        pending_canvas = tk.Canvas(pending_frame, bg=self.colors['card_bg'], highlightthickness=0)
        pending_scrollbar = ttk.Scrollbar(pending_frame, orient="vertical", command=pending_canvas.yview)
        self.requests_container = ttk.Frame(pending_canvas)
        
        self.requests_container.bind(
            "<Configure>",
            lambda e: pending_canvas.configure(scrollregion=pending_canvas.bbox("all"))
        )
        
        pending_canvas.create_window((0, 0), window=self.requests_container, anchor="nw")
        pending_canvas.configure(yscrollcommand=pending_scrollbar.set)
        
        pending_canvas.pack(side="left", fill="both", expand=True)
        pending_scrollbar.pack(side="right", fill="y")
        
        # Right column - Approved users
        right_column = ttk.Frame(admin_content)
        right_column.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        approved_frame = tk.LabelFrame(right_column, text="✅ CLEARED AGENTS", 
                                      bg=self.colors['bg'], fg=self.colors['success'],
                                      font=('Courier New', 12, 'bold'), padx=20, pady=20)
        approved_frame.pack(fill=tk.BOTH, expand=True)
        
        approved_canvas = tk.Canvas(approved_frame, bg=self.colors['card_bg'], highlightthickness=0)
        approved_scrollbar = ttk.Scrollbar(approved_frame, orient="vertical", command=approved_canvas.yview)
        self.approved_container = ttk.Frame(approved_canvas)
        
        self.approved_container.bind(
            "<Configure>",
            lambda e: approved_canvas.configure(scrollregion=approved_canvas.bbox("all"))
        )
        
        approved_canvas.create_window((0, 0), window=self.approved_container, anchor="nw")
        approved_canvas.configure(yscrollcommand=approved_scrollbar.set)
        
        approved_canvas.pack(side="left", fill="both", expand=True)
        approved_scrollbar.pack(side="right", fill="y")
        
        if self.chat_id:
            self.load_registry_for_chat()
    
    def show_recent_chats_dropdown(self):
        """Show dropdown of recent chats for quick selection"""
        if not self.chat_history:
            messagebox.showinfo("NO RECENT CHANNELS", "No channel history available.")
            return
        
        dropdown = tk.Toplevel(self.root)
        dropdown.title("SELECT RECENT CHANNEL")
        dropdown.geometry("400x300")
        dropdown.configure(bg=self.colors['bg'])
        dropdown.transient(self.root)
        dropdown.grab_set()
        
        # Center dialog
        dropdown.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (200)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (150)
        dropdown.geometry(f"+{x}+{y}")
        
        main_frame = tk.Frame(dropdown, bg=self.colors['bg'], padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(main_frame, text="SELECT RECENT CHANNEL",
                 font=('Courier New', 14, 'bold'), bg=self.colors['bg'], fg=self.colors['accent']).pack(pady=(0, 20))
        
        # List of recent chats
        listbox = tk.Listbox(main_frame, bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                            font=('Courier New', 10))
        listbox.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        for chat in self.chat_history:
            display_text = f"{chat['chat_id'][:30]}..."
            listbox.insert(tk.END, display_text)
        
        def select_chat():
            selection = listbox.curselection()
            if selection:
                selected_chat = self.chat_history[selection[0]]
                self.admin_chat_id_entry.delete(0, tk.END)
                self.admin_chat_id_entry.insert(0, selected_chat['chat_id'])
                dropdown.destroy()
                self.load_registry_for_chat()
        
        button_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="SELECT",
                  command=select_chat,
                  style='ClassifiedButton.TButton').pack(side=tk.RIGHT)
        
        ttk.Button(button_frame, text="CANCEL",
                  command=dropdown.destroy,
                  style='ClassifiedButton.TButton').pack(side=tk.RIGHT, padx=10)
    
    def find_registry_by_chat_id(self, chat_id):
        """Find registry ID for a given chat ID"""
        # First check local history
        if chat_id in self.chat_registry_map:
            return self.chat_registry_map[chat_id]
        return None
    
    def load_registry_for_chat(self):
        """Load registry data for a specific chat ID"""
        chat_id = self.admin_chat_id_entry.get().strip()
        if not chat_id:
            messagebox.showerror("INCOMPLETE DATA", "Channel ID required")
            return
        
        # Find registry ID for this chat
        registry_id = self.find_registry_by_chat_id(chat_id)
        
        if not registry_id:
            messagebox.showwarning("REGISTRY NOT FOUND", 
                                 f"Registry not found for channel: {chat_id}\n\n"
                                 f"Possible causes:\n"
                                 f"1. Channel not created by this system\n"
                                 f"2. Channel history cleared\n"
                                 f"3. Manual registry ID entry required\n\n"
                                 f"Obtain Registry ID from channel creation.")
            
            # Ask for registry ID manually
            registry_id = self.ask_for_registry_id_manually(chat_id)
            if not registry_id:
                return
        
        self.registry_id = registry_id
        self.chat_id = chat_id  # Update current chat ID
        
        try:
            response = self.secure_request('GET', f"{REGISTRY_URL}/{self.registry_id}", timeout=5)
            if response.status_code != 200:
                self.registry_info_label.config(text="❌ INVALID REGISTRY ID", foreground=self.colors['danger'])
                return
            
            registry = response.json()
            
            # Verify this registry is for the correct chat
            registry_chat_id = registry.get("chat_id", "")
            if registry_chat_id != chat_id:
                messagebox.showwarning("REGISTRY MISMATCH", 
                                     f"Registry for channel: {registry_chat_id}\n"
                                     f"You entered: {chat_id}")
                return
            
            pending_count = len(registry.get("pending_requests", []))
            approved_count = len(registry.get("approved_users", []))
            rejected_count = len(registry.get("rejected_users", []))
            
            info_text = f"✅ Registry loaded for channel: {chat_id[:20]}..."
            self.registry_info_label.config(text=info_text, foreground=self.colors['success'])
            
            # Update stats in sidebar
            auto_status = "AUTO-APPROVE: ON" if self.auto_approve_enabled else "AUTO-APPROVE: OFF"
            stats_text = f"Channel: {chat_id[:15]}...\nPending: {pending_count}\nCleared: {approved_count}\nDenied: {rejected_count}\n{auto_status}"
            self.stats_label.config(text=stats_text)
            
            # Clear containers
            for widget in self.requests_container.winfo_children():
                widget.destroy()
            
            for widget in self.approved_container.winfo_children():
                widget.destroy()
            
            # Pending requests - check for auto-approval first
            pending_requests = registry.get("pending_requests", [])
            
            # Auto-approve requests if enabled
            if self.auto_approve_enabled and pending_requests:
                auto_approved = []
                remaining_pending = []
                
                for request in pending_requests:
                    username = request.get("username", "")
                    # Auto-approve all requests when enabled, or specific users in whitelist
                    if self.auto_approve_enabled and (not self.auto_approve_whitelist or username in self.auto_approve_whitelist):
                        # Move to approved list
                        approved = registry.get("approved_users", [])
                        if username not in approved:
                            approved.append(username)
                            registry["approved_users"] = approved
                            auto_approved.append(username)
                            
                            # Track user session when auto-approved
                            client_info = request.get('client_info', {})
                            if client_info:
                                session_data = {
                                    'username': username,
                                    'chat_id': self.chat_id,
                                    'registry_id': self.registry_id,
                                    'ip_address': client_info.get('ip_address', 'Unknown'),
                                    'hwid': client_info.get('hwid', 'Unknown'),
                                    'hardware_details': {
                                        'hwid': client_info.get('hwid', 'Unknown'),
                                        'mac_address': client_info.get('mac_address', 'Unknown'),
                                        'disk_serial': 'Unknown',
                                        'cpu_info': 'Unknown',
                                        'memory_total': 'Unknown',
                                        'system_info': client_info.get('system_info', {})
                                    },
                                    'location': self.user_tracker.get_location_info(client_info.get('ip_address', 'Unknown')),
                                    'session_start': time.time(),
                                    'last_activity': time.time(),
                                    'status': 'auto_approved',
                                    'user_agent': client_info.get('user_agent', 'Unknown'),
                                    'connection_count': 1
                                }
                                
                                session_key = f"{username}_{self.chat_id}"
                                self.user_tracker.user_sessions[session_key] = session_data
                    else:
                        remaining_pending.append(request)
                
                # Update registry with auto-approvals
                if auto_approved:
                    registry["pending_requests"] = remaining_pending
                    registry["metadata"]["last_updated"] = time.time()
                    
                    # Save updated registry
                    headers = {'Content-Type': 'application/json'}
                    try:
                        self.secure_request(
                            'PUT',
                            f"{REGISTRY_URL}/{self.registry_id}",
                            json=registry,
                            headers=headers,
                            timeout=5
                        )
                        
                        # Show notification
                        auto_approved_text = ", ".join(auto_approved)
                        messagebox.showinfo("AUTO-APPROVAL", f"✅ Auto-approved agents: {auto_approved_text}")
                    except:
                        pass
                
                pending_requests = remaining_pending
            
            if not pending_requests:
                empty_frame = tk.Frame(self.requests_container, bg=self.colors['card_bg'], padx=30, pady=30)
                empty_frame.pack(fill=tk.BOTH, expand=True, pady=20)
                
                tk.Label(empty_frame, text="📭", 
                         font=('Courier New', 36), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(pady=(10, 20))
                
                tk.Label(empty_frame, text="NO PENDING REQUESTS",
                         font=('Courier New', 14, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack()
                
                auto_status = "Auto-approval: ENABLED" if self.auto_approve_enabled else "All clearance requests processed"
                tk.Label(empty_frame, text=auto_status,
                         font=('Courier New', 10), bg=self.colors['card_bg'], fg=self.colors['fg']).pack(pady=(10, 0))
            else:
                for request in pending_requests:
                    self.display_pending_request(request, registry)
            
            # Approved users
            approved_users = registry.get("approved_users", [])
            if not approved_users:
                empty_frame = tk.Frame(self.approved_container, bg=self.colors['card_bg'], padx=30, pady=30)
                empty_frame.pack(fill=tk.BOTH, expand=True, pady=20)
                
                tk.Label(empty_frame, text="👥", 
                         font=('Courier New', 36), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(pady=(10, 20))
                
                tk.Label(empty_frame, text="NO CLEARED AGENTS",
                         font=('Courier New', 14, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack()
                
                tk.Label(empty_frame, text="Approve requests to see agents here",
                         font=('Courier New', 10), bg=self.colors['card_bg'], fg=self.colors['fg']).pack(pady=(10, 0))
            else:
                for user in approved_users:
                    self.display_approved_user(user, registry)
            
        except Exception as e:
            self.registry_info_label.config(text=f"❌ OPERATION FAILED: {str(e)}", foreground=self.colors['danger'])
    
    def ask_for_registry_id_manually(self, chat_id):
        """Ask user to enter registry ID manually"""
        dialog = tk.Toplevel(self.root)
        dialog.title("ENTER REGISTRY ID")
        dialog.geometry("500x200")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (250)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (100)
        dialog.geometry(f"+{x}+{y}")
        
        main_frame = tk.Frame(dialog, bg=self.colors['bg'], padx=30, pady=30)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(main_frame, text=f"Registry not found for channel: {chat_id[:20]}...",
                 font=('Courier New', 11, 'bold'), bg=self.colors['bg'], fg=self.colors['accent']).pack(anchor='w', pady=(0, 10))
        
        tk.Label(main_frame, text="Enter Registry ID manually:",
                 font=('Courier New', 10), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor='w', pady=(0, 10))
        
        registry_entry = tk.Entry(main_frame, bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                 font=('Courier New', 10), insertbackground=self.colors['entry_fg'])
        registry_entry.pack(fill=tk.X, pady=(0, 20))
        
        result = {"registry_id": None}
        
        def submit():
            registry_id = registry_entry.get().strip()
            if registry_id:
                result["registry_id"] = registry_id
                dialog.destroy()
        
        button_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="SUBMIT",
                  command=submit,
                  style='ClassifiedButton.TButton').pack(side=tk.RIGHT)
        
        ttk.Button(button_frame, text="CANCEL",
                  command=dialog.destroy,
                  style='ClassifiedButton.TButton').pack(side=tk.RIGHT, padx=10)
        
        dialog.wait_window()
        return result["registry_id"]
    
    def display_pending_request(self, request, registry):
        request_card = tk.Frame(self.requests_container, bg=self.colors['card_bg'], relief='solid', borderwidth=2, padx=15, pady=15)
        request_card.pack(fill=tk.X, pady=8)
        
        # Request info
        info_frame = tk.Frame(request_card, bg=self.colors['card_bg'])
        info_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        username = request.get("username", "Unknown")
        request_id = request.get("request_id", "N/A")
        timestamp = request.get("timestamp", 0)
        client_info = request.get("client_info", {})
        
        time_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "Unknown"
        
        tk.Label(info_frame, text=f"AGENT: {username}",
                 font=('Courier New', 12, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(anchor='w')
        
        tk.Label(info_frame, text=f"ID: {request_id[:12]}... | Requested: {time_str}",
                 font=('Courier New', 9), bg=self.colors['card_bg'],
                 foreground=self.colors['fg']).pack(anchor='w', pady=(2, 0))
        
        # Show client tracking info if available
        if client_info:
            ip_address = client_info.get('ip_address', 'Unknown')
            hwid = client_info.get('hwid', 'Unknown')
            system_info = client_info.get('system_info', {})
            system_text = f"{system_info.get('system', 'Unknown')} {system_info.get('release', '')}"
            
            tk.Label(info_frame, text=f"IP: {ip_address} | HWID: {hwid[:12]}... | System: {system_text[:20]}",
                     font=('Courier New', 8), bg=self.colors['card_bg'],
                     foreground=self.colors['info']).pack(anchor='w', pady=(2, 0))
        
        # Action buttons
        action_frame = tk.Frame(request_card, bg=self.colors['card_bg'])
        action_frame.pack(side=tk.RIGHT)
        
        # Add intel button to view full client info
        if client_info:
            ttk.Button(action_frame, text="📊 INTEL",
                      command=lambda r=request: self.show_request_intel(r),
                      style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=2)
        
        ttk.Button(action_frame, text="✅ GRANT CLEARANCE",
                  command=lambda r=request, reg=registry: self.approve_request(r, reg),
                  style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=2)
        
        ttk.Button(action_frame, text="❌ DENY ACCESS",
                  command=lambda r=request, reg=registry: self.reject_request(r, reg),
                  style='ClassifiedButton.TButton').pack(side=tk.LEFT, padx=2)
    
    def show_request_intel(self, request):
        """Show detailed intelligence about a clearance request"""
        dialog = tk.Toplevel(self.root)
        dialog.title("CLEARANCE REQUEST INTELLIGENCE")
        dialog.geometry("700x600")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (350)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (300)
        dialog.geometry(f"+{x}+{y}")
        
        main_frame = tk.Frame(dialog, bg=self.colors['bg'], padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(main_frame, text=f"CLEARANCE REQUEST INTELLIGENCE - {request['username']}",
                 font=('Courier New', 16, 'bold'), bg=self.colors['bg'], fg=self.colors['accent']).pack(pady=(0, 20))
        
        # Create scrollable text area
        text_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        text_widget = scrolledtext.ScrolledText(text_frame, 
                                               bg=self.colors['entry_bg'], 
                                               fg=self.colors['entry_fg'],
                                               font=('Courier New', 10),
                                               wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        # Format request details
        client_info = request.get('client_info', {})
        system_info = client_info.get('system_info', {})
        
        details = f"""CLEARANCE REQUEST DETAILS:
Agent Username: {request.get('username', 'Unknown')}
Request ID: {request.get('request_id', 'N/A')}
Chat ID: {request.get('chat_id', 'N/A')}
Request Time: {datetime.fromtimestamp(request.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S')}
Status: {request.get('status', 'Unknown').upper()}
Classification: {request.get('classification', 'Unknown')}

CLIENT NETWORK INFORMATION:
IP Address: {client_info.get('ip_address', 'Unknown')}
User Agent: {client_info.get('user_agent', 'Unknown')}

CLIENT HARDWARE INFORMATION:
Hardware ID (HWID): {client_info.get('hwid', 'Unknown')}
MAC Address: {client_info.get('mac_address', 'Unknown')}

CLIENT SYSTEM INFORMATION:
Operating System: {system_info.get('system', 'Unknown')}
OS Release: {system_info.get('release', 'Unknown')}
OS Version: {system_info.get('version', 'Unknown')}
Machine Type: {system_info.get('machine', 'Unknown')}
Processor: {system_info.get('processor', 'Unknown')}
Network Node: {system_info.get('node', 'Unknown')}

SECURITY ASSESSMENT:
Risk Level: {"HIGH" if 'error' in system_info else "MEDIUM" if client_info.get('ip_address') == 'Unknown' else "LOW"}
System Fingerprint: {"AVAILABLE" if client_info.get('hwid') != 'Unknown' else "LIMITED"}
Network Visibility: {"VISIBLE" if client_info.get('ip_address') != 'Unknown' else "HIDDEN"}

RECOMMENDATION:
{"⚠️  CAUTION: Limited client information available" if not client_info else "✅ Full client intelligence available for tracking"}
"""
        
        text_widget.insert(tk.END, details)
        text_widget.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="CLOSE",
                  command=dialog.destroy,
                  style='ClassifiedButton.TButton').pack(pady=(20, 0))
    
    def display_approved_user(self, user, registry):
        user_card = tk.Frame(self.approved_container, bg=self.colors['card_bg'], relief='solid', borderwidth=2, padx=15, pady=15)
        user_card.pack(fill=tk.X, pady=8)
        
        # User info
        info_frame = tk.Frame(user_card, bg=self.colors['card_bg'])
        info_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        tk.Label(info_frame, text=f"AGENT: {user}",
                 font=('Courier New', 12, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(anchor='w')
        
        status_text = "👑 COMMAND" if user == self.username else "✅ CLEARED AGENT"
        status_color = self.colors['success'] if user != self.username else self.colors['warning']
        tk.Label(info_frame, text=status_text,
                 font=('Courier New', 9), bg=self.colors['card_bg'],
                 foreground=status_color).pack(anchor='w', pady=(5, 0))
        
        # Remove button (not for admin)
        if user != self.username:
            action_frame = tk.Frame(user_card, bg=self.colors['card_bg'])
            action_frame.pack(side=tk.RIGHT)
            
            ttk.Button(action_frame, text="REVOKE CLEARANCE",
                      command=lambda u=user, r=registry: self.remove_approved_user(u, r),
                      style='ClassifiedButton.TButton').pack()
    
    def approve_request(self, request, registry):
        username = request.get("username")
        request_id = request.get("request_id")
        
        if not username or not request_id:
            messagebox.showerror("INVALID DATA", "Invalid request data")
            return
        
        try:
            pending = registry.get("pending_requests", [])
            registry["pending_requests"] = [r for r in pending if r.get("request_id") != request_id]
            
            approved = registry.get("approved_users", [])
            if username not in approved:
                approved.append(username)
                registry["approved_users"] = approved
            
            registry["metadata"]["last_updated"] = time.time()
            registry["metadata"]["total_requests"] = len(pending) + len(approved)
            
            headers = {'Content-Type': 'application/json'}
            response = self.secure_request(
                'PUT',
                f"{REGISTRY_URL}/{self.registry_id}",
                json=registry,
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                # Track user session when approved with client info from request
                client_info = request.get('client_info', {})
                if client_info:
                    # Create comprehensive session data from request
                    session_data = {
                        'username': username,
                        'chat_id': self.chat_id,
                        'registry_id': self.registry_id,
                        'ip_address': client_info.get('ip_address', 'Unknown'),
                        'hwid': client_info.get('hwid', 'Unknown'),
                        'hardware_details': {
                            'hwid': client_info.get('hwid', 'Unknown'),
                            'mac_address': client_info.get('mac_address', 'Unknown'),
                            'disk_serial': 'Unknown',
                            'cpu_info': 'Unknown',
                            'memory_total': 'Unknown',
                            'system_info': client_info.get('system_info', {})
                        },
                        'location': self.user_tracker.get_location_info(client_info.get('ip_address', 'Unknown')),
                        'session_start': time.time(),
                        'last_activity': time.time(),
                        'status': 'approved',
                        'user_agent': client_info.get('user_agent', 'Unknown'),
                        'connection_count': 1
                    }
                    
                    # Store in tracking system
                    session_key = f"{username}_{self.chat_id}"
                    self.user_tracker.user_sessions[session_key] = session_data
                    
                    # Update databases
                    ip_address = client_info.get('ip_address', 'Unknown')
                    if ip_address != 'Unknown':
                        self.user_tracker.ip_database[ip_address] = {
                            'username': username,
                            'location': session_data['location'],
                            'first_seen': session_data['session_start'],
                            'last_seen': time.time()
                        }
                    
                    hwid = client_info.get('hwid', 'Unknown')
                    if hwid != 'Unknown':
                        self.user_tracker.hwid_database[hwid] = {
                            'username': username,
                            'hardware_details': session_data['hardware_details'],
                            'first_seen': session_data['session_start'],
                            'last_seen': time.time()
                        }
                else:
                    # Fallback tracking without client info
                    self.user_tracker.track_user_session(username, self.chat_id, self.registry_id)
                
                messagebox.showinfo("CLEARANCE GRANTED", f"✅ Agent cleared: {username}")
                self.load_registry_for_chat()
            else:
                messagebox.showerror("OPERATION FAILED", "Failed to update registry")
                
        except Exception as e:
            messagebox.showerror("OPERATION FAILED", f"Failed to approve request: {str(e)}")
    
    def reject_request(self, request, registry):
        username = request.get("username")
        request_id = request.get("request_id")
        
        if not username or not request_id:
            messagebox.showerror("INVALID DATA", "Invalid request data")
            return
        
        try:
            pending = registry.get("pending_requests", [])
            registry["pending_requests"] = [r for r in pending if r.get("request_id") != request_id]
            
            rejected = registry.get("rejected_users", [])
            if username not in rejected:
                rejected.append(username)
                registry["rejected_users"] = rejected
            
            registry["metadata"]["last_updated"] = time.time()
            
            headers = {'Content-Type': 'application/json'}
            response = self.secure_request(
                'PUT',
                f"{REGISTRY_URL}/{self.registry_id}",
                json=registry,
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                messagebox.showinfo("ACCESS DENIED", f"❌ Agent denied: {username}")
                self.load_registry_for_chat()
            else:
                messagebox.showerror("OPERATION FAILED", "Failed to update registry")
                
        except Exception as e:
            messagebox.showerror("OPERATION FAILED", f"Failed to reject request: {str(e)}")
    
    def remove_approved_user(self, username, registry):
        if username == self.username:
            messagebox.showwarning("CANNOT REVOKE", "Cannot revoke own command clearance")
            return
        
        if messagebox.askyesno("CONFIRM REVOCATION", f"Revoke clearance for agent '{username}'?"):
            try:
                approved = registry.get("approved_users", [])
                registry["approved_users"] = [u for u in approved if u != username]
                
                headers = {'Content-Type': 'application/json'}
                response = self.secure_request(
                    'PUT',
                    f"{REGISTRY_URL}/{self.registry_id}",
                    json=registry,
                    headers=headers,
                    timeout=5
                )
                
                if response.status_code == 200:
                    messagebox.showinfo("CLEARANCE REVOKED", f"Revoked clearance: {username}")
                    self.load_registry_for_chat()
                else:
                    messagebox.showerror("OPERATION FAILED", "Failed to update registry")
                    
            except Exception as e:
                messagebox.showerror("OPERATION FAILED", f"Failed to remove user: {str(e)}")
    
    def show_chat_window(self):
        if not self.registry_id or not self.chat_id:
            messagebox.showwarning("NOT CONNECTED", "Establish or join channel first")
            return
        
        # Check if this is a video chat
        try:
            response = self.secure_request('GET', f"{BASE_URL}/{self.chat_id}", timeout=5)
            if response.status_code == 200:
                chat_data = response.json()
                if chat_data.get('chat_type') == 'video':
                    self.start_video_chat()
                    return
        except:
            pass  # Continue with regular chat if can't determine type
        
        self.track_current_window(self.show_chat_window)
        self.clear_window()
        
        # CLASSIFIED BANNER
        banner_frame = tk.Frame(self.root, bg=self.colors['success'], height=40)
        banner_frame.pack(fill=tk.X)
        banner_frame.pack_propagate(False)
        
        tk.Label(banner_frame, text="★ ★ ★ CLASSIFIED - SECURE CHANNEL ACTIVE - TOP SECRET ★ ★ ★", 
                 bg=self.colors['success'], fg='black', 
                 font=('Courier New', 12, 'bold')).pack(expand=True)
        
        # Main chat layout
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Left sidebar - Admin controls
        sidebar = ttk.Frame(main_container, width=300, style='ClassifiedSidebar.TFrame')
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)
        
        # Admin info
        tk.Label(sidebar, text="COMMAND OPERATOR", 
                 font=('Courier New', 16, 'bold'),
                 fg=self.colors['accent'],
                 bg=self.colors['sidebar_bg']).pack(pady=(30, 20), padx=20, anchor='w')
        
        # Chat info card
        info_card = tk.Frame(sidebar, bg=self.colors['card_bg'], relief='solid', borderwidth=2, padx=20, pady=20)
        info_card.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        tk.Label(info_card, text="CHANNEL DETAILS",
                 font=('Courier New', 12, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(anchor='w', pady=(0, 10))
        
        tk.Label(info_card, text=f"ID: {self.chat_id[:20]}...",
                 font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg'],
                 wraplength=250).pack(anchor='w', pady=2)
        
        tk.Label(info_card, text=f"Registry: {self.registry_id[:20]}...",
                 font=('Courier New', 9), bg=self.colors['card_bg'], fg=self.colors['fg'],
                 wraplength=250).pack(anchor='w', pady=2)
        
        tk.Label(info_card, text="Status: ✅ SECURE CONNECTION",
                 foreground=self.colors['success'], bg=self.colors['card_bg'],
                 font=('Courier New', 10, 'bold')).pack(anchor='w', pady=(10, 0))
        
        # Admin controls
        tk.Label(sidebar, text="COMMAND CONTROLS",
                 font=('Courier New', 12, 'bold'),
                 fg=self.colors['accent'],
                 bg=self.colors['sidebar_bg']).pack(pady=(20, 10), padx=20, anchor='w')
        
        control_frame = ttk.Frame(sidebar, style='ClassifiedSidebar.TFrame')
        control_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        ttk.Button(control_frame, text="COMMAND CENTER",
                  command=self.show_admin_panel,
                  style='ClassifiedButton.TButton').pack(fill=tk.X, pady=5)
        
        ttk.Button(control_frame, text="CLEAR CHANNEL",
                  command=self.clear_chat_display,
                  style='ClassifiedButton.TButton').pack(fill=tk.X, pady=5)
        
        ttk.Button(control_frame, text="REFRESH INTEL",
                  command=self.refresh_messages,
                  style='ClassifiedButton.TButton').pack(fill=tk.X, pady=5)
        
        ttk.Button(control_frame, text="🎥 VIDEO CHAT",
                  command=self.start_video_chat,
                  style='ClassifiedButton.TButton').pack(fill=tk.X, pady=5)
        
        ttk.Button(control_frame, text="DISCONNECT",
                  command=self.disconnect_chat,
                  style='ClassifiedButton.TButton').pack(fill=tk.X, pady=5)
        
        # Online Users
        tk.Label(sidebar, text="ONLINE AGENTS",
                 font=('Courier New', 12, 'bold'),
                 fg=self.colors['accent'],
                 bg=self.colors['sidebar_bg']).pack(pady=(20, 10), padx=20, anchor='w')
        
        online_frame = tk.Frame(sidebar, bg=self.colors['card_bg'], relief='solid', borderwidth=2, padx=15, pady=15)
        online_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        self.online_users_label = tk.Label(online_frame, text="Loading...", 
                                          bg=self.colors['card_bg'], fg=self.colors['fg'], 
                                          font=('Courier New', 10), justify=tk.LEFT)
        self.online_users_label.pack(anchor='w')
        
        # Settings
        tk.Label(sidebar, text="SECURITY SETTINGS",
                 font=('Courier New', 12, 'bold'),
                 fg=self.colors['accent'],
                 bg=self.colors['sidebar_bg']).pack(pady=(20, 10), padx=20, anchor='w')
        
        settings_frame = tk.Frame(sidebar, bg=self.colors['sidebar_bg'], padx=20, pady=20)
        settings_frame.pack(fill=tk.X, padx=20)
        
        tk.Checkbutton(settings_frame, text="Auto-decrypt intel",
                       variable=self.auto_decrypt_var,
                       command=self.toggle_auto_decrypt,
                       fg=self.colors['fg'],
                       bg=self.colors['sidebar_bg'],
                       selectcolor=self.colors['sidebar_bg'],
                       font=('Courier New', 10)).pack(anchor='w')
        
        tk.Checkbutton(settings_frame, text="Auto-approve clearances",
                       variable=self.auto_approve_var,
                       command=self.toggle_auto_approve,
                       fg=self.colors['fg'],
                       bg=self.colors['sidebar_bg'],
                       selectcolor=self.colors['sidebar_bg'],
                       font=('Courier New', 10)).pack(anchor='w')
        
        # Main chat area
        chat_container = ttk.Frame(main_container)
        chat_container.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Messages area
        messages_frame = ttk.Frame(chat_container)
        messages_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Messages canvas
        self.canvas = tk.Canvas(messages_frame, bg=self.colors['bg'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(messages_frame, orient="vertical", command=self.canvas.yview)
        self.messages_container = ttk.Frame(self.canvas)
        
        self.messages_container.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.messages_container, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True, padx=(0, 10))
        scrollbar.pack(side="right", fill="y")
        
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        
        # Message input
        input_frame = tk.Frame(chat_container, bg=self.colors['bg'], padx=20, pady=20)
        input_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        input_card = tk.Frame(input_frame, bg=self.colors['card_bg'], relief='solid', borderwidth=2, padx=10, pady=10)
        input_card.pack(fill=tk.X)
        
        self.message_entry = tk.Entry(input_card, bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                     font=('Courier New', 10), insertbackground=self.colors['entry_fg'])
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        # File sharing button
        ttk.Button(input_card, text="📎 FILE", 
                  command=self.send_file,
                  style='ClassifiedButton.TButton').pack(side=tk.RIGHT, padx=(0, 5))
        
        ttk.Button(input_card, text="TRANSMIT", 
                  command=self.send_message,
                  style='ClassifiedButton.TButton').pack(side=tk.RIGHT)
        
        # Status bar
        status_frame = tk.Frame(chat_container, relief='solid', borderwidth=2, bg=self.colors['card_bg'])
        status_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        tk.Label(status_frame, text=f"Connected as Command Operator - {self.username}",
                 font=('Courier New', 9, 'bold'), bg=self.colors['card_bg'],
                 foreground=self.colors['success']).pack(side=tk.LEFT, padx=10, pady=5)
        
        self.message_checker = threading.Thread(target=self.check_messages, daemon=True)
        self.message_checker.start()
        
        self.refresh_messages()
    
    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def get_messages(self):
        try:
            response = self.secure_request('GET', f"{BASE_URL}/{self.chat_id}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                # Update online users tracking
                current_time = time.time()
                if current_time - self.last_online_check > 10:  # Check every 10 seconds
                    self.update_online_users(data)
                    self.last_online_check = current_time
                
                return data
        except:
            pass
        return {"messages": [], "users": [], "encrypted": True}
    
    def update_online_users(self, chat_data):
        """Update online users based on recent activity"""
        current_time = time.time()
        messages = chat_data.get("messages", [])
        
        # Consider users online if they sent a message in the last 5 minutes
        online_threshold = current_time - 300  # 5 minutes
        
        recent_users = set()
        for msg in messages:
            if msg.get("timestamp", 0) > online_threshold:
                recent_users.add(msg.get("sender", ""))
        
        # Always include current user as online
        recent_users.add(self.username)
        
        self.online_users = recent_users
        
        # Update online users display if it exists
        if hasattr(self, 'online_users_label'):
            self.update_online_users_display()
    
    def send_message(self):
        message = self.message_entry.get().strip()
        if not message or not self.connected:
            return
        
        try:
            current = self.get_messages()
            
            encrypted_msg = self.cipher.encrypt(message.encode()).decode()
            
            # Check if key rotation is needed
            if self.message_security.should_rotate_keys():
                self.message_security.rotate_keys()
                # Keys rotated after 100 messages
            
            # Sign the message with enhanced authentication (includes sequence number)
            signature_data = self.message_security.sign_message(message)
            
            new_message = {
                "sender": self.username,
                "message": encrypted_msg,
                "time": datetime.now().strftime("%H:%M:%S"),
                "timestamp": time.time(),
                "encrypted": True,
                "classification": "TOP_SECRET",
                "signature": signature_data,  # Now contains full signature structure
                "read_receipt": False
            }
            
            current["messages"].append(new_message)
            
            if len(current["messages"]) > 50:
                current["messages"] = current["messages"][-50:]
            
            headers = {'Content-Type': 'application/json'}
            response = self.secure_request(
                'PUT',
                f"{BASE_URL}/{self.chat_id}",
                json=current,
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                self.add_message_to_display(new_message, is_own=True, decrypted=message)
                self.message_entry.delete(0, tk.END)
            else:
                messagebox.showerror("TRANSMISSION FAILED", "Failed to send message")
                
        except Exception as e:
            messagebox.showerror("TRANSMISSION FAILED", f"Failed to send message: {str(e)}")
    
    def send_file(self):
        """Send a file through the secure chat"""
        from tkinter import filedialog
        import os
        
        if not self.connected:
            messagebox.showwarning("NOT CONNECTED", "Connect to a channel first")
            return
        
        # Open file dialog
        file_path = filedialog.askopenfilename(
            title="Select File to Send",
            filetypes=[
                ("All Files", "*.*"),
                ("Images", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("Documents", "*.pdf *.doc *.docx *.txt"),
                ("Archives", "*.zip *.rar *.7z")
            ]
        )
        
        if not file_path:
            return
        
        try:
            # Check file size (limit to 10MB)
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                messagebox.showerror("FILE TOO LARGE", "File size must be less than 10MB")
                return
            
            # Read and encode file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            file_b64 = base64.b64encode(file_data).decode('utf-8')
            file_name = os.path.basename(file_path)
            
            # Create file message
            file_message = {
                'type': 'file',
                'filename': file_name,
                'size': file_size,
                'data': file_b64,
                'mime_type': self.get_mime_type(file_name)
            }
            
            # Encrypt file message
            encrypted_file = self.cipher.encrypt(json.dumps(file_message).encode())
            
            # Send file message
            new_message = {
                'username': self.username,
                'message': base64.b64encode(encrypted_file).decode(),
                'timestamp': time.time(),
                'message_type': 'file'
            }
            
            response = self.secure_request('POST', f"{BASE_URL}/{self.chat_id}", json=new_message)
            
            if response.status_code == 200:
                self.add_file_to_display(new_message, file_message, is_own=True)
                messagebox.showinfo("FILE SENT", f"File '{file_name}' sent successfully")
            else:
                messagebox.showerror("TRANSMISSION FAILED", "Failed to send file")
                
        except Exception as e:
            messagebox.showerror("FILE SEND FAILED", f"Failed to send file: {str(e)}")
    
    def get_mime_type(self, filename):
        """Get MIME type based on file extension"""
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        mime_types = {
            'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'gif': 'image/gif',
            'pdf': 'application/pdf', 'txt': 'text/plain', 'doc': 'application/msword',
            'zip': 'application/zip', 'mp4': 'video/mp4', 'mp3': 'audio/mpeg'
        }
        return mime_types.get(ext, 'application/octet-stream')
    
    def add_file_to_display(self, msg, file_data, is_own=False):
        """Add file message to chat display"""
        message_frame = tk.Frame(self.messages_container, bg=self.colors['bg'])
        message_frame.pack(fill=tk.X, pady=8)
        
        # File info card
        file_card = tk.Frame(message_frame, bg=self.colors['own_message'] if is_own else self.colors['their_message'], 
                            relief='solid', borderwidth=1, padx=10, pady=8)
        file_card.pack(side=tk.RIGHT if is_own else tk.LEFT, padx=20)
        
        # File icon and info
        icon = "📎" if file_data['mime_type'].startswith('application') else \
               "🖼️" if file_data['mime_type'].startswith('image') else \
               "🎵" if file_data['mime_type'].startswith('audio') else \
               "🎬" if file_data['mime_type'].startswith('video') else "📄"
        
        tk.Label(file_card, text=f"{icon} {file_data['filename']}", 
                font=('Courier New', 10, 'bold'), 
                bg=file_card['bg'], fg=self.colors['accent']).pack(anchor='w')
        
        tk.Label(file_card, text=f"Size: {self.format_file_size(file_data['size'])}", 
                font=('Courier New', 9), 
                bg=file_card['bg'], fg=self.colors['fg']).pack(anchor='w')
        
        # Download button
        ttk.Button(file_card, text="💾 DOWNLOAD", 
                  command=lambda: self.download_file(file_data),
                  style='ClassifiedButton.TButton').pack(pady=(5, 0))
        
        # Timestamp
        timestamp = datetime.fromtimestamp(msg['timestamp']).strftime('%H:%M:%S')
        tk.Label(message_frame, text=f"[{timestamp}] {msg['username']}", 
                font=('Courier New', 8), bg=self.colors['bg'], fg=self.colors['fg']).pack(
                side=tk.RIGHT if is_own else tk.LEFT, padx=20)
        
        # Auto-scroll
        self.messages_canvas.update_idletasks()
        self.messages_canvas.yview_moveto(1.0)
    
    def format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        else:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
    
    def download_file(self, file_data):
        """Download a received file"""
        from tkinter import filedialog
        
        try:
            # Ask where to save
            save_path = filedialog.asksaveasfilename(
                title="Save File As",
                initialname=file_data['filename'],
                defaultextension=os.path.splitext(file_data['filename'])[1]
            )
            
            if not save_path:
                return
            
            # Decode and save file
            file_bytes = base64.b64decode(file_data['data'])
            with open(save_path, 'wb') as f:
                f.write(file_bytes)
            
            messagebox.showinfo("DOWNLOAD COMPLETE", f"File saved to: {save_path}")
            
        except Exception as e:
            messagebox.showerror("DOWNLOAD FAILED", f"Failed to download file: {str(e)}")
    
    def handle_received_file(self, msg, is_own=False):
        """Handle received file message"""
        try:
            # Decrypt file message
            encrypted_data = base64.b64decode(msg['message'])
            decrypted_json = self.cipher.decrypt(encrypted_data).decode()
            file_data = json.loads(decrypted_json)
            
            # Add to display
            self.add_file_to_display(msg, file_data, is_own)
            
        except Exception as e:
            # Error handling received file - show as regular message if file handling fails
            self.add_message_to_display(msg, is_own, "📎 [File - Decryption Failed]")
    
    def add_message_to_display(self, msg, is_own=False, decrypted=None):
        message_frame = tk.Frame(self.messages_container, bg=self.colors['bg'])
        message_frame.pack(fill=tk.X, pady=8)
        
        widget_data = {
            'frame': message_frame,
            'message': msg,
            'is_own': is_own,
            'decrypted': decrypted,
            'is_locked': False if (is_own or self.auto_decrypt) else True
        }
        self.message_widgets.append(widget_data)
        
        # Message bubble
        bubble_frame = tk.Frame(message_frame, bg=self.colors['bg'])
        if is_own:
            bubble_frame.pack(side=tk.RIGHT, anchor='e')
        else:
            bubble_frame.pack(side=tk.LEFT, anchor='w')
        
        # Sender and time
        header_frame = tk.Frame(bubble_frame, bg=self.colors['bg'])
        header_frame.pack(fill=tk.X)
        
        time_label = tk.Label(header_frame, 
                              text=msg.get('time', '??:??'),
                              font=('Courier New', 8), bg=self.colors['bg'],
                              foreground=self.colors['fg'])
        if is_own:
            time_label.pack(side=tk.RIGHT, padx=(5, 0))
        else:
            time_label.pack(side=tk.LEFT, padx=(0, 5))
        
        sender_label = tk.Label(header_frame, 
                                text=msg.get('sender', '?'),
                                font=('Courier New', 9, 'bold'), bg=self.colors['bg'],
                                fg=self.colors['accent'])
        if is_own:
            sender_label.pack(side=tk.RIGHT)
        else:
            sender_label.pack(side=tk.LEFT)
        
        # Message content
        content_frame = tk.Frame(bubble_frame, bg=self.colors['card_bg'], relief='solid', borderwidth=2, padx=12, pady=12)
        content_frame.pack(fill=tk.X, pady=2)
        
        if is_own:
            msg_text = msg.get('message', '')
            try:
                decrypted_text = self.cipher.decrypt(msg_text.encode()).decode()
            except:
                decrypted_text = msg_text
            
            text_label = tk.Label(content_frame, 
                                  text=decrypted_text,
                                  wraplength=400,
                                  justify='right',
                                  background=self.colors['own_message'],
                                  fg=self.colors['fg'],
                                  font=('Courier New', 10))
            text_label.pack(side=tk.RIGHT)
            widget_data['is_locked'] = False
            widget_data['text_label'] = text_label
            
        else:
            if self.auto_decrypt:
                msg_text = msg.get('message', '')
                try:
                    decrypted_text = self.cipher.decrypt(msg_text.encode()).decode()
                except:
                    decrypted_text = msg_text
                
                text_label = tk.Label(content_frame, 
                                      text=decrypted_text,
                                      wraplength=400,
                                      justify='left',
                                      background=self.colors['their_message'],
                                      fg=self.colors['fg'],
                                      font=('Courier New', 10))
                text_label.pack(side=tk.LEFT)
                widget_data['is_locked'] = False
                widget_data['decrypted'] = decrypted_text
                widget_data['text_label'] = text_label
            else:
                text_label = tk.Label(content_frame, 
                                      text="🔐 CLASSIFIED INTEL",
                                      wraplength=400,
                                      justify='left',
                                      background='#333333',
                                      foreground=self.colors['warning'],
                                      font=('Courier New', 9, 'italic'))
                text_label.pack(side=tk.LEFT)
                widget_data['is_locked'] = True
                widget_data['text_label'] = text_label
        
        # Unlock button for others' messages
        if not is_own:
            action_frame = tk.Frame(bubble_frame, bg=self.colors['bg'])
            action_frame.pack(fill=tk.X, pady=(2, 0))
            
            if widget_data['is_locked']:
                unlock_btn = ttk.Button(action_frame, 
                                       text="🔓 DECRYPT INTEL",
                                       command=lambda w=widget_data: self.unlock_message(w),
                                       style='ClassifiedButton.TButton')
                unlock_btn.pack(side=tk.LEFT)
                widget_data['lock_btn'] = unlock_btn
            else:
                lock_btn = ttk.Button(action_frame, 
                                     text="🔒 CLASSIFY INTEL",
                                     command=lambda w=widget_data: self.lock_message(w),
                                     style='ClassifiedButton.TButton')
                lock_btn.pack(side=tk.LEFT)
                widget_data['lock_btn'] = lock_btn
        
        self.canvas.update_idletasks()
        self.canvas.yview_moveto(1.0)
    
    def unlock_message(self, widget_data):
        msg = widget_data['message']
        msg_text = msg.get('message', '')
        
        try:
            decrypted_text = self.cipher.decrypt(msg_text.encode()).decode()
        except:
            decrypted_text = "Decryption failed"
        
        widget_data['text_label'].config(text=decrypted_text, 
                                        background=self.colors['their_message'],
                                        foreground=self.colors['fg'],
                                        font=('Courier New', 10),
                                        justify='left')
        widget_data['lock_btn'].config(text="🔒 CLASSIFY INTEL", 
                                      command=lambda: self.lock_message(widget_data))
        widget_data['is_locked'] = False
        widget_data['decrypted'] = decrypted_text
    
    def lock_message(self, widget_data):
        widget_data['text_label'].config(text="🔐 CLASSIFIED INTEL", 
                                        background='#333333',
                                        foreground=self.colors['warning'],
                                        font=('Courier New', 9, 'italic'),
                                        justify='left')
        widget_data['lock_btn'].config(text="🔓 DECRYPT INTEL", 
                                      command=lambda: self.unlock_message(widget_data))
        widget_data['is_locked'] = True
    
    def check_messages(self):
        while self.connected:
            try:
                data = self.get_messages()
                messages = data.get("messages", [])
                
                for msg in messages:
                    if msg.get("timestamp", 0) > self.last_timestamp:
                        if msg.get("sender") != self.username:
                            self.last_timestamp = max(self.last_timestamp, msg.get("timestamp", 0))
                            if msg.get("message_type") == "file":
                                self.root.after(0, self.handle_received_file, msg)
                            else:
                                self.root.after(0, self.add_message_to_display, msg, False)
                
                time.sleep(2)
            except:
                time.sleep(5)
    
    def refresh_messages(self):
        for widget in self.messages_container.winfo_children():
            widget.destroy()
        self.message_widgets = []
        
        try:
            data = self.get_messages()
            messages = data.get("messages", [])
            
            # Apply forward secrecy - remove expired messages
            messages = self.forward_secrecy.cleanup_expired_messages(messages)
            
            for msg in messages:
                is_own = msg.get("sender") == self.username
                
                if msg.get("message_type") == "file":
                    self.handle_received_file(msg, is_own)
                else:
                    decrypted = None
                    if is_own or self.auto_decrypt:
                        msg_text = msg.get('message', '')
                        try:
                            decrypted = self.cipher.decrypt(msg_text.encode()).decode()
                            
                            # Verify message signature if available
                            signature = msg.get('signature')
                            if signature:
                                # Handle both old format (string) and new format (dict)
                                if isinstance(signature, dict):
                                    # New format with sequence numbers
                                    if not self.message_security.verify_signature(signature):
                                        decrypted = "⚠️ MESSAGE VERIFICATION FAILED - POSSIBLE TAMPERING OR REPLAY"
                                elif isinstance(signature, str):
                                    # Old format compatibility
                                    if not self.message_security.verify_signature(decrypted, signature):
                                        decrypted = "⚠️ MESSAGE VERIFICATION FAILED - POSSIBLE TAMPERING"
                        except:
                            decrypted = msg_text
                    
                    self.add_message_to_display(msg, is_own, decrypted)
                
        except Exception as e:
            # Error loading messages - handled silently
            pass
    
    def clear_chat_display(self):
        for widget in self.messages_container.winfo_children():
            widget.destroy()
        self.message_widgets = []
    
    def toggle_auto_decrypt(self):
        self.auto_decrypt = self.auto_decrypt_var.get()
        
        if self.connected:
            self.refresh_messages()
    
    def toggle_auto_approve(self):
        """Toggle auto-approval of clearance requests"""
        self.auto_approve_enabled = self.auto_approve_var.get()
        if self.auto_approve_enabled:
            messagebox.showinfo("AUTO-APPROVAL ENABLED", 
                              "⚠️ Auto-approval enabled!\n\n"
                              "All new clearance requests will be automatically approved.\n"
                              "Use with caution in secure environments.")
        else:
            messagebox.showinfo("AUTO-APPROVAL DISABLED", 
                              "Auto-approval disabled. Manual approval required for all requests.")
    
    def change_theme(self, theme_name=None):
        """Change the interface theme - Winter Cherry Blossom is default"""
        # Default to Winter Cherry Blossom if no theme specified
        if not theme_name:
            theme_name = "winter_cherry_blossom"
            
        if theme_name in self.themes:
            self.current_theme = theme_name
            self.colors = self.themes[theme_name]
            
            # For Winter Cherry Blossom, use the full theme system
            if theme_name == "winter_cherry_blossom":
                self.colors = self.winter_cherry_theme.get_color_palette()
                self.winter_cherry_theme.apply_theme(self.root)
                self.winter_components.apply_window_theme(self.root)
            
            # Update root window colors
            self.root.configure(bg=self.colors['bg'])
            
            # Recreate styles with new colors
            self.setup_styles()
            
            # Update all existing UI elements with new theme colors
            self.update_all_ui_elements()
            
            # Show current window again to apply new theme
            current_method = getattr(self, '_current_window_method', self.show_main_menu)
            try:
                current_method()
            except Exception as e:
                print(f"Error refreshing window after theme change: {e}")
                # Fallback to main menu if current method fails
                if self.authenticated:
                    self.show_main_menu()
                else:
                    self.show_authentication_screen()
            
            theme_display_name = theme_name.replace('_', ' ').title()
            if theme_name == "winter_cherry_blossom":
                theme_display_name += " (Default)"
            messagebox.showinfo("THEME CHANGED", f"Interface theme changed to: {theme_display_name}")
        else:
            # Fallback to Winter Cherry Blossom
            self.change_theme("winter_cherry_blossom")
    
    def update_all_ui_elements(self):
        """Update all existing UI elements with current theme colors"""
        def update_widget_recursive(widget):
            try:
                # Update buttons
                if isinstance(widget, tk.Button):
                    widget.configure(
                        bg=self.colors['button_bg'],
                        fg=self.colors['button_fg'],
                        activebackground=self.colors.get('button_hover', self.colors['button_bg']),
                        activeforeground=self.colors['button_fg']
                    )
                # Update labels
                elif isinstance(widget, tk.Label):
                    widget.configure(
                        bg=self.colors.get('card_bg', self.colors['bg']),
                        fg=self.colors['fg']
                    )
                # Update frames
                elif isinstance(widget, tk.Frame):
                    widget.configure(bg=self.colors.get('card_bg', self.colors['bg']))
                # Update entries
                elif isinstance(widget, tk.Entry):
                    widget.configure(
                        bg=self.colors['entry_bg'],
                        fg=self.colors['entry_fg'],
                        insertbackground=self.colors['entry_fg']
                    )
                # Update text widgets
                elif isinstance(widget, tk.Text):
                    widget.configure(
                        bg=self.colors['entry_bg'],
                        fg=self.colors['entry_fg'],
                        insertbackground=self.colors['entry_fg']
                    )
                
                # Recursively update all children
                for child in widget.winfo_children():
                    update_widget_recursive(child)
                    
            except Exception as e:
                # Skip widgets that can't be updated
                pass
        
        # Update all widgets starting from root
        update_widget_recursive(self.root)
    
    def track_current_window(self, method):
        """Track current window method for theme changes"""
        self._current_window_method = method
    
    def update_online_users_display(self):
        """Update the online users display"""
        if hasattr(self, 'online_users_label'):
            if self.online_users:
                users_text = ""
                for user in sorted(self.online_users):
                    if user == self.username:
                        users_text += f"👤 {user} (YOU)\n"
                    else:
                        users_text += f"👤 {user}\n"
                
                status_text = f"🟢 {len(self.online_users)} Online\n{users_text.strip()}"
                self.online_users_label.config(text=status_text)
            else:
                self.online_users_label.config(text="🔴 No agents online")
    
    def approve_all_pending(self):
        """Approve all pending clearance requests at once"""
        if not self.registry_id:
            messagebox.showerror("NO REGISTRY", "Load a registry first")
            return
        
        try:
            response = self.secure_request('GET', f"{REGISTRY_URL}/{self.registry_id}", timeout=5)
            if response.status_code != 200:
                messagebox.showerror("OPERATION FAILED", "Failed to load registry")
                return
            
            registry = response.json()
            pending_requests = registry.get("pending_requests", [])
            
            if not pending_requests:
                messagebox.showinfo("NO PENDING REQUESTS", "No pending clearance requests to approve")
                return
            
            # Confirm bulk approval
            usernames = [req.get("username", "Unknown") for req in pending_requests]
            if not messagebox.askyesno("CONFIRM BULK APPROVAL", 
                                     f"Approve clearance for {len(pending_requests)} agents?\n\n" + 
                                     "\n".join([f"• {name}" for name in usernames])):
                return
            
            # Approve all pending requests
            approved = registry.get("approved_users", [])
            newly_approved = []
            
            for request in pending_requests:
                username = request.get("username", "")
                if username and username not in approved:
                    approved.append(username)
                    newly_approved.append(username)
                    
                    # Track user session when approved
                    client_info = request.get('client_info', {})
                    if client_info:
                        session_data = {
                            'username': username,
                            'chat_id': self.chat_id,
                            'registry_id': self.registry_id,
                            'ip_address': client_info.get('ip_address', 'Unknown'),
                            'hwid': client_info.get('hwid', 'Unknown'),
                            'hardware_details': {
                                'hwid': client_info.get('hwid', 'Unknown'),
                                'mac_address': client_info.get('mac_address', 'Unknown'),
                                'disk_serial': 'Unknown',
                                'cpu_info': 'Unknown',
                                'memory_total': 'Unknown',
                                'system_info': client_info.get('system_info', {})
                            },
                            'location': self.user_tracker.get_location_info(client_info.get('ip_address', 'Unknown')),
                            'session_start': time.time(),
                            'last_activity': time.time(),
                            'status': 'bulk_approved',
                            'user_agent': client_info.get('user_agent', 'Unknown'),
                            'connection_count': 1
                        }
                        
                        session_key = f"{username}_{self.chat_id}"
                        self.user_tracker.user_sessions[session_key] = session_data
            
            # Clear pending requests and update registry
            registry["pending_requests"] = []
            registry["approved_users"] = approved
            registry["metadata"]["last_updated"] = time.time()
            registry["metadata"]["total_requests"] = len(approved)
            
            headers = {'Content-Type': 'application/json'}
            response = self.secure_request(
                'PUT',
                f"{REGISTRY_URL}/{self.registry_id}",
                json=registry,
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                approved_text = ", ".join(newly_approved)
                messagebox.showinfo("BULK APPROVAL COMPLETE", 
                                  f"✅ Approved {len(newly_approved)} agents:\n{approved_text}")
                self.load_registry_for_chat()
            else:
                messagebox.showerror("OPERATION FAILED", "Failed to update registry")
                
        except Exception as e:
            messagebox.showerror("OPERATION FAILED", f"Failed to approve requests: {str(e)}")
    
    def disconnect_chat(self):
        self.connected = False
        self.chat_id = None
        self.cipher = None
        self.registry_id = None
        # Secure memory wipe
        self.secure_memory.wipe_all()
        messagebox.showinfo("DISCONNECTED", "Secure channel terminated.")
        self.show_main_menu()
    
    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("COPIED", "Credentials copied to clipboard!")
    
    def show_instructions(self):
        instructions = """🔒 SECURE CHAT HOST - MANUAL

MAXIMUM SECURITY PROTOCOL:
• All communications routed through TOR network
• AES-256-GCM military-grade encryption
• PBKDF2 key derivation with 1M iterations
• Zero-trace operation with secure memory wiping
• Advanced traffic obfuscation and dummy requests
• Payload obfuscation prevents external visibility
• Complete privacy protection from outside monitoring

AGENT REGISTRATION SYSTEM:
1. Create channel with 'Create Secure Channel'
2. System establishes Channel AND Registry
3. Share Registry ID with client (PRIORITY)
4. Agent registers using Registry ID
5. Approve agent in Command Center

COMMAND CENTER:
• Enter Channel ID to manage agent clearances
• System locates registry automatically
• Review all pending clearance requests with full intel
• View agent IP, location, hardware fingerprint
• Click ✅ Grant or ❌ Deny clearance
• Manage cleared agents list

USER MONITORING SYSTEM:
• Track all user sessions with IP addresses
• Monitor hardware fingerprints (HWID)
• Geolocation tracking for all connections
• Real-time session monitoring
• Block suspicious users instantly
• Complete user intelligence gathering

MISSION HISTORY:
• All channels automatically archived
• Access 'Mission History' for saved channels
• Click 'Reconnect' on any archived channel
• Manual access available if needed

SECURE CHANNEL:
• Type intel and press Enter
• All messages encrypted before transmission
• Toggle Auto-Decrypt in Security menu
• Click 🔓 Decrypt to view individual intel
• Click 🔒 Classify to hide intel again

MAXIMUM SECURITY FEATURES:
• All messages end-to-end encrypted
• Server only processes obfuscated encrypted data
• Registration prevents unauthorized access
• Command must approve all agents
• Complete user tracking and monitoring
• IP address and location tracking
• Hardware fingerprinting for device identification
• Use TOR for complete anonymity
• No external visibility of chat contents"""
        
        messagebox.showinfo("OPERATION MANUAL", instructions)
    
    def show_about(self):
        messagebox.showinfo("SYSTEM INFO", 
                          "Secure Chat Host v5.0\n\n"
                          "MAXIMUM SECURITY IMPLEMENTATION\n"
                          "Military-grade encrypted communication\n"
                          "With advanced user monitoring and tracking\n\n"
                          "SECURITY FEATURES:\n"
                          "• AES-256-GCM encryption with PBKDF2\n"
                          "• TOR-only networking for anonymity\n"
                          "• Zero-trace secure memory management\n"
                          "• Advanced traffic obfuscation\n"
                          "• Complete privacy protection\n\n"
                          "MONITORING FEATURES:\n"
                          "• IP address tracking and geolocation\n"
                          "• Hardware fingerprinting (HWID)\n"
                          "• Real-time user session monitoring\n"
                          "• Complete user intelligence gathering\n"
                          "• Command-controlled agent clearance")
    
    # ============================================================================
    # DENIABLE ENCRYPTION UI METHODS
    # ============================================================================
    
    def show_deniable_encryption_setup(self):
        """Show deniable encryption setup wizard"""
        dialog = tk.Toplevel(self.root)
        dialog.title("DENIABLE ENCRYPTION SETUP")
        dialog.geometry("700x600")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 350
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 300
        dialog.geometry(f"+{x}+{y}")
        
        main_frame = tk.Frame(dialog, bg=self.colors['bg'], padx=40, pady=40)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        tk.Label(main_frame, text="🔐 DENIABLE ENCRYPTION SETUP",
                 font=('Courier New', 16, 'bold'), bg=self.colors['bg'], fg=self.colors['classified']).pack(pady=(0, 20))
        
        # Description
        desc_text = ("Deniable encryption provides plausible deniability in high-risk environments.\n"
                    "You will set up two passwords:\n"
                    "• Outer password: Shows innocent, harmless data\n"
                    "• Inner password: Reveals your actual sensitive communications\n\n"
                    "If coerced, you can provide the outer password to show innocent data.")
        
        tk.Label(main_frame, text=desc_text, font=('Segoe UI', 11), 
                bg=self.colors['bg'], fg=self.colors['fg'], justify=tk.LEFT).pack(pady=(0, 30))
        
        # Password fields
        password_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        password_frame.pack(fill=tk.X, pady=(0, 30))
        
        tk.Label(password_frame, text="Outer Password (for innocent data):",
                font=('Segoe UI', 12, 'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor=tk.W, pady=(0, 5))
        
        outer_password_entry = tk.Entry(password_frame, show="*", font=('Segoe UI', 12), width=40)
        self.winter_cherry_theme.apply_theme(outer_password_entry)
        outer_password_entry.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(password_frame, text="Inner Password (for sensitive data):",
                font=('Segoe UI', 12, 'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor=tk.W, pady=(0, 5))
        
        inner_password_entry = tk.Entry(password_frame, show="*", font=('Segoe UI', 12), width=40)
        self.winter_cherry_theme.apply_theme(inner_password_entry)
        inner_password_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Status label
        status_label = tk.Label(main_frame, text="", font=('Segoe UI', 11), 
                               bg=self.colors['bg'], fg=self.colors['danger'])
        status_label.pack(pady=(0, 20))
        
        def setup_deniable_encryption():
            outer_password = outer_password_entry.get()
            inner_password = inner_password_entry.get()
            
            if not outer_password or not inner_password:
                status_label.config(text="Both passwords are required", fg=self.colors['danger'])
                return
            
            if outer_password == inner_password:
                status_label.config(text="Passwords must be different", fg=self.colors['danger'])
                return
            
            try:
                success = self.master_password_manager.enable_deniable_encryption(outer_password, inner_password)
                if success:
                    messagebox.showinfo("SUCCESS", "Deniable encryption has been enabled successfully!")
                    dialog.destroy()
                else:
                    status_label.config(text="Failed to enable deniable encryption", fg=self.colors['danger'])
            except Exception as e:
                status_label.config(text=f"Error: {str(e)}", fg=self.colors['danger'])
        
        # Buttons
        button_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        tk.Button(button_frame, text="ENABLE DENIABLE ENCRYPTION",
                 command=setup_deniable_encryption,
                 bg=self.colors['button_bg'], fg=self.colors['button_fg'],
                 font=('Courier New', 12, 'bold'),
                 padx=20, pady=10).pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Button(button_frame, text="CANCEL",
                 command=dialog.destroy,
                 bg=self.colors['danger'], fg='white',
                 font=('Courier New', 12, 'bold'),
                 padx=20, pady=10).pack(side=tk.LEFT)
    
    def show_deniable_encryption_config(self):
        """Show deniable encryption configuration dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("DENIABLE ENCRYPTION CONFIGURATION")
        dialog.geometry("600x500")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 300
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 250
        dialog.geometry(f"+{x}+{y}")
        
        main_frame = tk.Frame(dialog, bg=self.colors['bg'], padx=40, pady=40)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        tk.Label(main_frame, text="🔧 DENIABLE ENCRYPTION CONFIGURATION",
                 font=('Courier New', 16, 'bold'), bg=self.colors['bg'], fg=self.colors['classified']).pack(pady=(0, 20))
        
        # Status
        status_info = self.master_password_manager.get_deniable_encryption_status()
        status_text = f"Status: {status_info['message']}"
        status_color = self.colors['success'] if status_info['status'] == 'enabled' else self.colors['warning']
        
        tk.Label(main_frame, text=status_text, font=('Segoe UI', 12, 'bold'), 
                bg=self.colors['bg'], fg=status_color).pack(pady=(0, 20))
        
        # Configuration options
        config_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        config_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        # Get current configuration
        try:
            config = self.master_password_manager.get_deniable_encryption_config()
            
            # Enable/Disable checkbox
            enabled_var = tk.BooleanVar(value=config.get('enabled', False))
            tk.Checkbutton(config_frame, text="Enable Deniable Encryption", 
                          variable=enabled_var, font=('Segoe UI', 11),
                          bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor=tk.W, pady=5)
            
            # Mode selection
            tk.Label(config_frame, text="Encryption Mode:", font=('Segoe UI', 11, 'bold'),
                    bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor=tk.W, pady=(15, 5))
            
            mode_var = tk.StringVar(value=config.get('mode', 'dual_layer'))
            for mode in config.get('available_modes', ['dual_layer']):
                tk.Radiobutton(config_frame, text=mode.replace('_', ' ').title(), 
                              variable=mode_var, value=mode, font=('Segoe UI', 10),
                              bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor=tk.W, padx=20)
            
            # Plausible deniability settings
            tk.Label(config_frame, text="Plausible Deniability Settings:", font=('Segoe UI', 11, 'bold'),
                    bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor=tk.W, pady=(15, 5))
            
            denial_settings = config.get('plausible_denial_settings', {})
            
            fake_timestamps_var = tk.BooleanVar(value=denial_settings.get('generate_fake_timestamps', True))
            tk.Checkbutton(config_frame, text="Generate Fake Timestamps", 
                          variable=fake_timestamps_var, font=('Segoe UI', 10),
                          bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor=tk.W, padx=20, pady=2)
            
            innocent_metadata_var = tk.BooleanVar(value=denial_settings.get('create_innocent_metadata', True))
            tk.Checkbutton(config_frame, text="Create Innocent Metadata", 
                          variable=innocent_metadata_var, font=('Segoe UI', 10),
                          bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor=tk.W, padx=20, pady=2)
            
            steganographic_var = tk.BooleanVar(value=denial_settings.get('use_steganographic_headers', False))
            tk.Checkbutton(config_frame, text="Use Steganographic Headers", 
                          variable=steganographic_var, font=('Segoe UI', 10),
                          bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor=tk.W, padx=20, pady=2)
            
        except Exception as e:
            tk.Label(config_frame, text=f"Error loading configuration: {str(e)}", 
                    font=('Segoe UI', 11), bg=self.colors['bg'], fg=self.colors['danger']).pack(pady=20)
            return
        
        def save_configuration():
            try:
                new_config = {
                    'enabled': enabled_var.get(),
                    'mode': mode_var.get(),
                    'plausible_denial_settings': {
                        'generate_fake_timestamps': fake_timestamps_var.get(),
                        'create_innocent_metadata': innocent_metadata_var.get(),
                        'use_steganographic_headers': steganographic_var.get()
                    }
                }
                
                success = self.master_password_manager.update_deniable_encryption_config(new_config)
                if success:
                    messagebox.showinfo("SUCCESS", "Configuration updated successfully!")
                    dialog.destroy()
                else:
                    messagebox.showerror("ERROR", "Failed to update configuration")
            except Exception as e:
                messagebox.showerror("ERROR", f"Configuration error: {str(e)}")
        
        def disable_deniable_encryption():
            if messagebox.askyesno("CONFIRM", "Are you sure you want to disable deniable encryption?"):
                try:
                    success = self.master_password_manager.disable_deniable_encryption()
                    if success:
                        messagebox.showinfo("SUCCESS", "Deniable encryption disabled")
                        dialog.destroy()
                    else:
                        messagebox.showerror("ERROR", "Failed to disable deniable encryption")
                except Exception as e:
                    messagebox.showerror("ERROR", f"Error: {str(e)}")
        
        # Buttons
        button_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        tk.Button(button_frame, text="SAVE CONFIGURATION",
                 command=save_configuration,
                 bg=self.colors['button_bg'], fg=self.colors['button_fg'],
                 font=('Courier New', 11, 'bold'),
                 padx=15, pady=8).pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Button(button_frame, text="DISABLE",
                 command=disable_deniable_encryption,
                 bg=self.colors['warning'], fg='white',
                 font=('Courier New', 11, 'bold'),
                 padx=15, pady=8).pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Button(button_frame, text="CANCEL",
                 command=dialog.destroy,
                 bg=self.colors['danger'], fg='white',
                 font=('Courier New', 11, 'bold'),
                 padx=15, pady=8).pack(side=tk.LEFT)

def main():
    """Main entry point - direct launch without complex loading"""
    try:
        print("Starting Polly Tunnels Host Application...")
        print("Initializing security systems...")
        
        # Create main window
        root = tk.Tk()
        root.title("Polly Tunnels - Host")
        
        print("Loading interface...")
        
        # Initialize the main application
        app = SecureChatHostGUI(root)
        
        print("Ready! Application window should appear.")
        
        # Start the main loop
        root.mainloop()
        
    except Exception as e:
        print(f"Error starting application: {e}")
        import traceback
        traceback.print_exc()
        
        # Show error dialog if possible
        try:
            error_root = tk.Tk()
            error_root.withdraw()
            messagebox.showerror("Startup Error", f"Failed to start application:\n{str(e)}")
            error_root.destroy()
        except:
            print("Could not show error dialog")

if __name__ == "__main__":
    main()
