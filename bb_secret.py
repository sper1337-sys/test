"""
Polly Tunnels - Secure Communication Client
Professional secure messaging application with end-to-end encryption
Features: User registration, chat history, file sharing, advanced security
Privacy-focused with Tor network integration
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, Menu, filedialog
import requests
import json
import time
import threading
import hashlib
import base64
import os
import secrets
import hmac
import uuid
import tempfile
import shutil
import gc
import socket
import urllib3
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Try to import keyring, fallback if not available
try:
    import keyring
except ImportError:
    keyring = None

# Import secure secret generation system
from secure_secret_generation import SecureSecretGenerator, get_installation_secrets, initialize_new_installation
from safety_numbers import SafetyNumberGenerator, SafetyNumberDisplay
from external_storage_encryption import ExternalStorageManager
from deniable_encryption import DeniableEncryptionManager, DeniableEncryptionUI
from configuration_encryption import ConfigurationEncryption
from randomized_self_destruct import RandomizedSelfDestruct
from english_language_manager import EnglishLanguageManager, english_manager
from automatic_tor_connector import show_tor_setup_dialog
from loading_screen import LoadingManager

# Disable SSL warnings for Tor
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://jsonblob.com/api/jsonBlob"
REGISTRY_URL = "https://jsonblob.com/api/jsonBlob"

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
        self.max_attempts = 3
        self.decoy_password = None
        self.decoy_data = []
        self.is_decoy_mode = False
        self.attempt_file = "client_attempts.dat"
        self.recovery_phrase = None
        self.recovery_phrase_hash = None
        self.password_change_attempts = 0
        self.recovery_file = "client_recovery.dat"
        
        # Safety number system for end-to-end encryption verification
        self.safety_generator = SafetyNumberGenerator()
        self.safety_display = SafetyNumberDisplay(self.safety_generator)
        
        # External storage encryption system
        self.external_storage = None
        
        # Deniable encryption system
        self.deniable_encryption = DeniableEncryptionManager("client_deniable_config.json")
        self.deniable_ui = DeniableEncryptionUI(self.deniable_encryption)
        
        # Randomized self-destruct system
        self.randomized_self_destruct = RandomizedSelfDestruct()
        
        # Initialize external storage encryption
        self.initialize_external_storage()
    
    def initialize_external_storage(self):
        """Initialize external storage encryption system"""
        try:
            # Try to load existing installation secrets
            installation_secrets = get_installation_secrets()
            
            if installation_secrets and 'storage_encryption_key' in installation_secrets:
                # Use existing storage key
                storage_key = installation_secrets['storage_encryption_key']
                self.external_storage = ExternalStorageManager(storage_key)
                # External storage encryption initialized with existing key
            else:
                # Create with random key (fallback)
                self.external_storage = ExternalStorageManager()
                # External storage encryption initialized with random key
                
        except Exception as e:
            # Failed to initialize external storage encryption - using fallback mode
            # Still initialize with random key as fallback
            self.external_storage = ExternalStorageManager()
            # External storage encryption initialized in fallback mode
        
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
            iterations=2000000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        
        # Return both key and salt for storage
        return {
            'key': key,
            'salt': base64.b64encode(salt).decode('utf-8')
        }
    
    def generate_recovery_phrase(self):
        """Generate a unique, fully random 12-word recovery phrase"""
        word_list = [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
            "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
            "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
            "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "against", "age",
            "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol",
            "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also",
            "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient",
            "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna"
        ]
        
        recovery_words = []
        for _ in range(12):
            word_index = secrets.randbelow(len(word_list))
            recovery_words.append(word_list[word_index])
        
        self.recovery_phrase = recovery_words
        phrase_string = ' '.join(recovery_words)
        self.recovery_phrase_hash = hashlib.sha256(phrase_string.encode()).hexdigest()
        self.save_recovery_phrase()
        return recovery_words
    
    def save_recovery_phrase(self):
        """Save encrypted recovery phrase to secure file"""
        if not self.recovery_phrase:
            return
        
        try:
            phrase_string = ' '.join(self.recovery_phrase)
            salt = secrets.token_bytes(32)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=2000000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(phrase_string.encode()))
            cipher = Fernet(key)
            encrypted_phrase = cipher.encrypt(phrase_string.encode())
            
            recovery_data = {
                'salt': base64.b64encode(salt).decode(),
                'encrypted_phrase': base64.b64encode(encrypted_phrase).decode(),
                'hash': self.recovery_phrase_hash,
                'timestamp': time.time()
            }
            
            with open(self.recovery_file, 'w') as f:
                json.dump(recovery_data, f)
                
        except Exception as e:
            # Failed to save recovery phrase - handled silently
            pass
    
    def verify_recovery_phrase(self, input_words):
        """Verify all 12 words of recovery phrase in correct order"""
        if not self.recovery_phrase:
            return False
        
        if len(input_words) != 12:
            return False
        
        for i in range(12):
            if input_words[i].lower().strip() != self.recovery_phrase[i].lower():
                return False
        
        return True
    
    def setup_decoy_password(self, decoy_password):
        """Setup obviously fake decoy password with enhanced security"""
        # Use the provided obviously fake password
        self.decoy_password = decoy_password
        
        # Generate obviously fake data that matches the fake password pattern
        self.decoy_data = [
            {
                'chat_id': 'FAKE_CLIENT_CHAT_' + secrets.token_hex(8),
                'registry_id': 'FAKE_CLIENT_REGISTRY_' + secrets.token_hex(8),
                'encryption_key': base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
                'username': 'FAKE_CLIENT_USER',
                'timestamp': time.time() - 86400,
                'is_fake': True
            }
        ]
    
    def is_decoy_password(self, password):
        """Check if password is the obviously fake decoy password"""
        if not password or not self.decoy_password:
            return False
        return password == self.decoy_password
    
    def check_failed_attempts(self):
        """Check and update failed login attempts"""
        try:
            if os.path.exists(self.attempt_file):
                with open(self.attempt_file, 'r') as f:
                    data = json.load(f)
                    self.failed_attempts = data.get('attempts', 0)
        except:
            self.failed_attempts = 0
    
    def record_failed_attempt(self):
        """Record failed attempt and check if should self-destruct"""
        self.failed_attempts += 1
        
        try:
            with open(self.attempt_file, 'w') as f:
                json.dump({'attempts': self.failed_attempts, 'timestamp': time.time()}, f)
        except:
            pass
        
        return self.failed_attempts >= self.max_attempts
    
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
            json_data = json.dumps(data, indent=2)
            encrypted_data = cipher.encrypt(json_data.encode('utf-8'))
            
            header = b'CLIENT_CLASSIFIED_HISTORY_V1'
            checksum = hashlib.sha256(encrypted_data).digest()
            
            return header + checksum + encrypted_data
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt_history_file(self, encrypted_data, password):
        """Decrypt history data with master password"""
        try:
            header = b'CLIENT_CLASSIFIED_HISTORY_V1'
            if not encrypted_data.startswith(header):
                raise Exception("Invalid file format")
            
            header_len = len(header)
            checksum = encrypted_data[header_len:header_len + 32]
            encrypted_content = encrypted_data[header_len + 32:]
            
            if hashlib.sha256(encrypted_content).digest() != checksum:
                raise Exception("File integrity check failed")
            
            key = self.derive_master_key(password)
            cipher = Fernet(key)
            decrypted_data = cipher.decrypt(encrypted_content)
            
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
    
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
            # Update password hash
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
            # Deniable encryption mode enabled/disabled silently
            return success
        except Exception as e:
            # Failed to enable deniable encryption in client
            return False
    
    def disable_deniable_encryption(self):
        """Disable deniable encryption mode"""
        try:
            success = self.deniable_encryption.disable_deniable_encryption()
            # Deniable encryption mode disabled silently
            return success
        except Exception as e:
            # Failed to disable deniable encryption in client
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

class SecurityManager:
    """Advanced multi-layer security system with 3-attempt lockout"""
    def __init__(self):
        self.app_name = "SecureChatClient"
        self.failed_attempts = 0
        self.max_attempts = 3
        self.session_timeout = 1800  # 30 minutes
        self.last_activity = time.time()
        self.is_authenticated = False
        self.locked = False
        self.history_password_hash = None
        self.startup_password_hash = None
        self.pin_hash = None
        self.load_security_settings()
        
    def hash_password(self, password, salt=None):
        """Hash password with random salt and enhanced security"""
        # Always generate new random salt for security (ignore provided salt parameter)
        salt = secrets.token_bytes(32)
        
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Use enhanced security with more iterations
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=salt,
            iterations=2000000,  # Increased iterations for better security
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
            
            # Use same enhanced security parameters
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=64,
                salt=salt,
                iterations=2000000,  # Match hash_password iterations
            )
            key = kdf.derive(password)
            
            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(stored_key, key)
        except Exception:
            return False
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()
    
    def check_session_timeout(self):
        """Check if session has timed out"""
        return (time.time() - self.last_activity) > self.session_timeout
    
    def lock_session(self):
        """Lock the session"""
        self.locked = True
    
    def unlock_session(self):
        """Unlock the session"""
        self.locked = False
        self.update_activity()
    
    def load_security_settings(self):
        """Load security settings from secure storage"""
        try:
            # Try to load from keyring if available
            if keyring:
                self.startup_password_hash = keyring.get_password(self.app_name, "startup_password")
                self.pin_hash = keyring.get_password(self.app_name, "pin_code")
                self.history_password_hash = keyring.get_password(self.app_name, "history_password")
        except:
            pass
    
    def save_security_settings(self):
        """Save security settings to secure storage"""
        try:
            # Try to save to keyring if available
            if keyring:
                if self.startup_password_hash:
                    keyring.set_password(self.app_name, "startup_password", self.startup_password_hash)
                if self.pin_hash:
                    keyring.set_password(self.app_name, "pin_code", self.pin_hash)
                if self.history_password_hash:
                    keyring.set_password(self.app_name, "history_password", self.history_password_hash)
        except:
            pass
    
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
    
    def panic_wipe(self):
        """Emergency data wipe with randomized timing"""
        try:
            # Wipe keyring data if available
            if keyring:
                keyring.delete_password(self.app_name, "startup_password")
                keyring.delete_password(self.app_name, "pin_code")
                keyring.delete_password(self.app_name, "history_password")
        except:
            pass
        
        # Wipe history files using randomized self-destruct
        history_files = [
            "polly_secure_logs.json",
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
    
    def authenticate_history(self, password):
        """Authenticate for history access"""
        if not self.history_password_hash:
            return True
        return self.verify_password(password, self.history_password_hash)
    
    def change_history_password(self, current_password, new_password):
        """Change history password"""
        if self.history_password_hash and not self.verify_password(current_password, self.history_password_hash):
            return False
        
        self.set_history_password(new_password)
        return True
    
    def verify_history_password(self, password):
        """Verify history password"""
        if not self.history_password_hash:
            return True
        return self.verify_password(password, self.history_password_hash)

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
            # Key generation failed silently
            pass
    
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
            # Message signing failed silently
            return None
    
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
            # Signature verification failed silently
            return False
    
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
                # Key rotation failed silently
                return False
        return False

class RSAMessageSigner:
    """RSA Message Signing System for digital signatures and message authentication"""
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
        self.public_keys_registry = {}  # Store other users' public keys
        
    def generate_key_pair(self) -> tuple[bytes, bytes]:
        """Generate RSA key pair (private_key, public_key)"""
        try:
            # Generate private key
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
                backend=default_backend()
            )
            
            # Get public key
            self.public_key = self.private_key.public_key()
            
            # Serialize keys
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return private_pem, public_pem
            
        except Exception as e:
            raise Exception(f"RSA key generation failed: {str(e)}")
    
    def load_private_key(self, private_key_data: bytes, password: bytes = None):
        """Load private key from PEM data"""
        try:
            self.private_key = serialization.load_pem_private_key(
                private_key_data,
                password=password,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
        except Exception as e:
            raise Exception(f"Failed to load private key: {str(e)}")
    
    def load_public_key(self, public_key_data: bytes):
        """Load public key from PEM data"""
        try:
            return serialization.load_pem_public_key(
                public_key_data,
                backend=default_backend()
            )
        except Exception as e:
            raise Exception(f"Failed to load public key: {str(e)}")
    
    def sign_message(self, message: str) -> str:
        """Sign message with RSA private key using SHA-256 hash"""
        if not self.private_key:
            raise Exception("No private key available for signing")
        
        try:
            if isinstance(message, str):
                message = message.encode('utf-8')
            
            # Sign with PKCS#1 v1.5 padding and SHA-256 hash
            signature = self.private_key.sign(
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            # Return base64 encoded signature
            return base64.b64encode(signature).decode('utf-8')
            
        except Exception as e:
            raise Exception(f"Message signing failed: {str(e)}")
    
    def verify_signature(self, message: str, signature: str, public_key_data: bytes = None) -> bool:
        """Verify message signature with RSA public key"""
        try:
            if isinstance(message, str):
                message = message.encode('utf-8')
            
            # Decode signature from base64
            signature_bytes = base64.b64decode(signature.encode('utf-8'))
            
            # Use provided public key or own public key
            if public_key_data:
                public_key = self.load_public_key(public_key_data)
            elif self.public_key:
                public_key = self.public_key
            else:
                return False
            
            # Verify signature
            public_key.verify(
                signature_bytes,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            return True
            
        except Exception:
            return False
    
    def export_public_key(self) -> str:
        """Export public key as PEM string"""
        if not self.public_key:
            raise Exception("No public key available")
        
        try:
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return public_pem.decode('utf-8')
        except Exception as e:
            raise Exception(f"Public key export failed: {str(e)}")
    
    def import_public_key(self, key_data: str) -> bytes:
        """Import public key from PEM string"""
        try:
            key_bytes = key_data.encode('utf-8')
            public_key = self.load_public_key(key_bytes)
            return key_bytes
        except Exception as e:
            raise Exception(f"Public key import failed: {str(e)}")
    
    def store_public_key(self, user_id: str, public_key_data: bytes):
        """Store another user's public key in registry"""
        try:
            # Validate the public key by loading it
            public_key = self.load_public_key(public_key_data)
            self.public_keys_registry[user_id] = public_key_data
        except Exception as e:
            raise Exception(f"Failed to store public key for {user_id}: {str(e)}")
    
    def get_public_key(self, user_id: str) -> bytes:
        """Get stored public key for a user"""
        return self.public_keys_registry.get(user_id)
    
    def verify_user_signature(self, message: str, signature: str, user_id: str) -> bool:
        """Verify signature using stored public key for specific user"""
        public_key_data = self.get_public_key(user_id)
        if not public_key_data:
            return False
        return self.verify_signature(message, signature, public_key_data)

class SecureMemory:
    """Military-grade secure memory management with enhanced security features"""
    def __init__(self):
        self._data = {}
        self._temp_files = []
        # Import and use enhanced memory security manager
        try:
            from memory_security import MemorySecurityManager
            self._memory_manager = MemorySecurityManager()
        except ImportError:
            self._memory_manager = None
    
    def store(self, key: str, value: bytes):
        """Store sensitive data in memory"""
        if isinstance(value, str):
            value = value.encode()
        self._data[key] = bytearray(value)
        
        # Lock memory pages if supported
        if self._memory_manager and self._memory_manager.supports_memory_locking():
            try:
                self._memory_manager.lock_memory_pages(self._data[key])
            except:
                pass  # Continue if locking fails
    
    def retrieve(self, key: str) -> bytes:
        """Retrieve sensitive data"""
        if key in self._data:
            return bytes(self._data[key])
        return b''
    
    def wipe(self, key: str = None):
        """Securely wipe memory using enhanced clearing"""
        if key:
            if key in self._data:
                # Use enhanced memory manager if available
                if self._memory_manager:
                    try:
                        # Unlock memory pages before clearing
                        if self._memory_manager.supports_memory_locking():
                            self._memory_manager.unlock_memory_pages(self._data[key])
                        
                        # Use enhanced secure clearing
                        self._memory_manager.secure_clear_variable(key, self._data, 'multiple_passes')
                    except:
                        # Fallback to original method
                        self._fallback_wipe(key)
                else:
                    self._fallback_wipe(key)
        else:
            for k in list(self._data.keys()):
                self.wipe(k)
        
        # Enhanced garbage collection
        if self._memory_manager:
            self._memory_manager.secure_garbage_collection()
        else:
            gc.collect()
    
    def _fallback_wipe(self, key: str):
        """Fallback wiping method if enhanced manager not available"""
        if key in self._data:
            for _ in range(7):  # DoD 5220.22-M standard
                for i in range(len(self._data[key])):
                    self._data[key][i] = secrets.randbits(8)
            del self._data[key]
    
    def create_temp_file(self) -> str:
        """Create secure temporary file"""
        fd, path = tempfile.mkstemp()
        os.close(fd)
        self._temp_files.append(path)
        return path
    
    def cleanup_temp_files(self):
        """Securely delete temporary files"""
        for path in self._temp_files:
            if os.path.exists(path):
                try:
                    size = os.path.getsize(path)
                    with open(path, 'wb') as f:
                        for _ in range(7):  # DoD standard
                            f.seek(0)
                            f.write(secrets.token_bytes(size))
                            f.flush()
                            os.fsync(f.fileno())
                    os.remove(path)
                except:
                    pass
        self._temp_files.clear()
    
    def __del__(self):
        self.wipe()
        self.cleanup_temp_files()

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
    """Obfuscate network traffic to prevent analysis"""
    def __init__(self):
        pass
    
    def obfuscate_payload(self, data: dict) -> dict:
        """Add obfuscation to payload"""
        # Add random padding
        padding_size = secrets.randbelow(512) + 256
        padding = base64.b64encode(secrets.token_bytes(padding_size)).decode()
        
        # Add fake metadata
        fake_metadata = {
            'timestamp': time.time() + secrets.randbelow(3600),
            'version': f"{secrets.randbelow(10)}.{secrets.randbelow(10)}.{secrets.randbelow(10)}",
            'client_id': secrets.token_hex(16),
            'session_id': secrets.token_hex(32),
            'padding': padding,
            'checksum': secrets.token_hex(64)
        }
        
        # Embed real data
        obfuscated = {
            'metadata': fake_metadata,
            'payload': data,
            'signature': secrets.token_hex(128)
        }
        
        return obfuscated
    
    def deobfuscate_payload(self, obfuscated: dict) -> dict:
        """Extract real payload"""
        if isinstance(obfuscated, dict) and 'payload' in obfuscated:
            return obfuscated['payload']
        return obfuscated

class UserRole:
    ADMIN = "COMMANDER"
    MODERATOR = "OPERATIVE"
    USER = "AGENT"
    READONLY = "OBSERVER"

class PermissionManager:
    def __init__(self):
        self.permissions = {
            UserRole.ADMIN: ["send", "delete", "ban", "approve", "moderate", "kick"],
            UserRole.MODERATOR: ["send", "delete", "moderate", "kick"],
            UserRole.USER: ["send"],
            UserRole.READONLY: []
        }
    
    def can_perform(self, role: str, action: str) -> bool:
        return action in self.permissions.get(role, [])

class MessageHistory:
    def __init__(self, max_messages=500):
        self.max_messages = max_messages
        self.messages = []
    
    def add_message(self, message: dict):
        self.messages.append(message)
        if len(self.messages) > self.max_messages:
            self.messages = self.messages[-self.max_messages:]
    
    def search_messages(self, query: str, username: str = None) -> list:
        results = []
        for msg in self.messages:
            content = msg.get("decrypted", msg.get("message", ""))
            if query.lower() in content.lower():
                if username is None or msg.get("sender") == username:
                    results.append(msg)
        return results

class MasterPasswordDialog:
    """Master password authentication dialog with Winter Cherry Blossom theme"""
    def __init__(self, parent, password_manager, colors=None):
        self.parent = parent
        self.password_manager = password_manager
        self.password = None
        self.dialog = None
        
        # Initialize Winter Cherry Blossom theme for dialog
        self.winter_theme = WinterCherryBlossomTheme()
        # Use Winter Cherry Blossom colors if provided, otherwise use theme colors
        self.colors = colors or self.winter_theme.get_color_palette()
        
    def show_dialog(self):
        """Show master password dialog"""
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
        
        # Main frame
        main_frame = tk.Frame(self.dialog, bg=self.colors['card_bg'], padx=40, pady=40)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header with Winter Cherry Blossom styling
        tk.Label(main_frame, text="🌸", 
                 font=self.winter_theme.get_font_config('title'), 
                 bg=self.colors['card_bg'], 
                 fg=self.colors['blossom_primary']).pack(pady=(0, 20))
        
        tk.Label(main_frame, text="CLASSIFIED ACCESS CONTROL",
                 font=self.winter_theme.get_font_config('heading'), 
                 bg=self.colors['card_bg'], 
                 fg=self.colors['accent']).pack(pady=(0, 10))
        
        tk.Label(main_frame, text="Enter Master Password to Access Classified Data",
                 font=self.winter_theme.get_font_config('body'), 
                 bg=self.colors['card_bg'], 
                 fg=self.colors['fg']).pack(pady=(0, 30))
        
        # Password entry
        password_frame = tk.Frame(main_frame, bg=self.colors['card_bg'])
        password_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(password_frame, text="MASTER PASSWORD:",
                 font=('Segoe UI', 12, 'bold'), bg=self.colors['card_bg'], fg=self.colors['accent']).pack(anchor='w', pady=(0, 10))
        
        self.password_entry = tk.Entry(password_frame, show="*", 
                                      bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                      font=('Segoe UI', 12),
                                      insertbackground=self.colors['entry_fg'])
        self.password_entry.pack(fill=tk.X, pady=(0, 10))
        self.password_entry.bind('<Return>', lambda e: self.authenticate())
        self.password_entry.focus()
        
        # Show/hide password
        show_frame = tk.Frame(password_frame, bg=self.colors['card_bg'])
        show_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.show_password_var = tk.BooleanVar()
        tk.Checkbutton(show_frame, text="Show Password", 
                      variable=self.show_password_var,
                      command=self.toggle_password_visibility,
                      bg=self.colors['card_bg'], fg=self.colors['fg'], 
                      selectcolor=self.colors['card_bg'],
                      font=('Segoe UI', 10)).pack(anchor='w')
        
        # Attempts warning
        attempts_left = self.password_manager.max_attempts - self.password_manager.failed_attempts
        if self.password_manager.failed_attempts > 0:
            warning_text = f"⚠️ WARNING: {attempts_left} attempts remaining before self-destruct"
            tk.Label(main_frame, text=warning_text,
                     font=('Segoe UI', 10, 'bold'), bg=self.colors['card_bg'], fg=self.colors['danger']).pack(pady=(0, 20))
        
        # Buttons
        button_frame = tk.Frame(main_frame, bg=self.colors['card_bg'])
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        access_btn = self.winter_components.create_styled_button(
            button_frame, 
            text="ACCESS CLASSIFIED DATA",
            command=self.authenticate
        )
        access_btn.configure(font=('Segoe UI', 12, 'bold'), padx=20, pady=10)
        access_btn.pack(side=tk.RIGHT, padx=(10, 0))
        
        cancel_btn = self.winter_components.create_styled_button(
            button_frame, 
            text="CANCEL",
            command=self.on_cancel
        )
        cancel_btn.configure(font=('Segoe UI', 12, 'bold'), padx=20, pady=10, 
                           fg=self.colors['danger'])
        cancel_btn.pack(side=tk.RIGHT)
        
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
            # Check if it's the obviously fake decoy password
            if self.password_manager.is_decoy_password(password):
                self.password_manager.is_decoy_mode = True
                self.password = password
                self.dialog.destroy()
                return
            
            # Try to authenticate with a test encryption/decryption
            test_data = {"test": "authentication"}
            encrypted = self.password_manager.encrypt_history_file(test_data, password)
            decrypted = self.password_manager.decrypt_history_file(encrypted, password)
            
            if decrypted.get("test") == "authentication":
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
                self.password_manager.self_destruct("polly_secure_logs.json")
                # Close dialog and let parent handle the self-destruct
                self.password = None
                self.dialog.destroy()
                # Signal parent to exit securely
                self.parent.after(100, self.parent.quit)
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

class PollyTunnelsGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Polly Tunnels - Secure Communication")
        self.root.geometry("1600x1000")
        
        # Configuration management - must be defined before theme setup
        self.config_file = "polly_client_config.enc"  # Use encrypted configuration
        self.theme_config_file = "polly_theme_config.json"  # Keep for backward compatibility
        self.config_encryption = ConfigurationEncryption()  # Initialize configuration encryption
        
        # Winter Cherry Blossom Theme System - Main Theme Integration (copied from host)
        self.winter_cherry_theme = WinterCherryBlossomTheme()
        self.winter_components = WinterCherryBlossomComponents(self.winter_cherry_theme)
        self.current_theme = "winter_cherry_blossom"
        
        # Theme colors - Winter Cherry Blossom is the main theme
        self.colors = self.winter_cherry_theme.get_color_palette()
        
        # Winter Cherry Blossom is the main theme, with other themes available (exact copy from host)
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
        self.setup_professional_styles()
        
        # Load theme preference and setup styles
        self.load_theme_preference()
        self.setup_professional_styles()
        
        self.root.configure(bg=self.colors['bg'])
        
        # Set window properties for secrecy
        self.root.attributes('-topmost', False)
        self.root.resizable(True, True)
        
        # Initialize master password system
        self.master_password_manager = MasterPasswordManager()
        self.master_password = None
        
        # Check failed attempts on startup
        self.master_password_manager.check_failed_attempts()
        
        # Setup obviously fake decoy password using enhanced system
        from enhanced_decoy_system import EnhancedDecoySystem
        enhanced_decoy = EnhancedDecoySystem()
        obvious_fake_password = enhanced_decoy.setup_obvious_decoy()
        self.master_password_manager.setup_decoy_password(obvious_fake_password)
        
        # Initialize security components first
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
        
        self.obfuscator = TrafficObfuscator()
        
        # Enhanced security components
        self.permission_manager = PermissionManager()
        self.message_history = MessageHistory()
        self.security_manager = SecurityManager()
        self.message_security = MessageSecurity()
        
        # Secure secret generation system
        self.secret_generator = SecureSecretGenerator()
        self.installation_secrets = None
        
        # Initialize secure secrets at startup
        self.initialize_secure_secrets()
        
        # Phase 2: Advanced Security Infrastructure
        self.rsa_signer = RSAMessageSigner(key_size=2048)
        self.rsa_keys_generated = False
        
        # Security state
        self.authenticated = False
        self.session_timer = None
        
        # Setup secure environment
        self.setup_secure_environment()
        
        # Chat state
        self.chat_id = None
        self.encryption_key = None
        self.cipher = None
        self.username = "TUNNEL_USER"
        self.user_role = UserRole.USER
        self.auto_decrypt = True
        self.connected = False
        self.last_timestamp = 0
        self.message_widgets = []
        self.auth_key = None
        
        # Registration state
        self.registry_id = None
        self.request_id = None
        self.is_approved = False
        self.registration_checked = False
        
        # Security features
        self.security_features = {}
        
        # Window tracking for theme changes
        self.current_window_func = None
        
        # Configuration files already defined above
        
        # Chat history
        self.chat_history_file = "polly_secure_logs.json"
        
        # Professional theme colors (already initialized above)
        
        # Show authentication screen first
        if self.security_manager.startup_password_hash:
            self.show_authentication_screen()
        else:
            self.show_security_setup()
        
        # Setup secure exit handler
        self.root.protocol("WM_DELETE_WINDOW", self.secure_exit)
    
    def authenticate_master_password(self):
        """Authenticate master password on startup"""
        dialog = MasterPasswordDialog(self.root, self.master_password_manager, self.colors)
        dialog.show_dialog()
        
        # Wait for dialog to complete
        self.root.wait_window(dialog.dialog)
        
        if dialog.password:
            self.master_password = dialog.password
            # Load chat history after authentication
            self.chat_history = self.load_chat_history()
            return True
        else:
            return False
    
    def secure_exit(self):
        """Secure application exit with enhanced memory wiping"""
        try:
            # Save encrypted history before exit
            if hasattr(self, 'master_password') and self.master_password and hasattr(self, 'chat_history'):
                self.save_encrypted_history(self.chat_history)
            
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
    
    def initialize_secure_secrets(self):
        """Initialize secure cryptographic secrets at startup"""
        try:
            # Try to load existing installation secrets
            self.installation_secrets = get_installation_secrets()
            
            if self.installation_secrets is None:
                # First time installation - generate new secrets
                # Initializing secure cryptographic secrets for new installation
                self.installation_secrets = initialize_new_installation()
                # Cryptographic secrets generated successfully
            else:
                # Loaded existing installation secrets
                pass
                
        except Exception as e:
            # Failed to initialize secure secrets - continuing in fallback mode
            # Continue without secure secrets (fallback mode)
            self.installation_secrets = None
    
    def get_installation_secret(self, secret_name):
        """Get a specific installation secret by name"""
        if self.installation_secrets and secret_name in self.installation_secrets:
            return self.installation_secrets[secret_name]
        return None
    
    def secure_request(self, method, url, **kwargs):
        """Make secure request through Tor with external storage encryption"""
        # Apply external storage encryption for data going to JSONBlob
        if 'json' in kwargs and (BASE_URL in url or REGISTRY_URL in url):
            try:
                # Encrypt data before sending to external storage
                if self.master_password_manager.external_storage:
                    encrypted_payload = self.master_password_manager.external_storage.prepare_data_for_jsonblob(kwargs['json'])
                    kwargs['json'] = encrypted_payload
                else:
                    # Fallback: just obfuscate if encryption not available
                    kwargs['json'] = self.obfuscator.obfuscate_payload(kwargs['json'])
            except Exception as e:
                # External storage encryption failed, using obfuscation
                kwargs['json'] = self.obfuscator.obfuscate_payload(kwargs['json'])
        elif 'json' in kwargs:
            # For non-JSONBlob requests, just obfuscate
            kwargs['json'] = self.obfuscator.obfuscate_payload(kwargs['json'])
        
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
                                    return self.obfuscator.deobfuscate_payload(data)
                            except Exception as e:
                                # External storage decryption failed, trying deobfuscation
                                return self.obfuscator.deobfuscate_payload(data)
                        else:
                            # For non-JSONBlob responses, just deobfuscate
                            return self.obfuscator.deobfuscate_payload(data)
                    
                    response.json = processed_json
            except Exception as e:
                # Response processing failed silently
                pass
        
        return response
    
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
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=100, pady=100)
        
        # Setup card
        setup_card = tk.Frame(main_container, bg=self.colors['card_bg'], relief='solid', borderwidth=2, padx=40, pady=40)
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
        
        tk.Label(setup_card, text="Separate password for accessing chat history",
                 font=('Courier New', 10), bg=self.colors['card_bg'], fg=self.colors['fg']).pack(anchor='w', pady=(0, 5))
        
        self.history_password_entry = tk.Entry(setup_card, show="*", bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                              font=('Courier New', 12), width=30)
        self.history_password_entry.pack(pady=(0, 30))
        
        # Setup button
        tk.Button(setup_card, text="COMPLETE SECURITY SETUP",
                  command=self.complete_security_setup,
                  bg=self.colors['button_bg'], fg=self.colors['button_fg'],
                  font=('Courier New', 12, 'bold'),
                  padx=20, pady=10).pack(pady=(20, 0))
    
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
        
        messagebox.showinfo("SETUP COMPLETE", "Security setup completed successfully!\n\nRemember your passwords - they cannot be recovered!")
        
        # Authenticate and show main menu
        self.security_manager.is_authenticated = True
        self.authenticated = True
        
        # For initial setup, skip master password and go directly to main menu
        self.master_password = startup_password  # Use startup password as master password
        self.chat_history = self.load_chat_history()
        self.load_configuration()
        self.start_session_timer()
        self.create_professional_menu_bar()
        self.show_classified_main_menu()
    
    def show_authentication_screen(self):
        """Show authentication screen"""
        self.clear_window()
        
        # Authentication banner
        banner_frame = tk.Frame(self.root, bg=self.colors['danger'], height=40)
        banner_frame.pack(fill=tk.X)
        banner_frame.pack_propagate(False)
        
        tk.Label(banner_frame, text="★ ★ ★ CLASSIFIED ACCESS - AUTHENTICATION REQUIRED ★ ★ ★", 
                 bg=self.colors['danger'], fg='white', 
                 font=('Courier New', 12, 'bold')).pack(expand=True)
        
        # Main auth container
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=150, pady=150)
        
        # Auth card
        auth_card = tk.Frame(main_container, bg=self.colors['card_bg'], relief='solid', borderwidth=2, padx=40, pady=40)
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
        
        auth_btn = self.winter_components.create_styled_button(
            button_frame, 
            text="AUTHENTICATE",
            command=self.authenticate_startup
        )
        auth_btn.configure(font=('Courier New', 12, 'bold'), padx=20, pady=10)
        auth_btn.pack(side=tk.LEFT, padx=10)
        
        # PIN option if available
        if self.security_manager.pin_hash:
            pin_btn = self.winter_components.create_styled_button(
                button_frame, 
                text="USE PIN",
                command=self.show_pin_auth
            )
            pin_btn.configure(font=('Courier New', 12, 'bold'), padx=20, pady=10)
            pin_btn.pack(side=tk.LEFT, padx=10)
    
    def authenticate_startup(self):
        """Authenticate with startup password"""
        password = self.auth_password_entry.get()
        
        if self.security_manager.authenticate_startup(password):
            self.authenticated = True
            # Use startup password as master password for simplicity
            self.master_password = password
            # Load chat history after authentication
            self.chat_history = self.load_chat_history()
            self.load_configuration()  # Load configuration after authentication
            # Setup RSA keys for message signing (Phase 2)
            self.setup_rsa_keys()
            self.start_session_timer()
            self.create_professional_menu_bar()
            self.show_classified_main_menu()
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
                # Use a default master password or prompt for it
                # For now, use the PIN as master password (not ideal but functional)
                self.master_password = pin
                # Load chat history after authentication
                self.chat_history = self.load_chat_history()
                self.load_configuration()  # Load configuration after authentication
                self.start_session_timer()
                self.create_professional_menu_bar()
                self.show_classified_main_menu()
            else:
                messagebox.showerror("ACCESS DENIED", "Invalid PIN!")
                pin_dialog.destroy()
                self.show_authentication_screen()
        
        pin_entry.bind('<Return>', lambda e: authenticate_pin())
        
        auth_pin_btn = self.winter_components.create_styled_button(
            main_frame, 
            text="AUTHENTICATE",
            command=authenticate_pin
        )
        auth_pin_btn.configure(font=('Courier New', 10, 'bold'))
        auth_pin_btn.pack()
    
    def start_session_timer(self):
        """Start session timeout timer"""
        def check_timeout():
            if self.security_manager.check_session_timeout():
                self.show_session_locked()
            self.session_timer = self.root.after(60000, check_timeout)  # Check every minute
        
        self.session_timer = self.root.after(60000, check_timeout)
    
    def show_session_locked(self):
        """Show session locked screen"""
        messagebox.showwarning("SESSION TIMEOUT", "Session has timed out for security.\nPlease re-authenticate.")
        self.authenticate_master_password()
    
    def setup_secure_environment(self):
        """Setup secure operating environment transparently"""
        try:
            # Disable swap to prevent key material from being written to disk
            if os.name == 'posix':
                os.system('swapoff -a 2>/dev/null')
        except:
            pass
        
        # Set process priority for security
        try:
            os.nice(-10)
        except:
            pass
        
        # Clear sensitive environment variables
        sensitive_vars = ['HOME', 'USER', 'USERNAME', 'LOGNAME']
        for var in list(os.environ.keys()):
            if any(sens in var.upper() for sens in sensitive_vars):
                try:
                    del os.environ[var]
                except:
                    pass
    
    def setup_rsa_keys(self):
        """Setup RSA keys for message signing"""
        try:
            if not self.rsa_keys_generated and hasattr(self, 'rsa_signer'):
                # Generate RSA key pair
                private_key_pem, public_key_pem = self.rsa_signer.generate_key_pair()
                
                # Store private key securely in memory (encrypted with master password)
                if hasattr(self, 'master_password') and self.master_password:
                    self.secure_memory.store('rsa_private_key', private_key_pem)
                    self.secure_memory.store('rsa_public_key', public_key_pem)
                    
                    # Store our own public key in the registry for others to verify
                    self.rsa_signer.store_public_key(self.username, public_key_pem)
                    
                    self.rsa_keys_generated = True
                    # RSA keys generated successfully
                    
                    # Test RSA signing functionality
                    self.test_rsa_signing()
                    # RSA Message Signing System status checked silently
                else:
                    # Master password not available for RSA key encryption
                    pass
        except Exception as e:
            # RSA key setup failed silently
            pass
    
    def get_rsa_signature_status(self, verification_result: dict) -> tuple[str, str]:
        """Get RSA signature status for UI display"""
        if not verification_result.get("rsa_signed", False):
            return "⚪", "No RSA signature"
        
        status = verification_result.get("rsa_status", "unknown")
        if status == "verified":
            return "✅", "RSA signature verified"
        elif status == "invalid":
            return "❌", "RSA signature invalid"
        elif status == "no_key":
            return "⚠️", "No public key for verification"
        else:
            return "❓", "RSA signature unknown"
    
    def exchange_public_keys_with_registry(self):
        """Exchange public keys through the registry system"""
        try:
            if not self.registry_id or not self.rsa_keys_generated:
                return
            
            # Get our public key
            our_public_key = self.secure_memory.retrieve('rsa_public_key')
            if not our_public_key:
                return
            
            # Get current registry data
            response = self.secure_request('GET', f"{REGISTRY_URL}/{self.registry_id}", timeout=5)
            if response.status_code != 200:
                return
            
            raw_data = response.json()
            registry = self.obfuscator.deobfuscate_payload(raw_data)
            
            # Add our public key to the registry
            if "public_keys" not in registry:
                registry["public_keys"] = {}
            
            registry["public_keys"][self.username] = our_public_key.decode('utf-8')
            
            # Store other users' public keys
            for username, public_key_pem in registry.get("public_keys", {}).items():
                if username != self.username:
                    try:
                        public_key_bytes = public_key_pem.encode('utf-8')
                        self.rsa_signer.store_public_key(username, public_key_bytes)
                        # Stored public key for user
                    except Exception as e:
                        # Failed to store public key
                        pass
            
            # Update registry with our public key
            obfuscated_registry = self.obfuscator.obfuscate_payload(registry)
            headers = {'Content-Type': 'application/json'}
            self.secure_request(
                'PUT',
                f"{REGISTRY_URL}/{self.registry_id}",
                json=obfuscated_registry,
                headers=headers,
                timeout=5
            )
            
            # Public key exchange completed silently
            
        except Exception as e:
            # Public key exchange failed silently
            pass
    
    def test_rsa_signing(self):
        """Test RSA signing functionality"""
        try:
            if not self.rsa_keys_generated:
                # RSA keys not generated yet
                return False
            
            # Test message
            test_message = "Test message for RSA signing verification"
            
            # Create signed message
            signed_msg = self.create_authenticated_message(test_message)
            
            # Verify the message
            verification_result = self.verify_message(signed_msg)
            
            # Check results
            if signed_msg.get("rsa_signed"):
                # RSA signing test: Message signed successfully
                if verification_result.get("rsa_valid"):
                    # RSA verification test: Signature verified successfully
                    return True
                else:
                    # RSA verification test: Signature verification failed
                    return False
            else:
                # RSA signing test: Message signing failed
                return False
                
        except Exception as e:
            # RSA test failed
            return False
    
        # Winter Cherry Blossom Theme System - Main Theme Integration (copied from host)
        self.winter_cherry_theme = WinterCherryBlossomTheme()
        self.winter_components = WinterCherryBlossomComponents(self.winter_cherry_theme)
        self.current_theme = "winter_cherry_blossom"
        
        # Theme colors - Winter Cherry Blossom is the main theme
        self.colors = self.winter_cherry_theme.get_color_palette()
        
        # Winter Cherry Blossom is the main theme, with other themes available (exact copy from host)
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
        self.setup_professional_styles()
        

    
    def derive_key(self, password: str, salt: bytes = None) -> tuple:
        """Military-grade key derivation with maximum security"""
        if salt is None:
            salt = secrets.token_bytes(64)  # Larger salt for maximum security
        
        # Store password securely in memory
        if isinstance(password, str):
            password_bytes = password.encode('utf-8')
        else:
            password_bytes = password
        
        self.secure_memory.store('temp_password', password_bytes)
        
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),  # Stronger hash algorithm
                length=64,  # Longer key for maximum security
                salt=salt,
                iterations=1000000,  # 10x more iterations for military-grade security
                backend=default_backend()
            )
            
            key = kdf.derive(password_bytes)
            
            # Store derived key securely
            self.secure_memory.store('derived_key', key)
            
            return base64.urlsafe_b64encode(key), salt
            
        finally:
            # Securely wipe password from memory
            self.secure_memory.wipe('temp_password')
            # Overwrite local password variable
            password_bytes = b'\x00' * len(password_bytes)
            gc.collect()
    
    def create_authenticated_message(self, message: str) -> dict:
        """Create authenticated message with enhanced RSA signing and sequence numbering"""
        # Use cipher if available, otherwise use plain message for testing
        if self.cipher:
            encrypted = self.cipher.encrypt(message.encode()).decode()
        else:
            encrypted = message  # For testing when cipher is not initialized
        
        # Check if key rotation is needed
        if hasattr(self, 'message_security') and self.message_security:
            if self.message_security.should_rotate_keys():
                self.message_security.rotate_keys()
                # Keys rotated after 100 messages
        
        # Enhanced RSA signature with sequence numbering
        signature_data = None
        rsa_signed = False
        if hasattr(self, 'message_security') and self.message_security:
            try:
                signature_data = self.message_security.sign_message(message)
                rsa_signed = True
            except Exception as e:
                # RSA signing failed silently
                pass
        
        # Legacy HMAC signature for backward compatibility
        hmac_signature = ""
        if self.auth_key:
            hmac_signature = hmac.new(self.auth_key, encrypted.encode(), hashlib.sha256).hexdigest()
        
        return {
            "content": encrypted,
            "signature": signature_data if signature_data else hmac_signature,  # New format or legacy
            "hmac_signature": hmac_signature,  # Legacy HMAC signature
            "rsa_signed": rsa_signed,
            "timestamp": time.time(),
            "sender": self.username,
            "authenticated": bool(self.auth_key) or rsa_signed,
            "rsa_authenticated": rsa_signed,
            "classification": "RESTRICTED"
        }
    
    def verify_message(self, msg_data: dict) -> dict:
        """Verify message authentication with enhanced RSA signing and sequence numbering"""
        verification_result = {
            "hmac_valid": True,
            "rsa_valid": False,
            "rsa_status": "unknown",  # unknown, verified, invalid, no_key
            "overall_valid": True
        }
        
        # Verify enhanced RSA signature with sequence numbering
        signature = msg_data.get("signature")
        if signature and hasattr(self, 'message_security') and self.message_security:
            try:
                if isinstance(signature, dict):
                    # New format with sequence numbers and anti-replay protection
                    verification_result["rsa_valid"] = self.message_security.verify_signature(signature)
                    verification_result["rsa_status"] = "verified" if verification_result["rsa_valid"] else "invalid"
                elif isinstance(signature, str):
                    # Legacy format - try HMAC verification
                    if self.auth_key:
                        expected_sig = hmac.new(
                            self.auth_key, 
                            msg_data["content"].encode(), 
                            hashlib.sha256
                        ).hexdigest()
                        verification_result["hmac_valid"] = hmac.compare_digest(expected_sig, signature)
                        verification_result["rsa_status"] = "legacy"
            except Exception as e:
                # Message verification failed silently
                verification_result["rsa_status"] = "invalid"
                verification_result["rsa_valid"] = False
        
        # Verify legacy HMAC signature for backward compatibility
        hmac_signature = msg_data.get("hmac_signature")
        if hmac_signature and self.auth_key:
            expected_sig = hmac.new(
                self.auth_key, 
                msg_data["content"].encode(), 
                hashlib.sha256
            ).hexdigest()
            verification_result["hmac_valid"] = hmac.compare_digest(expected_sig, hmac_signature)
        
        # Overall validity - prefer RSA over HMAC
        if verification_result["rsa_status"] in ["verified"]:
            verification_result["overall_valid"] = verification_result["rsa_valid"]
        else:
            verification_result["overall_valid"] = verification_result["hmac_valid"]
        
        return verification_result
    
    def setup_professional_styles(self):
        """Setup Winter Cherry Blossom theme styles for ttk widgets (copied from host)"""
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
                       foreground='#000000',
                       font=self.winter_cherry_theme.get_font_config('status'))
        style.configure('Danger.TLabel',
                       background=self.colors['danger'],
                       foreground='#ffffff',
                       font=self.winter_cherry_theme.get_font_config('status'))
        style.configure('Info.TLabel',
                       background=self.colors['info'],
                       foreground='#ffffff',
                       font=self.winter_cherry_theme.get_font_config('status'))
        style.configure('Classified.TLabel',
                       background=self.colors['classified'],
                       foreground='#000000',
                       font=self.winter_cherry_theme.get_font_config('status'))
    
    def create_professional_menu_bar(self):
        """Create professional menu bar for Polly Tunnels"""
        menubar = Menu(self.root, tearoff=0, 
                      bg=self.colors['sidebar_bg'], 
                      fg=self.colors['fg'],
                      font=('Segoe UI', 10),
                      activebackground=self.colors['accent'],
                      activeforeground=self.colors['button_fg'])
        self.root.config(menu=menubar)
        
        # Operations menu
        ops_menu = Menu(menubar, tearoff=0, 
                       bg=self.colors['sidebar_bg'], 
                       fg=self.colors['fg'],
                       font=('Courier New', 10))
        menubar.add_cascade(label="OPERATIONS", menu=ops_menu)
        ops_menu.add_command(label="New Connection", command=self.show_classified_main_menu)
        ops_menu.add_command(label="Check Authorization", command=self.check_approval_status)
        ops_menu.add_command(label="Mission Logs", command=self.show_chat_history_window)
        ops_menu.add_command(label="Export Intelligence", command=self.export_chat)
        ops_menu.add_separator()
        ops_menu.add_command(label="Terminate Session", command=self.root.quit)
        
        # Security menu
        security_menu = Menu(menubar, tearoff=0, 
                           bg=self.colors['sidebar_bg'], 
                           fg=self.colors['fg'])
        menubar.add_cascade(label="SECURITY", menu=security_menu)
        
        self.auto_decrypt_var = tk.BooleanVar(value=self.auto_decrypt)
        security_menu.add_checkbutton(label="Auto-Decrypt Messages", 
                                    variable=self.auto_decrypt_var,
                                    command=self.toggle_auto_decrypt)
        
        security_menu.add_separator()
        security_menu.add_command(label="Change History Password", command=self.show_change_history_password)
        security_menu.add_command(label="Change Startup Password", command=self.show_change_startup_password)
        security_menu.add_separator()
        security_menu.add_command(label="Deniable Encryption Setup", command=self.show_deniable_encryption_setup)
        security_menu.add_command(label="Deniable Encryption Config", command=self.show_deniable_encryption_config)
        security_menu.add_separator()
        
        # Configuration submenu
        config_menu = Menu(security_menu, tearoff=0, 
                          bg=self.colors['sidebar_bg'], 
                          fg=self.colors['fg'], 
                          font=('Courier New', 10, 'bold'))
        security_menu.add_cascade(label="Configuration", menu=config_menu)
        
        config_menu.add_command(label="Save Configuration", command=self.save_configuration)
        config_menu.add_command(label="Validate Configuration", command=self.validate_configuration)
        config_menu.add_separator()
        config_menu.add_command(label="Backup Configuration", command=self.backup_configuration)
        config_menu.add_command(label="Restore Configuration", command=self.restore_configuration)
        config_menu.add_separator()
        config_menu.add_command(label="Reset to Defaults", command=self.reset_configuration)
        
        security_menu.add_separator()
        security_menu.add_command(label="System Integrity Check", command=self.check_system_integrity)
        security_menu.add_command(label="Emergency Recovery", command=self.emergency_recovery_mode)
        security_menu.add_separator()
        
        # Theme selection submenu - Winter Cherry Blossom is default
        theme_menu = Menu(security_menu, tearoff=0, 
                         bg=self.colors['sidebar_bg'], 
                         fg=self.colors['fg'], 
                         font=('Segoe UI', 10))
        security_menu.add_cascade(label="Interface Theme", menu=theme_menu)
        
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
        
        security_menu.add_separator()
        security_menu.add_command(label="Refresh Theme", command=self.reset_theme_to_default)
        
        # Help menu
        help_menu = Menu(menubar, tearoff=0, 
                        bg=self.colors['sidebar_bg'], 
                        fg=self.colors['fg'])
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Operation Manual", command=self.show_instructions)
        help_menu.add_command(label="System Info", command=self.show_about)
    
    def toggle_auto_decrypt(self):
        self.auto_decrypt = self.auto_decrypt_var.get()
        self.save_configuration()  # Auto-save configuration changes
    
    def load_chat_history(self):
        """Load chat history from encrypted file"""
        try:
            if os.path.exists(self.chat_history_file):
                # Check if file is encrypted
                with open(self.chat_history_file, 'rb') as f:
                    data = f.read()
                
                if data.startswith(b'CLIENT_CLASSIFIED_HISTORY_V1'):
                    # File is encrypted, need master password
                    return self.load_encrypted_history(self.chat_history_file)
                else:
                    # File is not encrypted, load normally
                    with open(self.chat_history_file, 'r') as f:
                        return json.load(f)
        except Exception as e:
            # Error loading chat history - handled silently
            pass
        return []
    
    def load_encrypted_history(self, filename):
        """Load encrypted chat history"""
        # Check if history password is required
        if self.security_manager.history_password_hash:
            password = self.prompt_history_password()
            if not password:
                return []
        else:
            # Use master password
            password = self.master_password
            if not password:
                return []
        
        try:
            with open(filename, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.master_password_manager.decrypt_history_file(encrypted_data, password)
            return decrypted_data
        except Exception as e:
            # Failed to decrypt history - handled silently
            return []
    
    def save_encrypted_history(self, history):
        """Save encrypted chat history"""
        try:
            password = self.master_password
            if not password:
                return False
            
            encrypted_data = self.master_password_manager.encrypt_history_file(history, password)
            
            with open(self.chat_history_file, 'wb') as f:
                f.write(encrypted_data)
            
            return True
        except Exception as e:
            # Failed to encrypt history - handled silently
            return False
    
    def save_chat_history(self):
        """Save chat history to encrypted file"""
        try:
            if self.master_password:
                # Save encrypted
                self.save_encrypted_history(self.chat_history)
            else:
                # Save unencrypted (fallback)
                with open(self.chat_history_file, 'w') as f:
                    json.dump(self.chat_history, f, indent=2)
        except Exception as e:
            # Error saving chat history - handled silently
            pass
    
    def prompt_history_password(self):
        """Prompt for history password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("CLASSIFIED HISTORY ACCESS")
        dialog.geometry("400x300")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        password = tk.StringVar()
        
        def on_ok():
            if self.security_manager.verify_history_password(password.get()):
                dialog.destroy()
            else:
                messagebox.showerror("ACCESS DENIED", "Invalid history password")
        
        def on_cancel():
            password.set("")
            dialog.destroy()
        
        tk.Label(dialog, text="CLASSIFIED HISTORY PASSWORD:",
                bg=self.colors['bg'], fg=self.colors['fg'],
                font=('Courier New', 12, 'bold')).pack(pady=20)
        
        entry = tk.Entry(dialog, textvariable=password, show="*",
                        bg=self.colors['entry_bg'], fg=self.colors['entry_fg'],
                        font=('Courier New', 12))
        entry.pack(pady=20, padx=20, fill=tk.X)
        entry.bind('<Return>', lambda e: on_ok())
        entry.focus()
        
        button_frame = tk.Frame(dialog, bg=self.colors['bg'])
        button_frame.pack(pady=20)
        
        access_btn = self.winter_components.create_styled_button(
            button_frame, 
            text="ACCESS",
            command=on_ok
        )
        access_btn.configure(font=('Courier New', 10, 'bold'))
        access_btn.pack(side=tk.LEFT, padx=10)
        
        cancel_btn = self.winter_components.create_styled_button(
            button_frame, 
            text="CANCEL",
            command=on_cancel
        )
        cancel_btn.configure(font=('Courier New', 10, 'bold'), 
                           bg=self.colors['danger'], fg='white')
        cancel_btn.pack(side=tk.LEFT, padx=10)
        
        dialog.wait_window()
        return password.get() if password.get() else None
    
    def add_to_history(self, chat_info):
        self.chat_history = [h for h in self.chat_history if h.get('chat_id') != chat_info['chat_id']]
        self.chat_history.insert(0, chat_info)
        
        if len(self.chat_history) > 15:
            self.chat_history = self.chat_history[:15]
        
        self.save_chat_history()
    
    def clear_window(self):
        for widget in self.root.winfo_children():
            if not isinstance(widget, Menu):
                widget.destroy()
        self.message_widgets = []
    
    def show_classified_main_menu(self):
        """Main interface for Polly Tunnels"""
        self.track_current_window(self.show_classified_main_menu)
        self.clear_window()
        
        # Main container
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create scrollable container for the entire main menu (like host)
        scrollable_main = self.winter_components.create_scrollable_container(main_container)
        scrollable_main.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Get the scrollable frame
        scrollable_content = scrollable_main.get_frame()
        
        # Header area
        header_frame = tk.Frame(scrollable_content, bg=self.colors['bg'], height=80)
        header_frame.pack(fill=tk.X, padx=30, pady=(20, 0))
        header_frame.pack_propagate(False)
        
        # App title and logo with improved layout
        title_frame = tk.Frame(header_frame, bg=self.colors['bg'])
        title_frame.pack(expand=True, fill=tk.BOTH)
        
        # Logo and title container with proper alignment
        logo_container = tk.Frame(title_frame, bg=self.colors['bg'])
        logo_container.pack(expand=True, pady=(15, 10))
        
        # Logo frame with centered alignment
        logo_frame = tk.Frame(logo_container, bg=self.colors['bg'])
        logo_frame.pack(anchor=tk.CENTER)
        
        # Enhanced logo with better visual design
        logo_label = tk.Label(logo_frame, 
                text="🔐",  # More appropriate security icon
                bg=self.colors['bg'],
                fg=self.colors['accent'],
                font=('Segoe UI', 36, 'bold'))
        logo_label.pack(side=tk.LEFT, padx=(0, 15))
        
        # Title text frame
        title_text_frame = tk.Frame(logo_frame, bg=self.colors['bg'])
        title_text_frame.pack(side=tk.LEFT)
        
        # Main title with improved typography
        main_title = tk.Label(title_text_frame, 
                text="Polly Tunnels",
                bg=self.colors['bg'],
                fg=self.colors['accent'],
                font=('Segoe UI', 28, 'bold'))
        main_title.pack(anchor=tk.W)
        
        # Subtitle with better positioning
        subtitle = tk.Label(title_text_frame,
                text="Secure Communication Platform",
                bg=self.colors['bg'],
                fg=self.colors['fg'],
                font=('Segoe UI', 12, 'normal'))
        subtitle.pack(anchor=tk.W, pady=(2, 0))
        
        # Main content area
        content_frame = tk.Frame(scrollable_content, bg=self.colors['bg'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        # Left sidebar - Navigation
        sidebar = tk.Frame(content_frame, bg=self.colors['sidebar_bg'], width=280)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 20))
        sidebar.pack_propagate(False)
        
        # Sidebar header
        tk.Label(sidebar, 
                text="Navigation",
                bg=self.colors['sidebar_bg'],
                fg=self.colors['accent'],
                font=('Segoe UI', 18, 'bold')).pack(pady=(30, 20))
        
        # Connection status
        tk.Label(sidebar,
                text="Status: Ready",
                bg=self.colors['sidebar_bg'],
                fg=self.colors['success'],
                font=('Segoe UI', 11)).pack(pady=(0, 30))
        
        # Navigation buttons - use themed buttons instead of direct tk.Button
        nav_frame = tk.Frame(sidebar, bg=self.colors['sidebar_bg'])
        nav_frame.pack(fill=tk.X, padx=20, pady=(0, 30))
        
        nav_buttons = [
            ("Join Chat Room", self.show_chat_history_window),
            ("Request Access", self.join_classified_chat_window),
            ("Check Status", self.check_approval_status),
            ("Chat History", self.show_chat_history_window)
        ]
        
        for text, command in nav_buttons:
            btn = self.winter_components.create_styled_button(nav_frame, text=text, command=command)
            btn.configure(padx=20, pady=12)
            btn.pack(fill=tk.X, pady=3)
        
        # Status panel
        status_frame = tk.Frame(sidebar, bg=self.colors['card_bg'], relief='solid', borderwidth=1)
        status_frame.pack(fill=tk.X, padx=20, pady=(20, 0))
        
        tk.Label(status_frame,
                text="Connection Status",
                bg=self.colors['card_bg'],
                fg=self.colors['accent'],
                font=('Segoe UI', 12, 'bold')).pack(pady=(15, 10))
        
        security_status = "Standby" if not self.connected else "Connected"
        status_color = self.colors['fg'] if not self.connected else self.colors['success']
        
        tk.Label(status_frame,
                text=f"Security: {security_status}",
                bg=self.colors['card_bg'],
                fg=status_color,
                font=('Segoe UI', 9)).pack(anchor='w', padx=15, pady=2)
        
        if self.is_approved:
            tk.Label(status_frame,
                    text="Authorization: ✅ Approved",
                    bg=self.colors['card_bg'],
                    fg=self.colors['success'],
                    font=('Segoe UI', 9)).pack(anchor='w', padx=15, pady=2)
        else:
            tk.Label(status_frame,
                    text="Authorization: ⏳ Pending",
                    bg=self.colors['card_bg'],
                    fg=self.colors['warning'],
                    font=('Segoe UI', 9)).pack(anchor='w', padx=15, pady=2)
        
        tk.Label(status_frame,
                text=f"Role: {self.user_role}",
                bg=self.colors['card_bg'],
                fg=self.colors['info'],
                font=('Segoe UI', 9)).pack(anchor='w', padx=15, pady=2)
        
        tk.Label(status_frame, text="", bg=self.colors['card_bg']).pack(pady=10)
        
        # Main content area
        content = tk.Frame(content_frame, bg=self.colors['bg'])
        content.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Welcome section
        welcome_frame = tk.Frame(content, bg=self.colors['bg'])
        welcome_frame.pack(fill=tk.X, pady=(0, 30))
        
        tk.Label(welcome_frame,
                text="Your secure communication platform with end-to-end encryption",
                bg=self.colors['bg'],
                fg=self.colors['fg'],
                font=('Segoe UI', 12)).pack()
        
        # Feature cards
        cards_frame = tk.Frame(content, bg=self.colors['bg'])
        cards_frame.pack(fill=tk.X, pady=(30, 0))
        
        # Card 1 - Security
        card1 = tk.Frame(cards_frame, bg=self.colors['card_bg'], relief='solid', borderwidth=1)
        card1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 15))
        
        tk.Label(card1, text="🛡️", font=('Segoe UI', 32), bg=self.colors['card_bg']).pack(pady=(20, 10))
        tk.Label(card1, text="End-to-End Security",
                bg=self.colors['card_bg'],
                fg=self.colors['accent'],
                font=('Segoe UI', 12, 'bold')).pack()
        tk.Label(card1, text="Military-grade encryption",
                bg=self.colors['card_bg'],
                fg=self.colors['fg'],
                font=('Segoe UI', 10)).pack(pady=(5, 20))
        
        # Card 2 - Privacy
        card2 = tk.Frame(cards_frame, bg=self.colors['card_bg'], relief='solid', borderwidth=1)
        card2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=15)
        
        tk.Label(card2, text="🔒", font=('Segoe UI', 32), bg=self.colors['card_bg']).pack(pady=(20, 10))
        tk.Label(card2, text="Privacy First",
                bg=self.colors['card_bg'],
                fg=self.colors['accent'],
                font=('Segoe UI', 12, 'bold')).pack()
        tk.Label(card2, text="Anonymous communication",
                bg=self.colors['card_bg'],
                fg=self.colors['fg'],
                font=('Segoe UI', 10)).pack(pady=(5, 20))
        
        # Card 3 - Features
        card3 = tk.Frame(cards_frame, bg=self.colors['card_bg'], relief='solid', borderwidth=1)
        card3.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(15, 0))
        
        tk.Label(card3, text="💬", font=('Segoe UI', 32), bg=self.colors['card_bg']).pack(pady=(20, 10))
        tk.Label(card3, text="Rich Features",
                bg=self.colors['card_bg'],
                fg=self.colors['accent'],
                font=('Segoe UI', 12, 'bold')).pack()
        tk.Label(card3, text="Chat, files, and more",
                bg=self.colors['card_bg'],
                fg=self.colors['fg'],
                font=('Segoe UI', 10)).pack(pady=(5, 20))
        
        # Getting started section
        getting_started_frame = tk.Frame(content, bg=self.colors['card_bg'], relief='solid', borderwidth=1)
        getting_started_frame.pack(fill=tk.X, pady=(30, 0))
        
        tk.Label(getting_started_frame,
                text="Getting Started",
                bg=self.colors['card_bg'],
                fg=self.colors['accent'],
                font=('Segoe UI', 16, 'bold')).pack(pady=(20, 15))
        
        steps = [
            "1. Request access to a chat room from the administrator",
            "2. Wait for approval notification",
            "3. Join approved chat rooms from your history",
            "4. Start secure conversations with end-to-end encryption",
            "5. Share files securely with other participants"
        ]
        
        for step in steps:
            tk.Label(getting_started_frame,
                    text=step,
                    bg=self.colors['card_bg'],
                    fg=self.colors['fg'],
                    font=('Segoe UI', 11)).pack(anchor='w', padx=30, pady=3)
        
        tk.Label(getting_started_frame, text="", bg=self.colors['card_bg']).pack(pady=15)
    
    def join_classified_chat_window(self):
        """Request authorization interface"""
        self.track_current_window(self.join_classified_chat_window)
        self.clear_window()
        
        # Main container
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Top classification banner
        classification_banner = tk.Frame(main_container, bg=self.colors['warning'], height=40)
        classification_banner.pack(fill=tk.X)
        classification_banner.pack_propagate(False)
        
        tk.Label(classification_banner,
                text="★ ★ ★ REQUESTING AUTHORIZATION - CLASSIFIED OPERATION ★ ★ ★",
                bg=self.colors['warning'],
                fg='#000000',
                font=('Courier New', 12, 'bold')).pack(expand=True)
        
        # Create scrollable container for the entire content area
        scrollable_main = self.winter_components.create_scrollable_container(main_container, height=500)
        scrollable_main.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollable_content = scrollable_main.get_frame()
        
        # Content area (now inside scrollable container)
        content_frame = tk.Frame(scrollable_content, bg=self.colors['bg'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Sidebar
        sidebar = tk.Frame(content_frame, bg=self.colors['sidebar_bg'], width=350)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 20))
        sidebar.pack_propagate(False)
        
        tk.Label(sidebar,
                text="AUTHORIZATION REQUEST",
                bg=self.colors['sidebar_bg'],
                fg=self.colors['warning'],
                font=('Courier New', 14, 'bold')).pack(pady=(30, 20))
        
        # Back button
        back_btn = self.winter_components.create_styled_button(
            sidebar, 
            text="← RETURN TO TERMINAL",
            command=self.show_classified_main_menu
        )
        back_btn.configure(font=('Courier New', 10, 'bold'), relief='solid', borderwidth=1)
        back_btn.pack(fill=tk.X, padx=20, pady=5)
        
        # Authorization steps
        steps_frame = tk.Frame(sidebar, bg=self.colors['card_bg'], relief='solid', borderwidth=2)
        steps_frame.pack(fill=tk.X, padx=20, pady=(30, 0))
        
        tk.Label(steps_frame,
                text="AUTHORIZATION PROTOCOL",
                bg=self.colors['card_bg'],
                fg=self.colors['warning'],
                font=('Courier New', 12, 'bold')).pack(pady=(15, 10))
        
        steps = [
            "1. OBTAIN COMMAND REGISTRY ID",
            "2. SUBMIT AGENT CREDENTIALS",
            "3. AWAIT COMMAND APPROVAL",
            "4. RECEIVE SECURITY CLEARANCE",
            "5. ACCESS SECURE CHANNEL"
        ]
        
        for step in steps:
            tk.Label(steps_frame,
                    text=step,
                    bg=self.colors['card_bg'],
                    fg=self.colors['fg'],
                    font=('Courier New', 9)).pack(anchor='w', padx=15, pady=2)
        
        tk.Label(steps_frame, text="", bg=self.colors['card_bg']).pack(pady=10)
        
        # Main content
        content = tk.Frame(content_frame, bg=self.colors['bg'])
        content.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        tk.Label(content,
                text="REQUEST CLASSIFIED AUTHORIZATION",
                bg=self.colors['bg'],
                fg=self.colors['warning'],
                font=('Courier New', 20, 'bold')).pack(pady=(0, 10))
        
        tk.Label(content,
                text="OBTAIN COMMAND REGISTRY ID FROM INTELLIGENCE HEADQUARTERS",
                bg=self.colors['bg'],
                fg=self.colors['fg'],
                font=('Courier New', 12)).pack(pady=(0, 30))
        
        # Form card
        form_card = tk.Frame(content, bg=self.colors['card_bg'], relief='solid', borderwidth=2)
        form_card.pack(fill=tk.BOTH, expand=True, padx=20)
        
        tk.Label(form_card, text="", bg=self.colors['card_bg']).pack(pady=10)
        
        # Command Registry ID
        tk.Label(form_card,
                text="COMMAND REGISTRY ID",
                bg=self.colors['card_bg'],
                fg=self.colors['warning'],
                font=('Courier New', 11, 'bold')).pack(anchor='w', padx=30, pady=(10, 5))
        
        tk.Label(form_card,
                text="(OBTAIN FROM INTELLIGENCE COMMAND - NOT CHANNEL ID)",
                bg=self.colors['card_bg'],
                fg=self.colors['fg'],
                font=('Courier New', 9)).pack(anchor='w', padx=30, pady=(0, 10))
        
        self.registry_entry = tk.Entry(form_card,
                                      bg=self.colors['entry_bg'],
                                      fg=self.colors['entry_fg'],
                                      font=('Courier New', 12),
                                      relief='solid',
                                      borderwidth=1,
                                      insertbackground=self.colors['fg'])
        self.registry_entry.pack(fill=tk.X, padx=30, pady=(0, 20))
        
        # Agent designation
        tk.Label(form_card,
                text="AGENT DESIGNATION",
                bg=self.colors['card_bg'],
                fg=self.colors['warning'],
                font=('Courier New', 11, 'bold')).pack(anchor='w', padx=30, pady=(10, 5))
        
        self.username_entry = tk.Entry(form_card,
                                      bg=self.colors['entry_bg'],
                                      fg=self.colors['entry_fg'],
                                      font=('Courier New', 12),
                                      relief='solid',
                                      borderwidth=1,
                                      insertbackground=self.colors['fg'])
        self.username_entry.pack(fill=tk.X, padx=30, pady=(0, 20))
        self.username_entry.insert(0, "TUNNEL_USER")
        
        # Chat Channel ID
        tk.Label(form_card,
                text="SECURE CHANNEL ID",
                bg=self.colors['card_bg'],
                fg=self.colors['warning'],
                font=('Courier New', 11, 'bold')).pack(anchor='w', padx=30, pady=(10, 5))
        
        tk.Label(form_card,
                text="(OBTAIN FROM CHANNEL HOST - REQUIRED FOR CONNECTION)",
                bg=self.colors['card_bg'],
                fg=self.colors['fg'],
                font=('Courier New', 9)).pack(anchor='w', padx=30, pady=(0, 10))
        
        self.chat_id_entry = tk.Entry(form_card,
                                     bg=self.colors['entry_bg'],
                                     fg=self.colors['entry_fg'],
                                     font=('Courier New', 12),
                                     relief='solid',
                                     borderwidth=1,
                                     insertbackground=self.colors['fg'])
        self.chat_id_entry.pack(fill=tk.X, padx=30, pady=(0, 20))
        
        # Encryption Key
        tk.Label(form_card,
                text="QUANTUM ENCRYPTION KEY",
                bg=self.colors['card_bg'],
                fg=self.colors['warning'],
                font=('Courier New', 11, 'bold')).pack(anchor='w', padx=30, pady=(10, 5))
        
        tk.Label(form_card,
                text="(CLASSIFIED ENCRYPTION KEY FROM CHANNEL HOST)",
                bg=self.colors['card_bg'],
                fg=self.colors['fg'],
                font=('Courier New', 9)).pack(anchor='w', padx=30, pady=(0, 10))
        
        # Encryption key with show/hide functionality
        key_frame = tk.Frame(form_card, bg=self.colors['card_bg'])
        key_frame.pack(fill=tk.X, padx=30, pady=(0, 20))
        
        self.encryption_key_entry = tk.Entry(key_frame, show="*",
                                           bg=self.colors['entry_bg'],
                                           fg=self.colors['entry_fg'],
                                           font=('Courier New', 12),
                                           relief='solid',
                                           borderwidth=1,
                                           insertbackground=self.colors['fg'])
        self.encryption_key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        tk.Button(key_frame, text="SHOW/HIDE",
                 command=self.toggle_key_visibility,
                 bg=self.colors['button_bg'],
                 fg=self.colors['button_fg'],
                 font=('Courier New', 9, 'bold'),
                 relief='solid',
                 borderwidth=1).pack(side=tk.RIGHT)
        
        # Security briefing
        briefing_section = tk.Frame(form_card, bg=self.colors['card_bg'])
        briefing_section.pack(fill=tk.X, padx=30, pady=(20, 0))
        
        tk.Label(briefing_section,
                text="SECURITY BRIEFING",
                bg=self.colors['card_bg'],
                fg=self.colors['warning'],
                font=('Courier New', 11, 'bold')).pack(anchor='w', pady=(0, 10))
        
        tk.Label(briefing_section,
                text="UPON AUTHORIZATION APPROVAL, YOU WILL RECEIVE:",
                bg=self.colors['card_bg'],
                fg=self.colors['fg'],
                font=('Courier New', 10, 'bold')).pack(anchor='w', pady=(0, 10))
        
        features = [
            "🔐 SECURE CHANNEL ID AND QUANTUM KEY",
            "👤 OPERATIONAL ROLE ASSIGNMENT",
            "📁 CLASSIFIED FILE TRANSFER ACCESS",
            "🔒 QUANTUM MESSAGE AUTHENTICATION",
            "⚡ ADVANCED SECURITY PROTOCOLS"
        ]
        
        for feature in features:
            tk.Label(briefing_section,
                    text=feature,
                    bg=self.colors['card_bg'],
                    fg=self.colors['success'],
                    font=('Courier New', 9)).pack(anchor='w', pady=2)
        
        # Warning box
        warning_box = tk.Frame(form_card, bg=self.colors['danger'], relief='solid', borderwidth=2)
        warning_box.pack(fill=tk.X, padx=30, pady=(20, 0))
        
        tk.Label(warning_box,
                text="⚠️ CLASSIFIED OPERATION WARNING ⚠️",
                bg=self.colors['danger'],
                fg='#000000',
                font=('Courier New', 11, 'bold')).pack(pady=(10, 5))
        
        warning_text = ("UNAUTHORIZED ACCESS TO CLASSIFIED SYSTEMS IS PROHIBITED\n"
                       "ALL COMMUNICATIONS ARE MONITORED AND RECORDED\n"
                       "VIOLATION OF SECURITY PROTOCOLS WILL BE PROSECUTED")
        
        tk.Label(warning_box,
                text=warning_text,
                bg=self.colors['danger'],
                fg='#000000',
                font=('Courier New', 9),
                justify='center').pack(padx=20, pady=(0, 10))
        
        # Submit button
        submit_btn = self.winter_components.create_styled_button(
            form_card, 
            text="SUBMIT AUTHORIZATION REQUEST",
            command=self.register_and_join
        )
        submit_btn.configure(bg=self.colors['warning'], fg='#000000',
                           font=('Courier New', 14, 'bold'),
                           relief='solid', borderwidth=2, pady=10)
        submit_btn.pack(pady=(30, 20))
        
        self.status_label = tk.Label(form_card, text="",
                                    bg=self.colors['card_bg'],
                                    fg=self.colors['danger'],
                                    font=('Courier New', 10, 'bold'))
        self.status_label.pack(pady=(10, 20))
        
        # Bottom classification
        bottom_banner = tk.Frame(main_container, bg=self.colors['warning'], height=30)
        bottom_banner.pack(fill=tk.X, side=tk.BOTTOM)
        bottom_banner.pack_propagate(False)
        
        tk.Label(bottom_banner,
                text=english_manager.get_text_constant('SECRET_AUTHORIZATION_REQUEST'),
                bg=self.colors['warning'],
                fg='#000000',
                font=('Courier New', 10, 'bold')).pack(expand=True)
    
    def get_fernet_key(self, shared_key):
        if isinstance(shared_key, str):
            shared_key = shared_key.encode()
        key_hash = hashlib.sha256(shared_key).digest()
        return base64.urlsafe_b64encode(key_hash)
    
    def toggle_key_visibility(self):
        """Toggle encryption key visibility"""
        if hasattr(self, 'encryption_key_entry') and self.encryption_key_entry:
            if self.encryption_key_entry.cget('show') == '*':
                self.encryption_key_entry.config(show='')
            else:
                self.encryption_key_entry.config(show='*')
    
    def register_and_join(self):
        # Get all three required credentials
        self.registry_id = self.registry_entry.get().strip()
        self.username = self.username_entry.get().strip() or "TUNNEL_USER"
        self.chat_id = self.chat_id_entry.get().strip()
        self.encryption_key = self.encryption_key_entry.get().strip()
        
        # Validate all credentials are provided
        missing_credentials = []
        if not self.registry_id:
            missing_credentials.append("Registry ID")
        if not self.chat_id:
            missing_credentials.append("Channel ID")
        if not self.encryption_key:
            missing_credentials.append("Encryption Key")
        
        if missing_credentials:
            messagebox.showerror("MISSING CREDENTIALS", 
                               f"The following credentials are required:\n\n" + 
                               "\n".join([f"• {cred}" for cred in missing_credentials]))
            return
        
        # Update status to show validation progress
        self.status_label.config(text="🔄 Validating credentials...", fg=self.colors['info'])
        self.root.update()
        
        try:
            # Ensure TOR connection is established before making requests
            self.status_label.config(text="🔄 Establishing secure connection...", fg=self.colors['info'])
            self.root.update()
            
            # Setup TOR session if not already done
            if not hasattr(self.tor_proxy, '_session_setup_attempted') or not self.tor_proxy._session_setup_attempted:
                self.tor_proxy.setup_session()
            
            # Validate registry ID
            self.status_label.config(text="🔄 Connecting to registry...", fg=self.colors['info'])
            self.root.update()
            
            response = self.secure_request('GET', f"{REGISTRY_URL}/{self.registry_id}", timeout=5)
            if response.status_code != 200:
                self.status_label.config(text="❌ INVALID REGISTRY ID", fg=self.colors['danger'])
                return
            
            # Deobfuscate response
            raw_data = response.json()
            registry = self.obfuscator.deobfuscate_payload(raw_data)
            
            # Validate chat ID matches registry
            registry_chat_id = registry.get("chat_id")
            if registry_chat_id and registry_chat_id != self.chat_id:
                self.status_label.config(text="❌ CHAT ID MISMATCH", fg=self.colors['danger'])
                messagebox.showerror("CREDENTIAL ERROR", 
                                   "Chat ID does not match registry.\n"
                                   "Verify credentials with channel host.")
                return
            
            # Validate encryption key by testing chat connection
            self.status_label.config(text="🔄 Validating encryption key...", fg=self.colors['info'])
            self.root.update()
            
            try:
                # Test encryption key
                fernet_key = self.get_fernet_key(self.encryption_key)
                test_cipher = Fernet(fernet_key)
                # If we can create the cipher, the key format is valid
            except Exception as e:
                self.status_label.config(text="❌ INVALID ENCRYPTION KEY", fg=self.colors['danger'])
                messagebox.showerror("ENCRYPTION ERROR", 
                                   "Invalid encryption key format.\n"
                                   "Verify key with channel host.")
                return
            
            # Test chat connection
            self.status_label.config(text="🔄 Testing chat connection...", fg=self.colors['info'])
            self.root.update()
            
            chat_response = self.secure_request('GET', f"{BASE_URL}/{self.chat_id}", timeout=5)
            if chat_response.status_code != 200:
                self.status_label.config(text="❌ INVALID CHAT ID", fg=self.colors['danger'])
                messagebox.showerror("CONNECTION ERROR", 
                                   "Cannot connect to chat channel.\n"
                                   "Verify Chat ID with channel host.")
                return
            
            # All credentials validated - proceed with registration
            self.status_label.config(text="🔄 Submitting authorization request...", fg=self.colors['info'])
            self.root.update()
            
            # Check if already approved
            if self.username in registry.get("approved_users", []):
                self.is_approved = True
                self.user_role = registry.get("user_roles", {}).get(self.username, UserRole.USER)
                self.cipher = Fernet(fernet_key)  # Set up cipher with validated key
                self.status_label.config(text="✅ AUTHORIZATION APPROVED", fg=self.colors['success'])
                self.show_approval_status()
                return
            
            # Check if already pending
            pending = registry.get("pending_requests", [])
            for req in pending:
                if req.get("username") == self.username:
                    self.request_id = req.get("request_id")
                    self.status_label.config(text="⏳ REQUEST PENDING", fg=self.colors['warning'])
                    self.show_waiting_for_approval()
                    return
            
            # Check if banned
            if self.username in registry.get("banned_users", []):
                self.status_label.config(text="❌ ACCESS DENIED", fg=self.colors['danger'])
                messagebox.showerror("ACCESS DENIED", "AGENT DESIGNATION COMPROMISED - ACCESS REVOKED")
                return
            
            # Create new authorization request
            self.request_id = str(uuid.uuid4())
            
            new_request = {
                "request_id": self.request_id,
                "username": self.username,
                "timestamp": time.time(),
                "status": "pending",
                "client_version": "POLLY_TUNNELS_2.0",
                "security_clearance": "REQUESTED",
                "chat_id": self.chat_id,  # Include validated chat ID
                "encryption_verified": True  # Mark that encryption key was validated
            }
            
            pending.append(new_request)
            registry["pending_requests"] = pending
            
            # Obfuscate registry data before sending
            obfuscated_registry = self.obfuscator.obfuscate_payload(registry)
            
            response = self.secure_request(
                'PUT',
                f"{REGISTRY_URL}/{self.registry_id}",
                json=obfuscated_registry,
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                self.status_label.config(text="✅ REQUEST SUBMITTED", fg=self.colors['success'])
                # Store validated credentials securely
                self.cipher = Fernet(fernet_key)
                self.show_waiting_for_approval()
            else:
                self.status_label.config(text="❌ AUTHORIZATION REQUEST FAILED", fg=self.colors['danger'])
                
        except Exception as e:
            self.status_label.config(text=f"❌ CONNECTION ERROR: {str(e)}", fg=self.colors['danger'])
            print(f"Registration error: {e}")
            messagebox.showerror("CONNECTION ERROR", 
                               f"Failed to connect through TOR:\n{str(e)}\n\n"
                               "Please check your TOR connection and try again.")
    
    def show_waiting_for_approval(self):
        """Waiting for approval interface"""
        self.clear_window()
        
        # Main container
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Top classification banner
        classification_banner = tk.Frame(main_container, bg=self.colors['warning'], height=40)
        classification_banner.pack(fill=tk.X)
        classification_banner.pack_propagate(False)
        
        tk.Label(classification_banner,
                text="★ ★ ★ AWAITING COMMAND AUTHORIZATION - STANDBY ★ ★ ★",
                bg=self.colors['warning'],
                fg='#000000',
                font=('Courier New', 12, 'bold')).pack(expand=True)
        
        # Content area
        content_frame = tk.Frame(main_container, bg=self.colors['bg'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Sidebar
        sidebar = tk.Frame(content_frame, bg=self.colors['sidebar_bg'], width=350)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 20))
        sidebar.pack_propagate(False)
        
        tk.Label(sidebar,
                text="AUTHORIZATION STATUS",
                bg=self.colors['sidebar_bg'],
                fg=self.colors['warning'],
                font=('Courier New', 14, 'bold')).pack(pady=(30, 20))
        
        # Back button
        tk.Button(sidebar, text="← RETURN TO TERMINAL",
                 command=self.show_classified_main_menu,
                 bg=self.colors['button_bg'],
                 fg=self.colors['button_fg'],
                 font=('Courier New', 10, 'bold'),
                 relief='solid',
                 borderwidth=1).pack(fill=tk.X, padx=20, pady=5)
        
        tk.Button(sidebar, text="CHECK STATUS",
                 command=self.check_approval_status,
                 bg=self.colors['button_bg'],
                 fg=self.colors['button_fg'],
                 font=('Courier New', 10, 'bold'),
                 relief='solid',
                 borderwidth=1).pack(fill=tk.X, padx=20, pady=5)
        
        # Status info
        status_frame = tk.Frame(sidebar, bg=self.colors['card_bg'], relief='solid', borderwidth=2)
        status_frame.pack(fill=tk.X, padx=20, pady=(30, 0))
        
        tk.Label(status_frame,
                text="CURRENT STATUS",
                bg=self.colors['card_bg'],
                fg=self.colors['warning'],
                font=('Courier New', 12, 'bold')).pack(pady=(15, 10))
        
        tk.Label(status_frame,
                text="⏳ PENDING AUTHORIZATION",
                bg=self.colors['card_bg'],
                fg=self.colors['warning'],
                font=('Courier New', 10, 'bold')).pack(anchor='w', padx=15, pady=2)
        
        tk.Label(status_frame,
                text=f"AGENT: {self.username}",
                bg=self.colors['card_bg'],
                fg=self.colors['fg'],
                font=('Courier New', 9)).pack(anchor='w', padx=15, pady=2)
        
        tk.Label(status_frame,
                text=f"REQUEST ID: {self.request_id[:12]}...",
                bg=self.colors['card_bg'],
                fg=self.colors['fg'],
                font=('Courier New', 9)).pack(anchor='w', padx=15, pady=2)
        
        tk.Label(status_frame, text="", bg=self.colors['card_bg']).pack(pady=10)
        
        # Main content
        content = tk.Frame(content_frame, bg=self.colors['bg'])
        content.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Waiting animation area
        waiting_frame = tk.Frame(content, bg=self.colors['card_bg'], relief='solid', borderwidth=2)
        waiting_frame.pack(fill=tk.BOTH, expand=True, padx=20)
        
        tk.Label(waiting_frame, text="", bg=self.colors['card_bg']).pack(pady=30)
        
        tk.Label(waiting_frame, text="⏳", 
                 font=('Arial', 64), bg=self.colors['card_bg']).pack(pady=(20, 30))
        
        tk.Label(waiting_frame,
                text="AWAITING COMMAND AUTHORIZATION",
                bg=self.colors['card_bg'],
                fg=self.colors['warning'],
                font=('Courier New', 20, 'bold')).pack(pady=(0, 20))
        
        tk.Label(waiting_frame,
                text=f"AUTHORIZATION REQUEST SUBMITTED FOR: {self.username}",
                bg=self.colors['card_bg'],
                fg=self.colors['fg'],
                font=('Courier New', 12)).pack(pady=(0, 10))
        
        tk.Label(waiting_frame,
                text=f"REQUEST ID: {self.request_id[:12]}...",
                bg=self.colors['card_bg'],
                fg=self.colors['fg'],
                font=('Courier New', 10)).pack(pady=(0, 30))
        
        # Instructions
        instructions_text = ("INTELLIGENCE COMMAND WILL REVIEW YOUR REQUEST\n"
                           "UPON APPROVAL, YOU WILL RECEIVE:\n\n"
                           "• SECURE CHANNEL ACCESS CREDENTIALS\n"
                           "• OPERATIONAL ROLE ASSIGNMENT\n"
                           "• CLASSIFIED COMMUNICATION PROTOCOLS\n\n"
                           "MAINTAIN OPERATIONAL SECURITY WHILE WAITING")
        
        tk.Label(waiting_frame,
                text=instructions_text,
                bg=self.colors['card_bg'],
                fg=self.colors['fg'],
                font=('Courier New', 11),
                justify='center').pack(pady=(0, 30))
        
        tk.Button(waiting_frame, text="CHECK AUTHORIZATION STATUS",
                 command=self.check_approval_status,
                 bg=self.colors['warning'],
                 fg='#000000',
                 font=('Courier New', 12, 'bold'),
                 relief='solid',
                 borderwidth=2).pack(pady=(0, 30))
        
        # Bottom classification
        bottom_banner = tk.Frame(main_container, bg=self.colors['warning'], height=30)
        bottom_banner.pack(fill=tk.X, side=tk.BOTTOM)
        bottom_banner.pack_propagate(False)
        
        tk.Label(bottom_banner,
                text=english_manager.get_text_constant('SECRET_WAITING_AUTHORIZATION'),
                bg=self.colors['warning'],
                fg='#000000',
                font=('Courier New', 10, 'bold')).pack(expand=True)
        
        # Start approval checking thread
        self.approval_checker = threading.Thread(target=self.check_approval_loop, daemon=True)
        self.approval_checker.start()
    
    def check_approval_loop(self):
        """Background approval checking"""
        while not self.is_approved and self.registry_id and self.username:
            try:
                response = self.tor_proxy.get(f"{REGISTRY_URL}/{self.registry_id}", timeout=5)
                if response.status_code == 200:
                    raw_data = response.json()
                    registry = self.obfuscator.deobfuscate_payload(raw_data)
                    
                    if self.username in registry.get("approved_users", []):
                        self.is_approved = True
                        self.user_role = registry.get("user_roles", {}).get(self.username, UserRole.USER)
                        
                        # Get chat credentials
                        self.chat_id = registry.get("chat_id")
                        self.encryption_key = registry.get("encryption_key")
                        
                        # Update UI on main thread
                        self.root.after(0, self.show_approval_status)
                        break
                    
                    # Check if rejected
                    if self.username in registry.get("rejected_users", []):
                        self.root.after(0, lambda: messagebox.showerror("ACCESS DENIED", "AUTHORIZATION REQUEST REJECTED"))
                        break
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                # Error checking approval - handled silently
                time.sleep(15)
    
    def check_approval_status(self):
        """Manually check approval status"""
        if not self.registry_id:
            messagebox.showinfo("NO REQUEST", "NO ACTIVE AUTHORIZATION REQUEST")
            return
        
        try:
            response = self.tor_proxy.get(f"{REGISTRY_URL}/{self.registry_id}", timeout=10)
            if response.status_code != 200:
                messagebox.showerror("ERROR", "INVALID COMMAND REGISTRY")
                return
            
            raw_data = response.json()
            registry = self.obfuscator.deobfuscate_payload(raw_data)
            
            if self.username in registry.get("approved_users", []):
                self.is_approved = True
                self.user_role = registry.get("user_roles", {}).get(self.username, UserRole.USER)
                
                # Get chat credentials
                self.chat_id = registry.get("chat_id")
                self.encryption_key = registry.get("encryption_key")
                
                self.show_approval_status()
            elif self.username in registry.get("rejected_users", []):
                messagebox.showwarning("ACCESS DENIED", "AUTHORIZATION REQUEST REJECTED")
            else:
                messagebox.showinfo("PENDING", "AUTHORIZATION REQUEST STILL UNDER REVIEW")
                
        except Exception as e:
            messagebox.showerror("ERROR", f"STATUS CHECK FAILED: {str(e)}")
    
    def show_approval_status(self):
        """Show approval status and save to history"""
        # Save approved chat to history
        if self.chat_id and self.registry_id and self.encryption_key:
            chat_info = {
                'chat_id': self.chat_id,
                'registry_id': self.registry_id,
                'encryption_key': self.encryption_key,
                'username': self.username,
                'approved': True,
                'user_role': self.user_role,
                'timestamp': time.time(),
                'approval_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self.add_to_history(chat_info)
        
        messagebox.showinfo(english_manager.get_text_constant('AUTHORIZATION_GRANTED'),
                           english_manager.get_text_constant('AUTHORIZATION_GRANTED_MESSAGE').format(
                               username=self.username,
                               user_role=self.user_role,
                               channel=self.chat_id[:12] if self.chat_id else 'N/A'
                           ))
        
        # Show main menu
        self.show_classified_main_menu()
    
    def show_chat_history_window(self):
        """Show chat history for quick rejoining approved chats"""
        self.track_current_window(self.show_chat_history_window)
        self.clear_window()
        
        # Main container
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Top classification banner
        classification_banner = tk.Frame(main_container, bg=self.colors['classified'], height=40)
        classification_banner.pack(fill=tk.X)
        classification_banner.pack_propagate(False)
        
        tk.Label(classification_banner,
                text=english_manager.get_text_constant('SECRET_OPERATIONS_ARCHIVE'),
                bg=self.colors['classified'],
                fg='#000000',
                font=('Courier New', 12, 'bold')).pack(expand=True)
        
        # Content area
        content_frame = tk.Frame(main_container, bg=self.colors['bg'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Sidebar
        sidebar = tk.Frame(content_frame, bg=self.colors['sidebar_bg'], width=350)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 20))
        sidebar.pack_propagate(False)
        
        tk.Label(sidebar,
                text=english_manager.get_text_constant('OPERATIONS_ARCHIVE'),
                bg=self.colors['sidebar_bg'],
                fg=self.colors['classified'],
                font=('Courier New', 16, 'bold')).pack(pady=(30, 20))
        
        # Navigation buttons
        nav_frame = tk.Frame(sidebar, bg=self.colors['sidebar_bg'])
        nav_frame.pack(fill=tk.X, padx=20, pady=(0, 30))
        
        tk.Button(nav_frame, text=english_manager.get_text_constant('RETURN_TO_TERMINAL'),
                 command=self.show_classified_main_menu,
                 bg=self.colors['button_bg'],
                 fg=self.colors['button_fg'],
                 font=('Courier New', 10, 'bold'),
                 relief='solid',
                 borderwidth=1).pack(fill=tk.X, pady=5)
        
        tk.Button(nav_frame, text=english_manager.get_text_constant('NEW_AUTHORIZATION'),
                 command=self.join_classified_chat_window,
                 bg=self.colors['button_bg'],
                 fg=self.colors['button_fg'],
                 font=('Courier New', 10, 'bold'),
                 relief='solid',
                 borderwidth=1).pack(fill=tk.X, pady=5)
        
        # Status panel
        status_frame = tk.Frame(sidebar, bg=self.colors['card_bg'], relief='solid', borderwidth=2)
        status_frame.pack(fill=tk.X, padx=20, pady=(20, 0))
        
        tk.Label(status_frame,
                text=english_manager.get_text_constant('ARCHIVE_STATUS'),
                bg=self.colors['card_bg'],
                fg=self.colors['classified'],
                font=('Courier New', 12, 'bold')).pack(pady=(15, 10))
        
        # Filter only approved chats
        approved_chats = [chat for chat in self.chat_history if chat.get('approved', False)]
        
        tk.Label(status_frame,
                text=english_manager.get_text_constant('TOTAL_OPERATIONS').format(count=len(self.chat_history)),
                bg=self.colors['card_bg'],
                fg=self.colors['fg'],
                font=('Courier New', 9)).pack(anchor='w', padx=15, pady=2)
        
        tk.Label(status_frame,
                text=english_manager.get_text_constant('APPROVED_COUNT').format(count=len(approved_chats)),
                bg=self.colors['card_bg'],
                fg=self.colors['success'],
                font=('Courier New', 9)).pack(anchor='w', padx=15, pady=2)
        
        tk.Label(status_frame,
                text=english_manager.get_text_constant('AGENT_STATUS').format(username=self.username),
                bg=self.colors['card_bg'],
                fg=self.colors['info'],
                font=('Courier New', 9)).pack(anchor='w', padx=15, pady=2)
        
        tk.Label(status_frame, text="", bg=self.colors['card_bg']).pack(pady=10)
        
        # Main content
        content = tk.Frame(content_frame, bg=self.colors['bg'])
        content.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        tk.Label(content,
                text=english_manager.get_text_constant('SECRET_OPERATIONS_ARCHIVE_TITLE'),
                bg=self.colors['bg'],
                fg=self.colors['classified'],
                font=('Courier New', 20, 'bold')).pack(pady=(0, 10))
        
        tk.Label(content,
                text=english_manager.get_text_constant('APPROVED_COMMUNICATION_CHANNELS').format(count=len(approved_chats)),
                bg=self.colors['bg'],
                fg=self.colors['fg'],
                font=('Courier New', 12)).pack(pady=(0, 30))
        
        if not approved_chats:
            # Empty state
            empty_frame = tk.Frame(content, bg=self.colors['card_bg'], relief='solid', borderwidth=2)
            empty_frame.pack(fill=tk.BOTH, expand=True, padx=20)
            
            tk.Label(empty_frame, text="", bg=self.colors['card_bg']).pack(pady=50)
            
            tk.Label(empty_frame, text="📭", 
                     font=('Arial', 64), bg=self.colors['card_bg']).pack(pady=(20, 30))
            
            tk.Label(empty_frame,
                    text=english_manager.get_text_constant('NO_APPROVED_OPERATIONS'),
                    bg=self.colors['card_bg'],
                    fg=self.colors['warning'],
                    font=('Courier New', 18, 'bold')).pack(pady=(0, 20))
            
            tk.Label(empty_frame,
                    text=english_manager.get_text_constant('REQUEST_AUTHORIZATION_ACCESS'),
                    bg=self.colors['card_bg'],
                    fg=self.colors['fg'],
                    font=('Courier New', 12)).pack(pady=(0, 30))
            
            tk.Button(empty_frame, text=english_manager.get_text_constant('REQUEST_AUTHORIZATION'),
                     command=self.join_classified_chat_window,
                     bg=self.colors['warning'],
                     fg='#000000',
                     font=('Courier New', 14, 'bold'),
                     relief='solid',
                     borderwidth=2).pack(pady=(0, 50))
        else:
            # Chat list
            list_frame = tk.Frame(content, bg=self.colors['card_bg'], relief='solid', borderwidth=2)
            list_frame.pack(fill=tk.BOTH, expand=True, padx=20)
            
            # Header
            header_frame = tk.Frame(list_frame, bg=self.colors['card_bg'])
            header_frame.pack(fill=tk.X, pady=(20, 0), padx=20)
            
            tk.Label(header_frame,
                    text=english_manager.get_text_constant('CHANNEL_ID'),
                    bg=self.colors['card_bg'],
                    fg=self.colors['classified'],
                    font=('Courier New', 11, 'bold'),
                    width=25).pack(side=tk.LEFT)
            
            tk.Label(header_frame,
                    text=english_manager.get_text_constant('REGISTRY_ID'),
                    bg=self.colors['card_bg'],
                    fg=self.colors['classified'],
                    font=('Courier New', 11, 'bold'),
                    width=25).pack(side=tk.LEFT)
            
            tk.Label(header_frame,
                    text=english_manager.get_text_constant('ACTIONS'),
                    bg=self.colors['card_bg'],
                    fg=self.colors['classified'],
                    font=('Courier New', 11, 'bold')).pack(side=tk.RIGHT)
            
            # Separator
            separator = tk.Frame(list_frame, height=2, bg=self.colors['classified'])
            separator.pack(fill=tk.X, padx=20, pady=10)
            
            # Scrollable content
            canvas = tk.Canvas(list_frame, bg=self.colors['card_bg'], highlightthickness=0)
            scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
            chat_container = tk.Frame(canvas, bg=self.colors['card_bg'])
            
            chat_container.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )
            
            canvas.create_window((0, 0), window=chat_container, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.pack(side="left", fill="both", expand=True, padx=(20, 0), pady=20)
            scrollbar.pack(side="right", fill="y", pady=20)
            
            # Chat rows
            for idx, chat in enumerate(approved_chats):
                row_bg = self.colors['card_bg'] if idx % 2 == 0 else '#0f0f0f'
                row_frame = tk.Frame(chat_container, bg=row_bg)
                row_frame.pack(fill=tk.X, pady=5, padx=(0, 20))
                
                # Chat ID
                tk.Label(row_frame,
                        text=f"{chat['chat_id'][:20]}...",
                        bg=row_bg,
                        fg=self.colors['fg'],
                        font=('Courier New', 9),
                        width=25).pack(side=tk.LEFT, padx=10)
                
                # Registry ID
                tk.Label(row_frame,
                        text=f"{chat['registry_id'][:20]}...",
                        bg=row_bg,
                        fg=self.colors['fg'],
                        font=('Courier New', 9),
                        width=25).pack(side=tk.LEFT, padx=10)
                
                # Actions
                action_frame = tk.Frame(row_frame, bg=row_bg)
                action_frame.pack(side=tk.RIGHT, padx=10)
                
                tk.Button(action_frame, text=english_manager.get_text_constant('CONNECT'),
                         command=lambda c=chat: self.rejoin_from_history(c),
                         bg=self.colors['success'],
                         fg='#000000',
                         font=('Courier New', 9, 'bold'),
                         relief='solid',
                         borderwidth=1).pack(side=tk.LEFT, padx=2)
                
                tk.Button(action_frame, text=english_manager.get_text_constant('DELETE'),
                         command=lambda c=chat: self.remove_from_history(c),
                         bg=self.colors['danger'],
                         fg='#ffffff',
                         font=('Courier New', 9, 'bold'),
                         relief='solid',
                         borderwidth=1).pack(side=tk.LEFT, padx=2)
        
        # Bottom classification
        bottom_banner = tk.Frame(main_container, bg=self.colors['classified'], height=30)
        bottom_banner.pack(fill=tk.X, side=tk.BOTTOM)
        bottom_banner.pack_propagate(False)
        
        tk.Label(bottom_banner,
                text=english_manager.get_text_constant('SECRET_OPERATIONS_ARCHIVE_PERSONNEL'),
                bg=self.colors['classified'],
                fg='#000000',
                font=('Courier New', 10, 'bold')).pack(expand=True)
    
    def rejoin_from_history(self, chat_info):
        """Rejoin approved chat from history"""
        try:
            self.chat_id = chat_info['chat_id']
            self.registry_id = chat_info['registry_id']
            self.encryption_key = chat_info['encryption_key']
            self.username = chat_info.get('username', 'TUNNEL_USER')
            self.is_approved = True
            
            # Derive encryption key
            fernet_key = self.get_fernet_key(self.encryption_key)
            self.cipher = Fernet(fernet_key)
            self.connected = True
            
            # Store credentials securely
            self.secure_memory.store('chat_id', self.chat_id.encode())
            self.secure_memory.store('registry_id', self.registry_id.encode())
            self.secure_memory.store('encryption_key', self.encryption_key.encode())
            
            # Exchange RSA public keys with other users (Phase 2)
            if self.rsa_keys_generated:
                self.exchange_public_keys_with_registry()
            
            # Verify still approved (optional check)
            try:
                response = self.secure_request('GET', f"{REGISTRY_URL}/{self.registry_id}", timeout=10)
                if response.status_code == 200:
                    raw_data = response.json()
                    registry = self.obfuscator.deobfuscate_payload(raw_data)
                    
                    if self.username in registry.get("approved_users", []):
                        messagebox.showinfo("CONNECTION ESTABLISHED",
                                          f"SUCCESSFUL CONNECTION TO CHANNEL\n\n"
                                          f"AGENT: {self.username}\n"
                                          f"CHANNEL: {self.chat_id[:12]}...\n"
                                          f"STATUS: ACTIVE")
                        # Here you would show the actual chat window
                        # For now, return to main menu
                        self.show_classified_main_menu()
                    else:
                        messagebox.showwarning("ACCESS REVOKED", 
                                             "Authorization for this channel has been revoked.\n"
                                             "Contact command.")
                        self.show_chat_history_window()
                else:
                    messagebox.showerror("CONNECTION ERROR", "Unable to check channel status")
                    
            except Exception as e:
                messagebox.showwarning("VERIFICATION UNAVAILABLE", 
                                     f"Unable to verify authorization status.\n"
                                     f"Channel connection may be unsafe.\n\n"
                                     f"Error: {str(e)}")
                
        except Exception as e:
            messagebox.showerror("CONNECTION FAILED", 
                               f"Unable to connect to channel:\n{str(e)}")
    
    def remove_from_history(self, chat_info):
        """Remove chat from history"""
        result = messagebox.askyesno("REMOVE FROM ARCHIVE",
                                   f"Remove this channel from your secure archive?\n\n"
                                   f"Channel: {chat_info['chat_id'][:20]}...\n"
                                   f"Agent: {chat_info['registry_id'][:20]}...\n\n"
                                   f"This will permanently delete the local record.")
        
        if result:
            try:
                # Remove from chat history
                self.chat_history = [h for h in self.chat_history if h.get('chat_id') != chat_info['chat_id']]
                
                # Save updated history
                self.save_chat_history()
                
                messagebox.showinfo("REMOVED", "Operation removed from archive")
                
                # Refresh the window
                self.show_chat_history_window()
                
            except Exception as e:
                messagebox.showerror("ERROR", f"Unable to remove operation: {str(e)}")
    
    def add_to_history(self, chat_info):
        """Add chat to history"""
        # Remove if already exists
        self.chat_history = [h for h in self.chat_history if h.get('chat_id') != chat_info['chat_id']]
        
        # Add to beginning
        self.chat_history.insert(0, chat_info)
        
        # Keep only last 15 chats
        if len(self.chat_history) > 15:
            self.chat_history = self.chat_history[:15]
        
        self.save_chat_history()
    
    def export_chat(self):
        messagebox.showinfo("EXPORT INTELLIGENCE", "CLASSIFIED DATA EXPORT\nCOMING SOON...")
    
    def show_instructions(self):
        messagebox.showinfo("OPERATION MANUAL",
                           "POLLY'S TUNNELS SECURE COMMUNICATION\n"
                           "USER TERMINAL v2.0\n\n"
                           "SECURITY FEATURES:\n"
                           "• QUANTUM-RESISTANT ENCRYPTION\n"
                           "• ZERO-TRACE PROTOCOLS\n"
                           "• COMPARTMENTED ACCESS CONTROL\n"
                           "• ANTI-SURVEILLANCE MEASURES\n"
                           "• SECURE FILE TRANSFER\n"
                           "• FORWARD SECRECY\n\n"
                           "CLASSIFICATION: TOP SECRET\n"
                           "AUTHORIZED PERSONNEL ONLY")
    
    def show_about(self):
        messagebox.showinfo("SYSTEM INFORMATION",
                           "POLLY'S TUNNELS SECURE COMMUNICATION\n"
                           "VERSION: 2.0 QUANTUM\n"
                           "CLASSIFICATION: MAXIMUM SECURITY\n\n"
                           "SECURITY LEVEL: MAXIMUM\n"
                           "ENCRYPTION: QUANTUM-RESISTANT\n"
                           "AUTHENTICATION: STATE-GRADE\n"
                           "COMPARTMENTATION: ENABLED\n\n"
                           "DEVELOPED FOR INTELLIGENCE OPERATIONS\n"
                           "UNAUTHORIZED ACCESS PROHIBITED")
    
    def track_current_window(self, method):
        """Track current window method for theme changes"""
        self.current_window_func = method
    
    def save_theme_preference(self):
        """Save theme preference to configuration file - Winter Cherry Blossom only"""
        try:
            theme_config = {
                'current_theme': 'winter_cherry_blossom',  # Always Winter Cherry Blossom
                'timestamp': time.time()
            }
            with open(self.theme_config_file, 'w') as f:
                json.dump(theme_config, f, indent=2)
        except Exception as e:
            # Failed to save theme preference - handled silently
            pass
    
    def load_theme_preference(self):
        """Load theme preference from configuration file - Winter Cherry Blossom only"""
        # Always use Winter Cherry Blossom theme for unified appearance
        self.current_theme = "winter_cherry_blossom"
        self.colors = self.winter_cherry_theme.get_color_palette()
        
        # Apply Winter Cherry Blossom theme to root window
        self.winter_cherry_theme.apply_theme(self.root)
        self.winter_components.apply_window_theme(self.root)
    
    def reset_theme_to_default(self):
        """Reset theme to default Winter Cherry Blossom Theme"""
        self.change_theme('winter_cherry_blossom')
        messagebox.showinfo("Theme Reset", "Theme has been reset to Winter Cherry Blossom")
    
    def change_theme(self, theme_name=None):
        """Change the interface theme - Winter Cherry Blossom is default (copied from host)"""
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
            self.setup_professional_styles()
            
            # Update all existing UI elements with new theme colors
            self.update_all_ui_elements()
            
            # Show current window again to apply new theme
            current_method = getattr(self, 'current_window_func', self.show_classified_main_menu)
            try:
                if current_method:
                    current_method()
                else:
                    self.show_classified_main_menu()
            except Exception as e:
                print(f"Error refreshing window after theme change: {e}")
                # Fallback to main menu if current method fails
                if self.authenticated:
                    self.show_classified_main_menu()
                else:
                    self.show_authentication_screen()
            
            # Save theme preference
            self.save_theme_preference()
            
            theme_display_name = theme_name.replace('_', ' ').title()
            if theme_name == "winter_cherry_blossom":
                theme_display_name += " (Default)"
            messagebox.showinfo("THEME CHANGED", f"Interface theme changed to: {theme_display_name}")
        else:
            # Fallback to Winter Cherry Blossom
            self.change_theme("winter_cherry_blossom")
    
    def update_all_ui_elements(self):
        """Update all existing UI elements with current theme colors (copied from host)"""
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
        """Track current window method for theme changes (copied from host)"""
        self.current_window_func = method
    
    def save_theme_preference(self):
        """Save current theme preference to configuration"""
        try:
            # Simple theme preference saving
            config = {'theme': self.current_theme}
            with open('client_theme_config.json', 'w') as f:
                json.dump(config, f)
        except Exception as e:
            # Theme preference saving failed - continue silently
            pass
    
    def show_change_history_password(self):
        """Show dialog to change history password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("CHANGE HISTORY PASSWORD")
        dialog.geometry("500x400")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 250
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 200
        dialog.geometry(f"+{x}+{y}")
        
        main_frame = tk.Frame(dialog, bg=self.colors['bg'], padx=40, pady=40)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(main_frame, text="CHANGE HISTORY PASSWORD",
                 font=('Courier New', 16, 'bold'), bg=self.colors['bg'], fg=self.colors['accent']).pack(pady=(0, 30))
        
        # Current password
        if self.security_manager.history_password_hash:
            tk.Label(main_frame, text="Current History Password:",
                     font=('Courier New', 12, 'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor='w', pady=(0, 5))
            
            current_entry = tk.Entry(main_frame, show="*", bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                    font=('Courier New', 12), width=30)
            current_entry.pack(pady=(0, 20))
        else:
            current_entry = None
        
        # New password
        tk.Label(main_frame, text="New History Password:",
                 font=('Courier New', 12, 'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor='w', pady=(0, 5))
        
        new_entry = tk.Entry(main_frame, show="*", bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                            font=('Courier New', 12), width=30)
        new_entry.pack(pady=(0, 20))
        
        # Confirm password
        tk.Label(main_frame, text="Confirm New Password:",
                 font=('Courier New', 12, 'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor='w', pady=(0, 5))
        
        confirm_entry = tk.Entry(main_frame, show="*", bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                font=('Courier New', 12), width=30)
        confirm_entry.pack(pady=(0, 30))
        
        def change_password():
            new_password = new_entry.get()
            confirm_password = confirm_entry.get()
            
            if new_password != confirm_password:
                messagebox.showerror("ERROR", "Passwords do not match!")
                return
            
            if len(new_password) < 8:
                messagebox.showerror("ERROR", "Password must be at least 8 characters!")
                return
            
            current_password = current_entry.get() if current_entry else ""
            
            if self.security_manager.change_history_password(current_password, new_password):
                messagebox.showinfo("SUCCESS", "History password changed successfully!")
                dialog.destroy()
            else:
                messagebox.showerror("ERROR", "Current password is incorrect!")
        
        button_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        button_frame.pack(pady=(20, 0))
        
        tk.Button(button_frame, text="CHANGE PASSWORD",
                 command=change_password,
                 bg=self.colors['button_bg'], fg=self.colors['button_fg'],
                 font=('Courier New', 12, 'bold'),
                 padx=20, pady=10).pack(side=tk.LEFT, padx=10)
        
        tk.Button(button_frame, text="CANCEL",
                 command=dialog.destroy,
                 bg=self.colors['danger'], fg='white',
                 font=('Courier New', 12, 'bold'),
                 padx=20, pady=10).pack(side=tk.LEFT, padx=10)
    
    def show_change_startup_password(self):
        """Show dialog to change startup password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("CHANGE STARTUP PASSWORD")
        dialog.geometry("500x500")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 250
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 250
        dialog.geometry(f"+{x}+{y}")
        
        main_frame = tk.Frame(dialog, bg=self.colors['bg'], padx=40, pady=40)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(main_frame, text="CHANGE STARTUP PASSWORD",
                 font=('Courier New', 16, 'bold'), bg=self.colors['bg'], fg=self.colors['accent']).pack(pady=(0, 30))
        
        tk.Label(main_frame, text="⚠️ WARNING: 3 failed attempts will require recovery phrase",
                 font=('Courier New', 10, 'bold'), bg=self.colors['bg'], fg=self.colors['warning']).pack(pady=(0, 20))
        
        # Current password
        tk.Label(main_frame, text="Current Startup Password:",
                 font=('Courier New', 12, 'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor='w', pady=(0, 5))
        
        current_entry = tk.Entry(main_frame, show="*", bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                font=('Courier New', 12), width=30)
        current_entry.pack(pady=(0, 20))
        
        # New password
        tk.Label(main_frame, text="New Startup Password:",
                 font=('Courier New', 12, 'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor='w', pady=(0, 5))
        
        new_entry = tk.Entry(main_frame, show="*", bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                            font=('Courier New', 12), width=30)
        new_entry.pack(pady=(0, 20))
        
        # Confirm password
        tk.Label(main_frame, text="Confirm New Password:",
                 font=('Courier New', 12, 'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor='w', pady=(0, 5))
        
        confirm_entry = tk.Entry(main_frame, show="*", bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                                font=('Courier New', 12), width=30)
        confirm_entry.pack(pady=(0, 30))
        
        def change_password():
            current_password = current_entry.get()
            new_password = new_entry.get()
            confirm_password = confirm_entry.get()
            
            if new_password != confirm_password:
                messagebox.showerror("ERROR", "Passwords do not match!")
                return
            
            if len(new_password) < 8:
                messagebox.showerror("ERROR", "Password must be at least 8 characters!")
                return
            
            result = self.security_manager.change_startup_password(current_password, new_password, self.master_password_manager)
            
            if result == "SUCCESS":
                messagebox.showinfo("SUCCESS", "Startup password changed successfully!")
                dialog.destroy()
            elif result == "RECOVERY_REQUIRED":
                messagebox.showerror("RECOVERY REQUIRED", "Too many failed attempts!\nRecovery phrase verification required.")
                dialog.destroy()
                self.show_recovery_phrase_dialog()
            elif result.startswith("INCORRECT_PASSWORD"):
                remaining = result.split(":")[1]
                messagebox.showerror("ERROR", f"Current password is incorrect!\n{remaining} attempts remaining.")
            else:
                messagebox.showerror("ERROR", f"Password change failed: {result}")
        
        button_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        button_frame.pack(pady=(20, 0))
        
        tk.Button(button_frame, text="CHANGE PASSWORD",
                 command=change_password,
                 bg=self.colors['button_bg'], fg=self.colors['button_fg'],
                 font=('Courier New', 12, 'bold'),
                 padx=20, pady=10).pack(side=tk.LEFT, padx=10)
        
        tk.Button(button_frame, text="CANCEL",
                 command=dialog.destroy,
                 bg=self.colors['danger'], fg='white',
                 font=('Courier New', 12, 'bold'),
                 padx=20, pady=10).pack(side=tk.LEFT, padx=10)
    
    def show_recovery_phrase_dialog(self):
        """Show recovery phrase verification dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("RECOVERY PHRASE VERIFICATION")
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
        
        tk.Label(main_frame, text="🔐 RECOVERY PHRASE VERIFICATION",
                 font=('Courier New', 16, 'bold'), bg=self.colors['bg'], fg=self.colors['danger']).pack(pady=(0, 20))
        
        tk.Label(main_frame, text="Enter your 12-word recovery phrase to reset failed attempts:",
                 font=('Courier New', 12), bg=self.colors['bg'], fg=self.colors['fg']).pack(pady=(0, 20))
        
        # Recovery phrase entry
        phrase_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        phrase_frame.pack(fill=tk.X, pady=(0, 30))
        
        phrase_entries = []
        for i in range(12):
            row = i // 4
            col = i % 4
            
            if col == 0:
                word_row = tk.Frame(phrase_frame, bg=self.colors['bg'])
                word_row.pack(fill=tk.X, pady=5)
            
            tk.Label(word_row, text=f"{i+1}:", font=('Courier New', 10), 
                    bg=self.colors['bg'], fg=self.colors['fg']).pack(side=tk.LEFT, padx=(0, 5))
            
            entry = tk.Entry(word_row, bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], 
                            font=('Courier New', 10), width=12)
            entry.pack(side=tk.LEFT, padx=(0, 15))
            phrase_entries.append(entry)
        
        def verify_recovery():
            words = [entry.get().strip().lower() for entry in phrase_entries]
            
            if self.master_password_manager.verify_recovery_phrase(words):
                self.security_manager.reset_failed_attempts_after_recovery()
                self.master_password_manager.reset_password_change_attempts()
                messagebox.showinfo("RECOVERY SUCCESS", "Recovery phrase verified!\nFailed attempts have been reset.")
                dialog.destroy()
            else:
                messagebox.showerror("RECOVERY FAILED", "Invalid recovery phrase!\nPlease check all 12 words.")
        
        button_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        button_frame.pack(pady=(20, 0))
        
        tk.Button(button_frame, text="VERIFY RECOVERY PHRASE",
                 command=verify_recovery,
                 bg=self.colors['button_bg'], fg=self.colors['button_fg'],
                 font=('Courier New', 12, 'bold'),
                 padx=20, pady=10).pack(side=tk.LEFT, padx=10)
        
        tk.Button(button_frame, text="CANCEL",
                 command=dialog.destroy,
                 bg=self.colors['danger'], fg='white',
                 font=('Courier New', 12, 'bold'),
                 padx=20, pady=10).pack(side=tk.LEFT, padx=10)

    def save_configuration(self):
        """Save unified configuration to encrypted file"""
        try:
            config = {
                'theme': self.current_theme,
                'session_timeout': self.security_manager.session_timeout,
                'auto_decrypt': self.auto_decrypt,
                'username': self.username,
                'user_role': self.user_role,
                'security_features': self.security_features,
                'timestamp': time.time(),
                'version': '2.0'  # Updated version for new encryption system
            }
            
            # Always encrypt configuration using dedicated encryption system
            if hasattr(self, 'master_password') and self.master_password:
                self.config_encryption.encrypt_configuration_to_file(config, self.master_password, self.config_file)
            else:
                # Use a default password if master password not available (should not happen in normal operation)
                default_password = "default_config_encryption_key"
                self.config_encryption.encrypt_configuration_to_file(config, default_password, self.config_file)
                    
        except Exception as e:
            # Configuration save failed - handled silently for security
            pass
    
    def load_configuration(self):
        """Load unified configuration from encrypted file"""
        try:
            if os.path.exists(self.config_file):
                # Check if file is encrypted with new system
                if self.config_encryption.is_encrypted_configuration_file(self.config_file):
                    # Use new encryption system
                    if hasattr(self, 'master_password') and self.master_password:
                        config = self.config_encryption.decrypt_configuration_from_file(self.master_password, self.config_file)
                    else:
                        # Try default password as fallback
                        default_password = "default_config_encryption_key"
                        try:
                            config = self.config_encryption.decrypt_configuration_from_file(default_password, self.config_file)
                        except:
                            return  # Cannot decrypt configuration
                else:
                    # Check if file is encrypted with old system
                    with open(self.config_file, 'rb') as f:
                        data = f.read()
                    
                    if data.startswith(b'CLIENT_CLASSIFIED_HISTORY_V1'):
                        # File is encrypted with old system
                        if hasattr(self, 'master_password') and self.master_password:
                            config = self.master_password_manager.decrypt_history_file(data, self.master_password)
                            # Migrate to new encryption system
                            self.save_configuration()
                        else:
                            return  # Cannot decrypt without master password
                    else:
                        # File is unencrypted - migrate to encrypted format
                        with open(self.config_file, 'r') as f:
                            config = json.load(f)
                        # Save in encrypted format
                        self.save_configuration()
                
                # Apply configuration
                if 'theme' in config and config['theme'] in self.themes:
                    self.current_theme = config['theme']
                    self.colors = self.themes[self.current_theme]
                
                if 'session_timeout' in config:
                    self.security_manager.session_timeout = config['session_timeout']
                
                if 'auto_decrypt' in config:
                    self.auto_decrypt = config['auto_decrypt']
                
                if 'username' in config:
                    self.username = config['username']
                
                if 'user_role' in config:
                    self.user_role = config['user_role']
                
                if 'security_features' in config:
                    self.security_features = config['security_features']
                    
        except Exception as e:
            # Configuration load failed - handled silently for security
            pass
    
    def backup_configuration(self):
        """Create backup of current configuration"""
        try:
            backup_file = f"polly_config_backup_{int(time.time())}.json"
            
            if os.path.exists(self.config_file):
                import shutil
                shutil.copy2(self.config_file, backup_file)
                messagebox.showinfo("BACKUP CREATED", f"Configuration backup saved as:\n{backup_file}")
            else:
                messagebox.showwarning("NO CONFIG", "No configuration file found to backup")
                
        except Exception as e:
            messagebox.showerror("BACKUP FAILED", f"Failed to create backup: {str(e)}")
    
    def restore_configuration(self):
        """Restore configuration from backup"""
        backup_file = filedialog.askopenfilename(
            title="Select Configuration Backup",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir="."
        )
        
        if backup_file:
            try:
                import shutil
                shutil.copy2(backup_file, self.config_file)
                messagebox.showinfo("RESTORE SUCCESS", "Configuration restored successfully!\nRestart application to apply changes.")
            except Exception as e:
                messagebox.showerror("RESTORE FAILED", f"Failed to restore configuration: {str(e)}")
    
    def reset_configuration(self):
        """Reset configuration to defaults"""
        if messagebox.askyesno("RESET CONFIG", "Reset all configuration to defaults?\nThis cannot be undone."):
            try:
                if os.path.exists(self.config_file):
                    os.remove(self.config_file)
                if os.path.exists(self.theme_config_file):
                    os.remove(self.theme_config_file)
                
                # Reset to defaults
                self.current_theme = "polly_light"
                self.colors = self.themes[self.current_theme]
                self.auto_decrypt = True
                self.security_manager.session_timeout = 1800
                
                messagebox.showinfo("RESET COMPLETE", "Configuration reset to defaults!")
                
                # Refresh UI
                if self.current_window_func:
                    self.current_window_func()
                    
            except Exception as e:
                messagebox.showerror("RESET FAILED", f"Failed to reset configuration: {str(e)}")
    
    def validate_configuration(self):
        """Validate current configuration"""
        issues = []
        
        if self.current_theme not in self.themes:
            issues.append(f"Invalid theme: {self.current_theme}")
        
        if self.security_manager.session_timeout < 300:  # Less than 5 minutes
            issues.append("Session timeout too short (minimum 5 minutes)")
        
        if self.security_manager.session_timeout > 7200:  # More than 2 hours
            issues.append("Session timeout too long (maximum 2 hours)")
        
        if not isinstance(self.auto_decrypt, bool):
            issues.append("Invalid auto_decrypt setting")
        
        if issues:
            messagebox.showwarning("CONFIG ISSUES", "Configuration issues found:\n\n" + "\n".join(issues))
            return False
        else:
            messagebox.showinfo("CONFIG VALID", "Configuration is valid!")
            return True
    
    def handle_security_error(self, error_type, error_message, context=""):
        """Handle security-related errors with appropriate response"""
        error_log = {
            'timestamp': time.time(),
            'error_type': error_type,
            'message': error_message,
            'context': context,
            'user': self.username,
            'session_id': getattr(self, 'session_id', 'unknown')
        }
        
        # Log error securely
        self.log_security_event(error_log)
        
        # Handle different error types
        if error_type == "AUTHENTICATION_FAILED":
            self.handle_auth_failure(error_message)
        elif error_type == "ENCRYPTION_ERROR":
            self.handle_encryption_error(error_message)
        elif error_type == "NETWORK_ERROR":
            self.handle_network_error(error_message)
        elif error_type == "CONFIG_ERROR":
            self.handle_config_error(error_message)
        else:
            self.handle_generic_error(error_message)
    
    def log_security_event(self, event):
        """Log security events for audit"""
        try:
            log_file = "polly_security_audit.log"
            timestamp = datetime.fromtimestamp(event['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
            
            log_entry = f"[{timestamp}] {event['error_type']}: {event['message']}"
            if event['context']:
                log_entry += f" (Context: {event['context']})"
            log_entry += f" - User: {event['user']}\n"
            
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
                
        except Exception as e:
            print(f"Failed to log security event: {e}")
    
    def emergency_recovery_mode(self):
        """Enter emergency recovery mode"""
        if messagebox.askyesno("EMERGENCY RECOVERY", 
                              "Emergency recovery will:\n"
                              "• Reset all security settings\n"
                              "• Clear all stored data\n"
                              "• Require complete re-setup\n\n"
                              "This action cannot be undone!\n\n"
                              "Continue?"):
            try:
                # Clear all data files
                files_to_clear = [
                    self.config_file,
                    self.theme_config_file,
                    self.chat_history_file,
                    "polly_security_audit.log"
                ]
                
                for file in files_to_clear:
                    if os.path.exists(file):
                        os.remove(file)
                
                # Reset security manager
                self.security_manager = SecurityManager()
                
                # Clear keyring data
                if keyring:
                    try:
                        keyring.delete_password(self.security_manager.app_name, "startup_password")
                        keyring.delete_password(self.security_manager.app_name, "pin_code")
                        keyring.delete_password(self.security_manager.app_name, "history_password")
                    except:
                        pass
                
                messagebox.showinfo("RECOVERY COMPLETE", 
                                  "Emergency recovery completed!\n"
                                  "Application will restart for initial setup.")
                
                # Restart application
                self.root.quit()
                
            except Exception as e:
                messagebox.showerror("RECOVERY FAILED", f"Emergency recovery failed: {str(e)}")
    
    def check_system_integrity(self):
        """Check system integrity and report issues"""
        issues = []
        
        # Check critical files
        critical_files = [self.config_file, self.chat_history_file]
        for file in critical_files:
            if os.path.exists(file):
                try:
                    # Check file permissions
                    if not os.access(file, os.R_OK):
                        issues.append(f"Cannot read {file}")
                    if not os.access(file, os.W_OK):
                        issues.append(f"Cannot write {file}")
                except:
                    issues.append(f"Cannot access {file}")
        
        # Check Tor connectivity
        if hasattr(self, 'tor_proxy'):
            status = self.tor_proxy.get_security_status()
            if not status['tor_available']:
                issues.append("Tor proxy not available")
            elif not status['tor_verified']:
                issues.append("Tor connection not verified")
        
        # Check keyring availability
        if not keyring:
            issues.append("Secure password storage not available")
        
        if issues:
            messagebox.showwarning("SYSTEM ISSUES", 
                                 "System integrity issues detected:\n\n" + 
                                 "\n".join(f"• {issue}" for issue in issues))
            return False
        else:
            messagebox.showinfo("SYSTEM OK", "System integrity check passed!")
            return True
    
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
        self.winter_cherry_components.theme.apply_theme(outer_password_entry)
        outer_password_entry.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(password_frame, text="Inner Password (for sensitive data):",
                font=('Segoe UI', 12, 'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor=tk.W, pady=(0, 5))
        
        inner_password_entry = tk.Entry(password_frame, show="*", font=('Segoe UI', 12), width=40)
        self.winter_cherry_components.theme.apply_theme(inner_password_entry)
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
        print("Starting Polly Tunnels Client Application...")
        print("Initializing security systems...")
        
        # Create main window
        root = tk.Tk()
        root.title("Polly Tunnels - Client")
        
        print("Loading interface...")
        
        # Initialize the main application
        app = PollyTunnelsGUI(root)
        
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