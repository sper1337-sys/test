"""
Deniable Encryption System
Provides optional deniable encryption mode with plausible deniability features
Allows users to plausibly deny the existence of encrypted communications
"""

import os
import json
import secrets
import base64
import time
from typing import Dict, Any, Optional, Tuple, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DeniableEncryptionManager:
    """
    Manages optional deniable encryption with plausible deniability features.
    
    Deniable encryption allows users to plausibly deny the existence of encrypted
    communications by providing multiple layers of encryption with different keys.
    """
    
    def __init__(self, config_file: str = "deniable_config.json"):
        self.config_file = config_file
        self.is_enabled = False
        self.outer_key = None  # Key for innocent/decoy data
        self.inner_key = None  # Key for real sensitive data
        self.innocent_data = {}  # Plausible innocent data
        self.config = self._load_configuration()
        
    def _load_configuration(self) -> Dict[str, Any]:
        """Load deniable encryption configuration from file"""
        default_config = {
            "enabled": False,
            "mode": "dual_layer",  # dual_layer, steganographic, or hidden_volume
            "innocent_data_template": {
                "type": "chat_logs",
                "sample_messages": [
                    "Hey, how's the weather today?",
                    "Did you see the news about the local festival?",
                    "I'm planning to visit the library this weekend.",
                    "The coffee shop downtown has great reviews.",
                    "Have you tried that new restaurant on Main Street?"
                ]
            },
            "plausible_denial_settings": {
                "generate_fake_timestamps": True,
                "create_innocent_metadata": True,
                "use_steganographic_headers": False
            }
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    default_config.update(loaded_config)
            return default_config
        except Exception as e:
            print(f"Warning: Failed to load deniable encryption config: {e}")
            return default_config
    
    def _save_configuration(self) -> None:
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save deniable encryption config: {e}")
    
    def enable_deniable_encryption(self, outer_password: str, inner_password: str) -> bool:
        """
        Enable deniable encryption mode with dual passwords.
        
        Args:
            outer_password: Password for innocent/decoy data
            inner_password: Password for real sensitive data
            
        Returns:
            True if successfully enabled, False otherwise
        """
        try:
            # Generate encryption keys from passwords
            self.outer_key = self._derive_key_from_password(outer_password, b"outer_salt")
            self.inner_key = self._derive_key_from_password(inner_password, b"inner_salt")
            
            # Generate innocent data for plausible deniability
            self._generate_innocent_data()
            
            # Update configuration
            self.config["enabled"] = True
            self.is_enabled = True
            self._save_configuration()
            
            print("🔐 Deniable encryption mode enabled")
            return True
            
        except Exception as e:
            print(f"Failed to enable deniable encryption: {e}")
            return False
    
    def disable_deniable_encryption(self) -> bool:
        """
        Disable deniable encryption mode.
        
        Returns:
            True if successfully disabled, False otherwise
        """
        try:
            self.is_enabled = False
            self.outer_key = None
            self.inner_key = None
            self.innocent_data = {}
            
            # Update configuration
            self.config["enabled"] = False
            self._save_configuration()
            
            print("🔓 Deniable encryption mode disabled")
            return True
            
        except Exception as e:
            print(f"Failed to disable deniable encryption: {e}")
            return False
    
    def _derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Use a fixed salt for deniable encryption to ensure consistency
        # In production, you might want to store salts securely
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # Fewer iterations for performance in deniable scenarios
        )
        return kdf.derive(password)
    
    def _generate_innocent_data(self) -> None:
        """Generate plausible innocent data for outer layer"""
        template = self.config["innocent_data_template"]
        
        # Generate innocent chat messages with realistic timestamps
        messages = []
        base_time = time.time() - (7 * 24 * 3600)  # Start from a week ago
        
        for i, message in enumerate(template["sample_messages"]):
            timestamp = base_time + (i * 3600) + secrets.randbelow(1800)  # Random within hour
            messages.append({
                "id": f"msg_{secrets.token_hex(8)}",
                "content": message,
                "timestamp": timestamp,
                "sender": "innocent_user",
                "type": "text"
            })
        
        # Add some innocent metadata
        self.innocent_data = {
            "chat_history": messages,
            "user_profile": {
                "username": "casual_user",
                "last_seen": time.time() - 3600,
                "preferences": {
                    "theme": "light",
                    "notifications": True,
                    "language": "en"
                }
            },
            "settings": {
                "auto_save": True,
                "encryption_level": "basic",
                "backup_enabled": False
            }
        }
    
    def encrypt_with_deniability(self, sensitive_data: Dict[str, Any], 
                                password_type: str = "inner") -> bytes:
        """
        Encrypt data with deniable encryption.
        
        Creates a single encrypted blob that can be decrypted with either password
        to reveal different data (innocent vs sensitive).
        
        Args:
            sensitive_data: The actual sensitive data to encrypt
            password_type: "inner" for real data, "outer" for decoy data
            
        Returns:
            Encrypted data that provides plausible deniability
        """
        if not self.is_enabled:
            raise ValueError("Deniable encryption is not enabled")
        
        try:
            # Create dual-layer encrypted package
            # Layer 1: Encrypt innocent data with outer key
            innocent_json = json.dumps(self.innocent_data, separators=(',', ':')).encode('utf-8')
            outer_aesgcm = AESGCM(self.outer_key)
            outer_nonce = secrets.token_bytes(12)
            outer_ciphertext = outer_aesgcm.encrypt(outer_nonce, innocent_json, None)
            
            # Layer 2: Encrypt sensitive data with inner key
            sensitive_json = json.dumps(sensitive_data, separators=(',', ':')).encode('utf-8')
            inner_aesgcm = AESGCM(self.inner_key)
            inner_nonce = secrets.token_bytes(12)
            inner_ciphertext = inner_aesgcm.encrypt(inner_nonce, sensitive_json, None)
            
            # Create the dual-layer encrypted package
            encrypted_package = {
                "version": "1.0",
                "outer_layer": {
                    "nonce": base64.b64encode(outer_nonce).decode('utf-8'),
                    "ciphertext": base64.b64encode(outer_ciphertext).decode('utf-8')
                },
                "inner_layer": {
                    "nonce": base64.b64encode(inner_nonce).decode('utf-8'),
                    "ciphertext": base64.b64encode(inner_ciphertext).decode('utf-8')
                },
                "metadata": {
                    "timestamp": time.time(),
                    "algorithm": "AES-GCM-DUAL",
                    "layers": 2
                }
            }
            
            # Add steganographic headers if enabled
            if self.config["plausible_denial_settings"]["use_steganographic_headers"]:
                encrypted_package["innocent_header"] = self._generate_innocent_header()
            
            return json.dumps(encrypted_package).encode('utf-8')
            
        except Exception as e:
            raise Exception(f"Deniable encryption failed: {e}")
    
    def decrypt_with_deniability(self, encrypted_data: bytes, 
                                password: str, 
                                expect_innocent: bool = False) -> Tuple[Dict[str, Any], bool]:
        """
        Decrypt data with deniable encryption.
        
        Args:
            encrypted_data: The encrypted data to decrypt
            password: Password to use for decryption
            expect_innocent: Whether to expect innocent data (for testing)
            
        Returns:
            Tuple of (decrypted_data, is_innocent_data)
        """
        if not self.is_enabled:
            raise ValueError("Deniable encryption is not enabled")
        
        try:
            # Parse the encrypted package
            package = json.loads(encrypted_data.decode('utf-8'))
            
            # Check if this is a dual-layer package
            if "outer_layer" in package and "inner_layer" in package:
                # Dual-layer deniable encryption
                outer_key = self._derive_key_from_password(password, b"outer_salt")
                inner_key = self._derive_key_from_password(password, b"inner_salt")
                
                # Try outer layer first (innocent data)
                try:
                    outer_nonce = base64.b64decode(package["outer_layer"]["nonce"])
                    outer_ciphertext = base64.b64decode(package["outer_layer"]["ciphertext"])
                    
                    outer_aesgcm = AESGCM(outer_key)
                    decrypted_bytes = outer_aesgcm.decrypt(outer_nonce, outer_ciphertext, None)
                    decrypted_data = json.loads(decrypted_bytes.decode('utf-8'))
                    
                    return decrypted_data, True  # Innocent data
                    
                except Exception:
                    pass  # Try inner layer
                
                # Try inner layer (sensitive data)
                try:
                    inner_nonce = base64.b64decode(package["inner_layer"]["nonce"])
                    inner_ciphertext = base64.b64decode(package["inner_layer"]["ciphertext"])
                    
                    inner_aesgcm = AESGCM(inner_key)
                    decrypted_bytes = inner_aesgcm.decrypt(inner_nonce, inner_ciphertext, None)
                    decrypted_data = json.loads(decrypted_bytes.decode('utf-8'))
                    
                    return decrypted_data, False  # Sensitive data
                    
                except Exception:
                    pass  # Neither key worked
                
                raise ValueError("Failed to decrypt with provided password")
            
            else:
                # Legacy single-layer encryption - try both keys
                nonce = base64.b64decode(package["nonce"])
                ciphertext = base64.b64decode(package["ciphertext"])
                
                # Try both keys to determine which data we're accessing
                keys_to_try = [
                    (self._derive_key_from_password(password, b"outer_salt"), True),   # Outer key (innocent)
                    (self._derive_key_from_password(password, b"inner_salt"), False)   # Inner key (sensitive)
                ]
                
                for key, is_innocent in keys_to_try:
                    try:
                        aesgcm = AESGCM(key)
                        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
                        decrypted_data = json.loads(decrypted_bytes.decode('utf-8'))
                        
                        return decrypted_data, is_innocent
                        
                    except Exception:
                        continue  # Try next key
                
                raise ValueError("Failed to decrypt with any available key")
            
        except Exception as e:
            raise Exception(f"Deniable decryption failed: {e}")
    
    def _generate_innocent_header(self) -> Dict[str, Any]:
        """Generate innocent-looking metadata headers"""
        return {
            "content_type": "application/json",
            "user_agent": "ChatClient/1.0",
            "session_id": secrets.token_hex(16),
            "request_id": secrets.token_hex(8),
            "timestamp": time.time()
        }
    
    def create_plausible_denial_story(self) -> Dict[str, str]:
        """
        Create a plausible denial story for the encrypted data.
        
        Returns:
            Dictionary with plausible explanations for the encrypted data
        """
        stories = [
            {
                "explanation": "Personal chat backup",
                "details": "This is just a backup of casual conversations with friends and family.",
                "context": "I use this app to stay in touch with people and backup my chat history."
            },
            {
                "explanation": "Work communication archive",
                "details": "These are archived work-related messages and project discussions.",
                "context": "My company requires us to backup work communications for compliance."
            },
            {
                "explanation": "Study group messages",
                "details": "Messages from my study group discussing homework and class projects.",
                "context": "We use encrypted messaging for academic collaboration and privacy."
            },
            {
                "explanation": "Family coordination",
                "details": "Family messages about schedules, events, and daily coordination.",
                "context": "We prefer encrypted messaging for family privacy and security."
            }
        ]
        
        # Return a random plausible story
        return secrets.choice(stories)
    
    def get_configuration_options(self) -> Dict[str, Any]:
        """
        Get available configuration options for deniable encryption.
        
        Returns:
            Dictionary of configuration options and their current values
        """
        return {
            "enabled": self.is_enabled,
            "mode": self.config.get("mode", "dual_layer"),
            "available_modes": ["dual_layer", "steganographic", "hidden_volume"],
            "plausible_denial_settings": self.config.get("plausible_denial_settings", {}),
            "innocent_data_types": ["chat_logs", "work_documents", "study_notes", "family_messages"]
        }
    
    def update_configuration(self, new_config: Dict[str, Any]) -> bool:
        """
        Update deniable encryption configuration.
        
        Args:
            new_config: New configuration settings
            
        Returns:
            True if successfully updated, False otherwise
        """
        try:
            # Validate configuration
            valid_modes = ["dual_layer", "steganographic", "hidden_volume"]
            if "mode" in new_config and new_config["mode"] not in valid_modes:
                raise ValueError(f"Invalid mode. Must be one of: {valid_modes}")
            
            # Update configuration
            self.config.update(new_config)
            self._save_configuration()
            
            # Regenerate innocent data if template changed
            if "innocent_data_template" in new_config:
                self._generate_innocent_data()
            
            print("🔧 Deniable encryption configuration updated")
            return True
            
        except Exception as e:
            print(f"Failed to update deniable encryption configuration: {e}")
            return False
    
    def is_deniable_encryption_enabled(self) -> bool:
        """Check if deniable encryption is currently enabled"""
        return self.is_enabled
    
    def get_innocent_data_preview(self) -> Dict[str, Any]:
        """Get a preview of the innocent data that would be shown"""
        if not self.innocent_data:
            self._generate_innocent_data()
        
        # Return a limited preview for security
        preview = {
            "message_count": len(self.innocent_data.get("chat_history", [])),
            "sample_message": self.innocent_data.get("chat_history", [{}])[0].get("content", "No messages"),
            "user_profile": self.innocent_data.get("user_profile", {}).get("username", "Unknown"),
            "last_activity": self.innocent_data.get("user_profile", {}).get("last_seen", 0)
        }
        
        return preview


class DeniableEncryptionUI:
    """
    User interface components for deniable encryption configuration.
    Provides methods to integrate deniable encryption into existing applications.
    """
    
    def __init__(self, deniable_manager: DeniableEncryptionManager):
        self.deniable_manager = deniable_manager
    
    def create_configuration_dialog_data(self) -> Dict[str, Any]:
        """
        Create data structure for deniable encryption configuration dialog.
        
        Returns:
            Dictionary with dialog configuration data
        """
        config = self.deniable_manager.get_configuration_options()
        
        return {
            "title": "Deniable Encryption Configuration",
            "description": "Configure optional deniable encryption for plausible deniability",
            "sections": [
                {
                    "name": "Basic Settings",
                    "fields": [
                        {
                            "name": "enabled",
                            "label": "Enable Deniable Encryption",
                            "type": "checkbox",
                            "value": config["enabled"],
                            "description": "Enable optional deniable encryption mode"
                        },
                        {
                            "name": "mode",
                            "label": "Encryption Mode",
                            "type": "dropdown",
                            "value": config["mode"],
                            "options": config["available_modes"],
                            "description": "Select deniable encryption mode"
                        }
                    ]
                },
                {
                    "name": "Plausible Deniability",
                    "fields": [
                        {
                            "name": "generate_fake_timestamps",
                            "label": "Generate Fake Timestamps",
                            "type": "checkbox",
                            "value": config["plausible_denial_settings"].get("generate_fake_timestamps", True),
                            "description": "Generate realistic fake timestamps for innocent data"
                        },
                        {
                            "name": "create_innocent_metadata",
                            "label": "Create Innocent Metadata",
                            "type": "checkbox",
                            "value": config["plausible_denial_settings"].get("create_innocent_metadata", True),
                            "description": "Generate innocent-looking metadata"
                        },
                        {
                            "name": "use_steganographic_headers",
                            "label": "Use Steganographic Headers",
                            "type": "checkbox",
                            "value": config["plausible_denial_settings"].get("use_steganographic_headers", False),
                            "description": "Hide encryption indicators in innocent headers"
                        }
                    ]
                }
            ],
            "buttons": [
                {"name": "save", "label": "Save Configuration", "type": "primary"},
                {"name": "cancel", "label": "Cancel", "type": "secondary"},
                {"name": "test", "label": "Test Configuration", "type": "info"}
            ]
        }
    
    def get_setup_wizard_data(self) -> Dict[str, Any]:
        """
        Get data for deniable encryption setup wizard.
        
        Returns:
            Dictionary with setup wizard configuration
        """
        return {
            "title": "Deniable Encryption Setup",
            "description": "Set up deniable encryption for plausible deniability in high-risk environments",
            "steps": [
                {
                    "name": "introduction",
                    "title": "Introduction to Deniable Encryption",
                    "content": [
                        "Deniable encryption allows you to plausibly deny the existence of encrypted communications.",
                        "You will set up two passwords:",
                        "• Outer password: Shows innocent, harmless data",
                        "• Inner password: Reveals your actual sensitive communications",
                        "If coerced, you can provide the outer password to show innocent data."
                    ]
                },
                {
                    "name": "passwords",
                    "title": "Set Up Passwords",
                    "fields": [
                        {
                            "name": "outer_password",
                            "label": "Outer Password (for innocent data)",
                            "type": "password",
                            "required": True,
                            "description": "Password that reveals innocent, harmless data"
                        },
                        {
                            "name": "inner_password",
                            "label": "Inner Password (for sensitive data)",
                            "type": "password",
                            "required": True,
                            "description": "Password that reveals your actual sensitive communications"
                        }
                    ]
                },
                {
                    "name": "innocent_data",
                    "title": "Configure Innocent Data",
                    "fields": [
                        {
                            "name": "data_type",
                            "label": "Type of Innocent Data",
                            "type": "dropdown",
                            "options": ["chat_logs", "work_documents", "study_notes", "family_messages"],
                            "value": "chat_logs",
                            "description": "Choose what type of innocent data to generate"
                        }
                    ]
                },
                {
                    "name": "confirmation",
                    "title": "Confirm Setup",
                    "content": [
                        "Review your deniable encryption setup:",
                        "• Outer password will show innocent data",
                        "• Inner password will show sensitive data",
                        "• Remember: Never reveal your inner password under coercion",
                        "• Practice your plausible denial story"
                    ]
                }
            ]
        }
    
    def get_status_info(self) -> Dict[str, Any]:
        """
        Get current status information for display in UI.
        
        Returns:
            Dictionary with status information
        """
        if not self.deniable_manager.is_deniable_encryption_enabled():
            return {
                "status": "disabled",
                "message": "Deniable encryption is not enabled",
                "color": "gray",
                "icon": "🔓"
            }
        
        preview = self.deniable_manager.get_innocent_data_preview()
        
        return {
            "status": "enabled",
            "message": f"Deniable encryption active - {preview['message_count']} innocent messages ready",
            "color": "green",
            "icon": "🔐",
            "details": {
                "innocent_user": preview["user_profile"],
                "sample_message": preview["sample_message"],
                "last_activity": preview["last_activity"]
            }
        }


# Example usage and testing functions
def example_usage():
    """Example of how to use the deniable encryption system"""
    
    # Initialize the deniable encryption manager
    deniable_mgr = DeniableEncryptionManager()
    
    # Enable deniable encryption with two passwords
    outer_password = "innocent_password_123"  # Shows innocent data
    inner_password = "sensitive_password_456"  # Shows real data
    
    success = deniable_mgr.enable_deniable_encryption(outer_password, inner_password)
    if not success:
        print("Failed to enable deniable encryption")
        return
    
    # Prepare some sensitive data
    sensitive_data = {
        "real_messages": [
            {"content": "This is sensitive information", "timestamp": time.time()},
            {"content": "Meeting at the secure location", "timestamp": time.time() + 100}
        ],
        "contacts": ["secure_contact_1", "secure_contact_2"],
        "encryption_keys": {"key1": "secret_key_data"}
    }
    
    # Encrypt the sensitive data
    encrypted_data = deniable_mgr.encrypt_with_deniability(sensitive_data, "inner")
    print(f"Encrypted data size: {len(encrypted_data)} bytes")
    
    # Decrypt with outer password (shows innocent data)
    try:
        decrypted_innocent, is_innocent = deniable_mgr.decrypt_with_deniability(
            encrypted_data, outer_password
        )
        print(f"Outer password decryption - Is innocent: {is_innocent}")
        print(f"Innocent data preview: {decrypted_innocent.get('user_profile', {}).get('username', 'Unknown')}")
    except Exception as e:
        print(f"Outer decryption failed: {e}")
    
    # Decrypt with inner password (shows real data)
    try:
        decrypted_real, is_innocent = deniable_mgr.decrypt_with_deniability(
            encrypted_data, inner_password
        )
        print(f"Inner password decryption - Is innocent: {is_innocent}")
        print(f"Real data messages: {len(decrypted_real.get('real_messages', []))}")
    except Exception as e:
        print(f"Inner decryption failed: {e}")
    
    # Get plausible denial story
    story = deniable_mgr.create_plausible_denial_story()
    print(f"Plausible denial story: {story['explanation']}")
    
    # Create UI components
    ui = DeniableEncryptionUI(deniable_mgr)
    config_dialog = ui.create_configuration_dialog_data()
    print(f"Configuration dialog has {len(config_dialog['sections'])} sections")
    
    status = ui.get_status_info()
    print(f"Status: {status['message']}")


if __name__ == "__main__":
    example_usage()