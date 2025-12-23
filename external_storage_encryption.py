"""
External Storage Encryption System
Encrypts all data before sending to JSONBlob and decrypts after retrieval.
Implements secure storage key management for external data protection.
"""

import json
import base64
import secrets
import hashlib
import hmac
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict, Any, Union


class ExternalStorageEncryption:
    """
    Encrypts all data before sending to JSONBlob external storage.
    Provides secure key management and round-trip encryption/decryption.
    """
    
    def __init__(self, master_key: bytes = None):
        """
        Initialize external storage encryption system.
        
        Args:
            master_key: Optional master key for encryption. If None, generates new key.
        """
        self.storage_key = master_key if master_key else self.generate_storage_key()
        self.cipher = Fernet(base64.urlsafe_b64encode(self.storage_key))
        
        # Integrity verification key (separate from encryption key)
        self.integrity_key = self._derive_integrity_key()
    
    def generate_storage_key(self) -> bytes:
        """
        Generate cryptographically secure random storage key.
        
        Returns:
            32-byte encryption key for external storage
        """
        return secrets.token_bytes(32)
    
    def _derive_integrity_key(self) -> bytes:
        """
        Derive integrity verification key from storage key.
        
        Returns:
            32-byte key for HMAC integrity verification
        """
        # Use PBKDF2 to derive integrity key from storage key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'external_storage_integrity_salt',
            iterations=100000,
        )
        return kdf.derive(self.storage_key)
    
    def encrypt_for_storage(self, data: Dict[str, Any]) -> bytes:
        """
        Encrypt data before sending to JSONBlob external storage.
        
        Args:
            data: Dictionary data to encrypt for external storage
            
        Returns:
            Encrypted bytes ready for external storage transmission
            
        Raises:
            Exception: If encryption fails
        """
        try:
            # Convert data to JSON string
            json_data = json.dumps(data, separators=(',', ':'), sort_keys=True)
            json_bytes = json_data.encode('utf-8')
            
            # Encrypt the JSON data
            encrypted_data = self.cipher.encrypt(json_bytes)
            
            # Add integrity verification
            integrity_hash = hmac.new(
                self.integrity_key,
                encrypted_data,
                hashlib.sha256
            ).digest()
            
            # Create storage envelope with metadata
            storage_envelope = {
                'version': 1,
                'encrypted_data': base64.b64encode(encrypted_data).decode('ascii'),
                'integrity_hash': base64.b64encode(integrity_hash).decode('ascii'),
                'timestamp': secrets.randbits(32),  # Random timestamp for obfuscation
                'padding': base64.b64encode(secrets.token_bytes(secrets.randbelow(64) + 16)).decode('ascii')
            }
            
            # Return as bytes for external storage
            envelope_json = json.dumps(storage_envelope, separators=(',', ':'))
            return envelope_json.encode('utf-8')
            
        except Exception as e:
            raise Exception(f"External storage encryption failed: {str(e)}")
    
    def decrypt_from_storage(self, encrypted_data: bytes) -> Dict[str, Any]:
        """
        Decrypt data after retrieval from JSONBlob external storage.
        
        Args:
            encrypted_data: Encrypted bytes retrieved from external storage
            
        Returns:
            Original dictionary data
            
        Raises:
            Exception: If decryption fails or integrity check fails
        """
        try:
            # Parse storage envelope
            envelope_json = encrypted_data.decode('utf-8')
            storage_envelope = json.loads(envelope_json)
            
            # Verify envelope structure
            required_fields = ['version', 'encrypted_data', 'integrity_hash']
            for field in required_fields:
                if field not in storage_envelope:
                    raise Exception(f"Missing required field: {field}")
            
            # Extract encrypted data and integrity hash
            encrypted_content = base64.b64decode(storage_envelope['encrypted_data'])
            stored_integrity_hash = base64.b64decode(storage_envelope['integrity_hash'])
            
            # Verify integrity
            computed_integrity_hash = hmac.new(
                self.integrity_key,
                encrypted_content,
                hashlib.sha256
            ).digest()
            
            if not hmac.compare_digest(stored_integrity_hash, computed_integrity_hash):
                raise Exception("Integrity verification failed - data may be corrupted or tampered")
            
            # Decrypt the data
            decrypted_bytes = self.cipher.decrypt(encrypted_content)
            json_data = decrypted_bytes.decode('utf-8')
            
            # Parse and return original data
            return json.loads(json_data)
            
        except json.JSONDecodeError as e:
            raise Exception(f"Invalid JSON in encrypted data: {str(e)}")
        except Exception as e:
            if "Integrity verification failed" in str(e):
                raise e
            raise Exception(f"External storage decryption failed: {str(e)}")
    
    def get_storage_key_info(self) -> Dict[str, str]:
        """
        Get information about the current storage key (for debugging/management).
        
        Returns:
            Dictionary with key information (no sensitive data)
        """
        key_hash = hashlib.sha256(self.storage_key).hexdigest()
        return {
            'key_hash': key_hash[:16] + '...',  # Truncated hash for identification
            'key_length': len(self.storage_key),
            'algorithm': 'Fernet (AES-128 in CBC mode with HMAC-SHA256)'
        }
    
    def rotate_storage_key(self, new_key: bytes = None) -> bytes:
        """
        Rotate the storage encryption key.
        
        Args:
            new_key: Optional new key. If None, generates random key.
            
        Returns:
            The new storage key
            
        Note:
            After key rotation, previously encrypted data cannot be decrypted
            unless the old key is retained for migration.
        """
        old_key = self.storage_key
        self.storage_key = new_key if new_key else self.generate_storage_key()
        self.cipher = Fernet(base64.urlsafe_b64encode(self.storage_key))
        self.integrity_key = self._derive_integrity_key()
        
        return self.storage_key
    
    def migrate_data(self, old_encrypted_data: bytes, old_key: bytes) -> bytes:
        """
        Migrate data from old key to current key.
        
        Args:
            old_encrypted_data: Data encrypted with old key
            old_key: The old encryption key
            
        Returns:
            Data re-encrypted with current key
        """
        # Create temporary encryption instance with old key
        old_encryption = ExternalStorageEncryption(old_key)
        
        # Decrypt with old key
        decrypted_data = old_encryption.decrypt_from_storage(old_encrypted_data)
        
        # Re-encrypt with current key
        return self.encrypt_for_storage(decrypted_data)


class ExternalStorageManager:
    """
    Manager class that integrates external storage encryption with JSONBlob operations.
    Provides high-level interface for secure external data storage.
    """
    
    def __init__(self, encryption_key: bytes = None):
        """
        Initialize external storage manager.
        
        Args:
            encryption_key: Optional encryption key. If None, generates new key.
        """
        self.encryption = ExternalStorageEncryption(encryption_key)
    
    def encrypt_for_storage(self, data: Dict[str, Any]) -> bytes:
        """
        Encrypt data for external storage (delegates to encryption instance).
        
        Args:
            data: Dictionary data to encrypt for external storage
            
        Returns:
            Encrypted bytes ready for external storage transmission
        """
        return self.encryption.encrypt_for_storage(data)
    
    def decrypt_from_storage(self, encrypted_data: bytes) -> Dict[str, Any]:
        """
        Decrypt data from external storage (delegates to encryption instance).
        
        Args:
            encrypted_data: Encrypted bytes retrieved from external storage
            
        Returns:
            Original dictionary data
        """
        return self.encryption.decrypt_from_storage(encrypted_data)
    
    def prepare_data_for_jsonblob(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare data for JSONBlob storage by encrypting it.
        
        Args:
            data: Original data to store
            
        Returns:
            Dictionary containing encrypted data ready for JSONBlob
        """
        encrypted_bytes = self.encryption.encrypt_for_storage(data)
        
        # Wrap in JSONBlob-compatible structure
        return {
            'encrypted_payload': base64.b64encode(encrypted_bytes).decode('ascii'),
            'metadata': {
                'encrypted': True,
                'version': 1,
                'timestamp': secrets.randbits(32)  # Obfuscated timestamp
            }
        }
    
    def extract_data_from_jsonblob(self, jsonblob_response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract and decrypt data retrieved from JSONBlob.
        
        Args:
            jsonblob_response: Response data from JSONBlob
            
        Returns:
            Original decrypted data
        """
        if not isinstance(jsonblob_response, dict):
            raise Exception("Invalid JSONBlob response format")
        
        if 'encrypted_payload' not in jsonblob_response:
            raise Exception("No encrypted payload found in JSONBlob response")
        
        # Extract encrypted data
        encrypted_bytes = base64.b64decode(jsonblob_response['encrypted_payload'])
        
        # Decrypt and return original data
        return self.encryption.decrypt_from_storage(encrypted_bytes)
    
    def get_encryption_info(self) -> Dict[str, str]:
        """Get information about the encryption system."""
        return self.encryption.get_storage_key_info()