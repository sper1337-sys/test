"""
Enhanced Password Security System
Implements secure password hashing with random salts and constant-time comparison
Replaces hardcoded salts with cryptographically secure random salt generation
"""

import secrets
import hmac
import hashlib
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EnhancedPasswordManager:
    """Enhanced password security manager with random salts and constant-time comparison"""
    
    def __init__(self):
        self.algorithm = hashes.SHA512()
        self.iterations = 2000000  # 2M iterations for strong security
        self.key_length = 64  # 64 bytes for strong keys
        self.salt_length = 32  # 32 bytes for strong salts
    
    def generate_random_salt(self) -> bytes:
        """Generate cryptographically secure random salt
        
        Returns:
            bytes: Random salt of configured length
        """
        return secrets.token_bytes(self.salt_length)
    
    def hash_password_with_random_salt(self, password: str) -> dict:
        """Hash password with randomly generated salt
        
        Args:
            password: Password to hash
            
        Returns:
            dict: Contains salt, hash, algorithm info, and metadata
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Generate random salt for this password
        salt = self.generate_random_salt()
        
        # Create KDF with random salt
        kdf = PBKDF2HMAC(
            algorithm=self.algorithm,
            length=self.key_length,
            salt=salt,
            iterations=self.iterations,
        )
        
        # Derive key from password and salt
        key = kdf.derive(password)
        
        return {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "hash": base64.b64encode(key).decode('utf-8'),
            "algorithm": "pbkdf2_sha512",
            "iterations": self.iterations,
            "key_length": self.key_length,
            "salt_length": self.salt_length
        }
    
    def verify_password_constant_time(self, password: str, stored_hash: dict) -> bool:
        """Verify password using constant-time comparison
        
        Args:
            password: Password to verify
            stored_hash: Dictionary containing salt and hash from hash_password_with_random_salt
            
        Returns:
            bool: True if password matches, False otherwise
        """
        try:
            if isinstance(password, str):
                password = password.encode('utf-8')
            
            # Extract salt and stored key
            salt = base64.b64decode(stored_hash["salt"].encode('utf-8'))
            stored_key = base64.b64decode(stored_hash["hash"].encode('utf-8'))
            
            # Recreate KDF with same parameters
            kdf = PBKDF2HMAC(
                algorithm=self.algorithm,
                length=stored_hash.get("key_length", self.key_length),
                salt=salt,
                iterations=stored_hash.get("iterations", self.iterations),
            )
            
            # Derive key from provided password
            derived_key = kdf.derive(password)
            
            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(stored_key, derived_key)
            
        except Exception:
            # Return False for any errors (invalid format, etc.)
            return False
    
    def secure_password_test(self, password: str) -> bool:
        """Test password security by performing hash and verify round-trip
        
        Args:
            password: Password to test
            
        Returns:
            bool: True if password can be securely hashed and verified
        """
        try:
            # Hash the password
            hash_result = self.hash_password_with_random_salt(password)
            
            # Verify the password
            return self.verify_password_constant_time(password, hash_result)
            
        except Exception:
            return False


def replace_hardcoded_salts_in_master_password_manager():
    """Replace hardcoded salts in MasterPasswordManager with random salt generation"""
    
    def enhanced_derive_master_key(self, password):
        """Enhanced derive_master_key with random salt generation"""
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Generate random salt instead of hardcoded salt
        salt = secrets.token_bytes(32)
        
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
    
    return enhanced_derive_master_key


def replace_hardcoded_salts_in_security_manager():
    """Replace hardcoded salts in SecurityManager with random salt generation"""
    
    def enhanced_hash_password(self, password, salt=None):
        """Enhanced hash_password with proper random salt generation"""
        # Always generate new random salt (ignore provided salt parameter for security)
        salt = secrets.token_bytes(32)
        
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=salt,
            iterations=2000000,  # Increased iterations for better security
        )
        key = kdf.derive(password)
        return base64.b64encode(salt + key).decode()
    
    def enhanced_verify_password(self, password, hash_str):
        """Enhanced verify_password with constant-time comparison"""
        try:
            decoded = base64.b64decode(hash_str.encode())
            salt = decoded[:32]
            stored_key = decoded[32:]
            
            if isinstance(password, str):
                password = password.encode('utf-8')
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=64,
                salt=salt,
                iterations=2000000,  # Match enhanced_hash_password iterations
            )
            key = kdf.derive(password)
            
            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(stored_key, key)
        except Exception:
            return False
    
    return enhanced_hash_password, enhanced_verify_password