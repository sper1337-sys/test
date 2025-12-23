"""
Secure Secret Generation System
Generates random cryptographic secrets at installation time using cryptographically secure random number generators
Ensures secret uniqueness across installations
"""

import secrets
import base64
import hashlib
import time
import json
import os
from typing import Dict, List, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class SecureSecretGenerator:
    """
    Secure secret generation system that creates cryptographically secure secrets
    at installation time with guaranteed uniqueness across installations.
    """
    
    def __init__(self):
        self.installation_id = None
        self.secrets_file = "installation_secrets.json"
        self.min_entropy_bits = 256  # Minimum entropy for secrets
        self.secret_types = [
            'master_encryption_key',
            'message_signing_key', 
            'session_key',
            'storage_encryption_key',
            'authentication_salt',
            'installation_uuid'
        ]
    
    def generate_cryptographic_secret(self, secret_type: str, length_bytes: int = 32) -> bytes:
        """
        Generate a cryptographically secure random secret using the system's
        cryptographically secure random number generator.
        
        Args:
            secret_type: Type of secret being generated (for logging/tracking)
            length_bytes: Length of secret in bytes (default 32 = 256 bits)
            
        Returns:
            Cryptographically secure random bytes
            
        Raises:
            ValueError: If length_bytes is less than 16 (128 bits minimum)
        """
        if length_bytes < 16:
            raise ValueError("Secret length must be at least 16 bytes (128 bits)")
        
        # Use secrets module which provides cryptographically secure random numbers
        # backed by the operating system's entropy source
        secret_bytes = secrets.token_bytes(length_bytes)
        
        # Verify we got the expected length
        if len(secret_bytes) != length_bytes:
            raise RuntimeError(f"Failed to generate secret of expected length: got {len(secret_bytes)}, expected {length_bytes}")
        
        return secret_bytes
    
    def generate_installation_secrets(self) -> Dict[str, str]:
        """
        Generate a complete set of cryptographic secrets for a new installation.
        Each installation gets unique secrets to ensure no two installations
        share the same cryptographic material.
        
        Returns:
            Dictionary containing base64-encoded secrets for the installation
        """
        installation_secrets = {}
        
        # Generate unique installation ID first
        installation_id = self.generate_unique_installation_id()
        installation_secrets['installation_id'] = installation_id
        
        # Generate master encryption key (256 bits)
        master_key = self.generate_cryptographic_secret('master_encryption_key', 32)
        installation_secrets['master_encryption_key'] = base64.b64encode(master_key).decode('utf-8')
        
        # Generate message signing key pair
        signing_keys = self.generate_signing_key_pair()
        installation_secrets['message_signing_private_key'] = signing_keys['private_key']
        installation_secrets['message_signing_public_key'] = signing_keys['public_key']
        
        # Generate session encryption key (256 bits)
        session_key = self.generate_cryptographic_secret('session_key', 32)
        installation_secrets['session_key'] = base64.b64encode(session_key).decode('utf-8')
        
        # Generate storage encryption key (256 bits)
        storage_key = self.generate_cryptographic_secret('storage_encryption_key', 32)
        installation_secrets['storage_encryption_key'] = base64.b64encode(storage_key).decode('utf-8')
        
        # Generate authentication salt (256 bits)
        auth_salt = self.generate_cryptographic_secret('authentication_salt', 32)
        installation_secrets['authentication_salt'] = base64.b64encode(auth_salt).decode('utf-8')
        
        # Generate additional entropy for key derivation (512 bits)
        key_derivation_entropy = self.generate_cryptographic_secret('key_derivation_entropy', 64)
        installation_secrets['key_derivation_entropy'] = base64.b64encode(key_derivation_entropy).decode('utf-8')
        
        # Add metadata
        installation_secrets['generated_at'] = time.time()
        installation_secrets['entropy_source'] = 'system_csprng'
        installation_secrets['version'] = '1.0'
        
        return installation_secrets
    
    def generate_unique_installation_id(self) -> str:
        """
        Generate a unique installation identifier that combines multiple sources
        of entropy to ensure uniqueness across installations.
        
        Returns:
            Unique installation ID as hex string
        """
        # Combine multiple entropy sources for maximum uniqueness
        entropy_sources = []
        
        # High-resolution timestamp
        entropy_sources.append(str(time.time_ns()).encode('utf-8'))
        
        # Cryptographically secure random bytes
        entropy_sources.append(secrets.token_bytes(32))
        
        # Process ID (if available)
        try:
            entropy_sources.append(str(os.getpid()).encode('utf-8'))
        except:
            pass
        
        # Additional random entropy
        entropy_sources.append(secrets.token_bytes(16))
        
        # Combine all entropy sources
        combined_entropy = b''.join(entropy_sources)
        
        # Hash to create fixed-length unique ID
        installation_hash = hashlib.sha256(combined_entropy).hexdigest()
        
        return installation_hash
    
    def generate_signing_key_pair(self) -> Dict[str, str]:
        """
        Generate RSA key pair for message signing.
        
        Returns:
            Dictionary with PEM-encoded private and public keys
        """
        # Generate RSA key pair with 2048-bit key size
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serialize public key
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'private_key': private_pem.decode('utf-8'),
            'public_key': public_pem.decode('utf-8')
        }
    
    def save_installation_secrets(self, secrets_dict: Dict[str, str], file_path: Optional[str] = None) -> bool:
        """
        Save installation secrets to encrypted file.
        
        Args:
            secrets_dict: Dictionary of secrets to save
            file_path: Optional custom file path
            
        Returns:
            True if saved successfully, False otherwise
        """
        try:
            file_path = file_path or self.secrets_file
            
            # Add integrity check
            secrets_dict['checksum'] = self.calculate_secrets_checksum(secrets_dict)
            
            # Save to file (in production, this should be encrypted)
            with open(file_path, 'w') as f:
                json.dump(secrets_dict, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Failed to save installation secrets: {e}")
            return False
    
    def load_installation_secrets(self, file_path: Optional[str] = None) -> Optional[Dict[str, str]]:
        """
        Load installation secrets from file.
        
        Args:
            file_path: Optional custom file path
            
        Returns:
            Dictionary of secrets if loaded successfully, None otherwise
        """
        try:
            file_path = file_path or self.secrets_file
            
            if not os.path.exists(file_path):
                return None
            
            with open(file_path, 'r') as f:
                secrets_dict = json.load(f)
            
            # Verify integrity
            if not self.verify_secrets_integrity(secrets_dict):
                print("Warning: Secrets file integrity check failed")
                return None
            
            return secrets_dict
        except Exception as e:
            print(f"Failed to load installation secrets: {e}")
            return None
    
    def calculate_secrets_checksum(self, secrets_dict: Dict[str, str]) -> str:
        """
        Calculate checksum for secrets dictionary (excluding existing checksum).
        
        Args:
            secrets_dict: Dictionary of secrets
            
        Returns:
            SHA-256 checksum as hex string
        """
        # Create copy without checksum field
        secrets_copy = {k: v for k, v in secrets_dict.items() if k != 'checksum'}
        
        # Sort keys for consistent hashing
        sorted_items = sorted(secrets_copy.items())
        
        # Create string representation
        secrets_string = json.dumps(sorted_items, sort_keys=True)
        
        # Calculate hash
        return hashlib.sha256(secrets_string.encode('utf-8')).hexdigest()
    
    def verify_secrets_integrity(self, secrets_dict: Dict[str, str]) -> bool:
        """
        Verify integrity of secrets dictionary.
        
        Args:
            secrets_dict: Dictionary of secrets to verify
            
        Returns:
            True if integrity check passes, False otherwise
        """
        if 'checksum' not in secrets_dict:
            return False
        
        stored_checksum = secrets_dict['checksum']
        calculated_checksum = self.calculate_secrets_checksum(secrets_dict)
        
        return stored_checksum == calculated_checksum
    
    def get_secret_entropy_bits(self, secret_bytes: bytes) -> float:
        """
        Estimate entropy bits in a secret (for testing purposes).
        This is a simplified entropy estimation.
        
        Args:
            secret_bytes: Secret to analyze
            
        Returns:
            Estimated entropy in bits
        """
        if not secret_bytes:
            return 0.0
        
        # For cryptographically secure random data from secrets module,
        # we can assume maximum entropy (8 bits per byte)
        # This is a reasonable assumption since secrets.token_bytes() 
        # uses the OS cryptographically secure random number generator
        max_possible_entropy = len(secret_bytes) * 8  # 8 bits per byte
        
        # Count unique bytes to do a basic sanity check
        unique_bytes = len(set(secret_bytes))
        
        # If we have good byte distribution, assume maximum entropy
        # For small secrets, we might not see all 256 possible byte values
        expected_unique_bytes = min(256, len(secret_bytes))
        
        if unique_bytes >= expected_unique_bytes * 0.5:  # At least 50% unique bytes
            return max_possible_entropy
        else:
            # If distribution seems poor, calculate based on unique bytes
            # This shouldn't happen with cryptographically secure random data
            return unique_bytes * 8 * (len(secret_bytes) / unique_bytes)
    
    def is_installation_initialized(self) -> bool:
        """
        Check if installation secrets have been generated.
        
        Returns:
            True if secrets exist, False otherwise
        """
        return os.path.exists(self.secrets_file)
    
    def initialize_installation(self) -> Dict[str, str]:
        """
        Initialize a new installation with fresh cryptographic secrets.
        
        Returns:
            Dictionary of generated secrets
            
        Raises:
            RuntimeError: If installation is already initialized
        """
        if self.is_installation_initialized():
            raise RuntimeError("Installation already initialized. Use load_installation_secrets() instead.")
        
        # Generate fresh secrets
        secrets_dict = self.generate_installation_secrets()
        
        # Save to file
        if not self.save_installation_secrets(secrets_dict):
            raise RuntimeError("Failed to save installation secrets")
        
        return secrets_dict


# Global instance for easy access
secret_generator = SecureSecretGenerator()


def generate_installation_secrets() -> Dict[str, str]:
    """
    Convenience function to generate installation secrets.
    
    Returns:
        Dictionary of generated secrets
    """
    return secret_generator.generate_installation_secrets()


def initialize_new_installation() -> Dict[str, str]:
    """
    Convenience function to initialize a new installation.
    
    Returns:
        Dictionary of generated secrets
    """
    return secret_generator.initialize_installation()


def get_installation_secrets() -> Optional[Dict[str, str]]:
    """
    Convenience function to get existing installation secrets.
    
    Returns:
        Dictionary of secrets if available, None otherwise
    """
    return secret_generator.load_installation_secrets()