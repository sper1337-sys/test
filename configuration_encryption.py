"""
Configuration File Encryption System
Provides secure encryption and decryption for application configuration files
"""

import json
import os
import base64
import hashlib
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class ConfigurationEncryption:
    """
    Secure configuration file encryption system
    
    Provides methods to encrypt and decrypt configuration data using
    password-based encryption with PBKDF2 key derivation and Fernet encryption.
    """
    
    def __init__(self):
        """Initialize the configuration encryption system"""
        self.header = b'CONFIG_ENCRYPTED_V1'
        self.salt_length = 32
        self.iterations = 2000000  # High iteration count for security
        
    def derive_encryption_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2
        
        Args:
            password: The password to derive key from
            salt: Random salt for key derivation
            
        Returns:
            Derived encryption key suitable for Fernet
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def encrypt_configuration(self, config_data: dict, password: str) -> bytes:
        """
        Encrypt configuration data with password
        
        Args:
            config_data: Dictionary containing configuration data
            password: Password for encryption
            
        Returns:
            Encrypted configuration data as bytes
        """
        # Convert config data to JSON
        json_data = json.dumps(config_data, indent=2, sort_keys=True)
        json_bytes = json_data.encode('utf-8')
        
        # Generate random salt
        salt = secrets.token_bytes(self.salt_length)
        
        # Derive encryption key
        key = self.derive_encryption_key(password, salt)
        
        # Create Fernet cipher
        cipher = Fernet(key)
        
        # Encrypt the JSON data
        encrypted_data = cipher.encrypt(json_bytes)
        
        # Create integrity checksum
        checksum = hashlib.sha256(encrypted_data).digest()
        
        # Combine header, salt, checksum, and encrypted data
        result = self.header + salt + checksum + encrypted_data
        
        return result
    
    def decrypt_configuration(self, encrypted_data: bytes, password: str) -> dict:
        """
        Decrypt configuration data with password
        
        Args:
            encrypted_data: Encrypted configuration data
            password: Password for decryption
            
        Returns:
            Decrypted configuration data as dictionary
            
        Raises:
            Exception: If decryption fails or data is corrupted
        """
        # Verify header
        if not encrypted_data.startswith(self.header):
            raise Exception("Invalid configuration file format")
        
        # Extract components
        header_len = len(self.header)
        salt = encrypted_data[header_len:header_len + self.salt_length]
        checksum = encrypted_data[header_len + self.salt_length:header_len + self.salt_length + 32]
        encrypted_content = encrypted_data[header_len + self.salt_length + 32:]
        
        # Verify integrity
        calculated_checksum = hashlib.sha256(encrypted_content).digest()
        if calculated_checksum != checksum:
            raise Exception("Configuration file integrity check failed")
        
        # Derive encryption key
        key = self.derive_encryption_key(password, salt)
        
        # Create Fernet cipher
        cipher = Fernet(key)
        
        try:
            # Decrypt the data
            decrypted_bytes = cipher.decrypt(encrypted_content)
            
            # Convert back to JSON
            json_data = decrypted_bytes.decode('utf-8')
            config_data = json.loads(json_data)
            
            return config_data
            
        except Exception as e:
            raise Exception(f"Configuration decryption failed: {str(e)}")
    
    def encrypt_configuration_to_file(self, config_data: dict, password: str, file_path: str) -> None:
        """
        Encrypt configuration data and save to file
        
        Args:
            config_data: Dictionary containing configuration data
            password: Password for encryption
            file_path: Path to save encrypted configuration file
        """
        encrypted_data = self.encrypt_configuration(config_data, password)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        # Write encrypted data to file
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
    
    def decrypt_configuration_from_file(self, password: str, file_path: str) -> dict:
        """
        Load and decrypt configuration data from file
        
        Args:
            password: Password for decryption
            file_path: Path to encrypted configuration file
            
        Returns:
            Decrypted configuration data as dictionary
            
        Raises:
            Exception: If file doesn't exist or decryption fails
        """
        if not os.path.exists(file_path):
            raise Exception(f"Configuration file not found: {file_path}")
        
        # Read encrypted data from file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        return self.decrypt_configuration(encrypted_data, password)
    
    def is_encrypted_configuration_file(self, file_path: str) -> bool:
        """
        Check if a file is an encrypted configuration file
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file appears to be encrypted configuration
        """
        if not os.path.exists(file_path):
            return False
        
        try:
            with open(file_path, 'rb') as f:
                header = f.read(len(self.header))
                return header == self.header
        except:
            return False
    
    def migrate_plain_configuration(self, plain_file_path: str, encrypted_file_path: str, password: str) -> bool:
        """
        Migrate a plain JSON configuration file to encrypted format
        
        Args:
            plain_file_path: Path to plain JSON configuration file
            encrypted_file_path: Path to save encrypted configuration
            password: Password for encryption
            
        Returns:
            True if migration successful, False otherwise
        """
        try:
            # Read plain configuration
            with open(plain_file_path, 'r') as f:
                config_data = json.load(f)
            
            # Encrypt and save
            self.encrypt_configuration_to_file(config_data, password, encrypted_file_path)
            
            return True
            
        except Exception as e:
            print(f"Configuration migration failed: {e}")
            return False
    
    def create_backup(self, config_data: dict, password: str, backup_dir: str) -> str:
        """
        Create encrypted backup of configuration data
        
        Args:
            config_data: Configuration data to backup
            password: Password for encryption
            backup_dir: Directory to store backup
            
        Returns:
            Path to created backup file
        """
        import time
        
        # Create backup filename with timestamp
        timestamp = int(time.time())
        backup_filename = f"config_backup_{timestamp}.enc"
        backup_path = os.path.join(backup_dir, backup_filename)
        
        # Encrypt and save backup
        self.encrypt_configuration_to_file(config_data, password, backup_path)
        
        return backup_path
    
    def validate_configuration_structure(self, config_data: dict) -> bool:
        """
        Validate that configuration data has expected structure
        
        Args:
            config_data: Configuration data to validate
            
        Returns:
            True if configuration structure is valid
        """
        if not isinstance(config_data, dict):
            return False
        
        # Check for required fields (basic validation)
        required_fields = ['version', 'timestamp']
        for field in required_fields:
            if field not in config_data:
                return False
        
        # Validate data types
        if not isinstance(config_data.get('timestamp'), (int, float)):
            return False
        
        if not isinstance(config_data.get('version'), str):
            return False
        
        return True
    
    def secure_delete_file(self, file_path: str) -> bool:
        """
        Securely delete a configuration file by overwriting it
        
        Args:
            file_path: Path to file to securely delete
            
        Returns:
            True if deletion successful
        """
        try:
            if not os.path.exists(file_path):
                return True
            
            # Get file size
            file_size = os.path.getsize(file_path)
            
            # Overwrite file multiple times with random data
            with open(file_path, 'wb') as f:
                for _ in range(3):  # 3 passes of random data
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Finally remove the file
            os.remove(file_path)
            
            return True
            
        except Exception as e:
            print(f"Secure file deletion failed: {e}")
            return False


# Convenience functions for easy integration
def encrypt_config_file(config_data: dict, password: str, file_path: str) -> None:
    """
    Convenience function to encrypt configuration to file
    """
    encryptor = ConfigurationEncryption()
    encryptor.encrypt_configuration_to_file(config_data, password, file_path)


def decrypt_config_file(password: str, file_path: str) -> dict:
    """
    Convenience function to decrypt configuration from file
    """
    encryptor = ConfigurationEncryption()
    return encryptor.decrypt_configuration_from_file(password, file_path)


def is_config_encrypted(file_path: str) -> bool:
    """
    Convenience function to check if configuration file is encrypted
    """
    encryptor = ConfigurationEncryption()
    return encryptor.is_encrypted_configuration_file(file_path)