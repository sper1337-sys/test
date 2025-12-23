"""
Message Authentication and Signing System
Provides cryptographic signing and verification for all messages with sequence numbering
"""

import time
import hmac
import hashlib
import secrets
import base64
import json
from typing import Dict, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


class MessageAuthenticator:
    """
    Message authentication system with cryptographic signing and sequence numbering
    Implements Requirements 2.1, 2.2, 2.3, 2.4 and 5.2, 5.4, 5.5
    """
    
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
        self.sequence_number = 0
        self.received_sequences = set()
        self.max_sequence_gap = 1000  # Maximum allowed gap in sequence numbers
        
    def generate_rsa_keys(self) -> tuple[bytes, bytes]:
        """Generate RSA key pair for message signing (alias for generate_key_pair)"""
        return self.generate_key_pair()
    
    def generate_key_pair(self) -> tuple[bytes, bytes]:
        """Generate RSA key pair for message signing"""
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
    
    def get_next_sequence_number(self) -> int:
        """Get the next sequence number for outgoing messages"""
        self.sequence_number += 1
        return self.sequence_number
    
    def check_sequence_validity(self, sequence_number: int) -> bool:
        """
        Check if sequence number is valid (not replayed and within acceptable range)
        Implements anti-replay protection
        """
        # Check if sequence number was already received (replay attack)
        if sequence_number in self.received_sequences:
            return False
        
        # Check if sequence number is within acceptable range
        if self.received_sequences:
            max_received = max(self.received_sequences)
            if sequence_number < max_received - self.max_sequence_gap:
                return False  # Too old
        
        # Add to received sequences
        self.received_sequences.add(sequence_number)
        
        # Clean up old sequence numbers to prevent memory growth
        if len(self.received_sequences) > self.max_sequence_gap * 2:
            min_keep = max(self.received_sequences) - self.max_sequence_gap
            self.received_sequences = {seq for seq in self.received_sequences if seq >= min_keep}
        
        return True
    
    def sign_message(self, message: str, sequence_number: int) -> dict:
        """
        Sign message with RSA private key and include sequence number
        Returns signed message structure
        """
        if not self.private_key:
            raise Exception("No private key available for signing")
        
        try:
            # Create message payload with sequence number
            message_payload = {
                "content": message,
                "sequence_number": sequence_number,
                "timestamp": time.time()
            }
            
            # Convert to JSON for signing
            payload_json = json.dumps(message_payload, sort_keys=True)
            payload_bytes = payload_json.encode('utf-8')
            
            # Sign with PKCS#1 v1.5 padding and SHA-256 hash
            signature = self.private_key.sign(
                payload_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            # Return signed message structure
            return {
                "content": message,
                "sequence_number": sequence_number,
                "timestamp": message_payload["timestamp"],
                "signature": base64.b64encode(signature).decode('utf-8'),
                "payload_hash": hashlib.sha256(payload_bytes).hexdigest()
            }
            
        except Exception as e:
            raise Exception(f"Message signing failed: {str(e)}")
    
    def verify_message_signature(self, signed_message: dict, public_key_data: bytes = None) -> bool:
        """
        Verify message signature with RSA public key
        Returns True if signature is valid, False otherwise
        """
        try:
            # Extract message components
            content = signed_message.get("content", "")
            sequence_number = signed_message.get("sequence_number", 0)
            timestamp = signed_message.get("timestamp", 0)
            signature_b64 = signed_message.get("signature", "")
            
            if not signature_b64:
                return False
            
            # Check sequence validity for anti-replay protection FIRST
            if not self.check_sequence_validity(sequence_number):
                return False
            
            # Reconstruct the payload that was signed
            message_payload = {
                "content": content,
                "sequence_number": sequence_number,
                "timestamp": timestamp
            }
            
            payload_json = json.dumps(message_payload, sort_keys=True)
            payload_bytes = payload_json.encode('utf-8')
            
            # Decode signature from base64
            signature_bytes = base64.b64decode(signature_b64.encode('utf-8'))
            
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
                payload_bytes,
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


class KeyRotationManager:
    """
    Handles automatic encryption key rotation every 100 messages
    Implements Requirements 5.1, 5.3
    """
    
    def __init__(self, rotation_threshold: int = 100):
        self.rotation_threshold = rotation_threshold
        self.message_count = 0
        self.current_key_version = 1
        self.key_history = {}
        
    def increment_message_count(self) -> None:
        """Increment message count for key rotation tracking"""
        self.message_count += 1
    
    def should_rotate_keys(self) -> bool:
        """Check if keys should be rotated based on message count"""
        return self.message_count >= self.rotation_threshold
    
    def rotate_encryption_keys(self) -> dict:
        """
        Rotate encryption keys and return new key information
        Resets message count and increments key version
        """
        # Store old key version
        old_version = self.current_key_version
        
        # Generate new key version
        self.current_key_version += 1
        
        # Reset message count
        self.message_count = 0
        
        # Generate new key material
        new_key = secrets.token_bytes(32)
        
        # Store in key history
        key_info = {
            "version": self.current_key_version,
            "key": base64.b64encode(new_key).decode('utf-8'),
            "created_at": time.time(),
            "previous_version": old_version,
            "message_count": 0
        }
        
        self.key_history[self.current_key_version] = key_info
        
        return key_info
    
    def get_current_key_info(self) -> dict:
        """Get current key information"""
        return {
            "version": self.current_key_version,
            "message_count": self.message_count,
            "rotation_threshold": self.rotation_threshold,
            "messages_until_rotation": max(0, self.rotation_threshold - self.message_count)
        }