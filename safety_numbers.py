"""
Safety Numbers for End-to-End Encryption Verification
Provides Signal-like safety numbers for secure channel verification
Implements Requirements 7.1, 7.2, 7.3
"""

import hashlib
import hmac
import secrets
import base64
import time
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class SafetyNumberGenerator:
    """
    Generates and manages safety numbers for end-to-end encryption verification
    Similar to Signal's safety number system for verifying secure channels
    """
    
    def __init__(self):
        self.safety_numbers = {}
        self.channel_keys = {}
        
    def generate_safety_numbers(self, local_public_key: bytes, remote_public_key: bytes, 
                              local_identity: str, remote_identity: str) -> str:
        """
        Generate safety numbers from two public keys and identities
        
        Args:
            local_public_key: Local party's public key (PEM format)
            remote_public_key: Remote party's public key (PEM format)
            local_identity: Local party's identity/username
            remote_identity: Remote party's identity/username
            
        Returns:
            60-digit safety number string (12 groups of 5 digits)
        """
        try:
            # Normalize identities (lowercase, strip whitespace, handle Unicode)
            import unicodedata
            local_id = unicodedata.normalize('NFKC', local_identity.lower().strip())
            remote_id = unicodedata.normalize('NFKC', remote_identity.lower().strip())
            
            # Ensure consistent ordering (alphabetical by identity)
            if local_id < remote_id:
                first_key = local_public_key
                second_key = remote_public_key
                first_id = local_id
                second_id = remote_id
            else:
                first_key = remote_public_key
                second_key = local_public_key
                first_id = remote_id
                second_id = local_id
            
            # Create combined input for hashing
            combined_input = (
                first_id.encode('utf-8') +
                b'\x00' +  # Separator
                first_key +
                b'\x00' +  # Separator
                second_id.encode('utf-8') +
                b'\x00' +  # Separator
                second_key
            )
            
            # Generate safety number using SHA-256
            safety_hash = hashlib.sha256(combined_input).digest()
            
            # Convert to 60-digit number (12 groups of 5 digits)
            # Use the first 25 bytes of hash to generate 60 decimal digits
            safety_number = ""
            for i in range(12):
                # Take 2 bytes at a time, convert to int, mod 100000 for 5 digits
                byte_pair = safety_hash[i*2:(i*2)+2]
                if len(byte_pair) == 2:
                    value = int.from_bytes(byte_pair, byteorder='big')
                    group = f"{value % 100000:05d}"
                    safety_number += group
                else:
                    # Fallback for last byte if odd number
                    value = safety_hash[i*2]
                    group = f"{value * 1000:05d}"
                    safety_number += group
            
            # Store the safety number for this key pair
            key_pair_id = self._get_key_pair_id(local_public_key, remote_public_key, 
                                               local_identity, remote_identity)
            self.safety_numbers[key_pair_id] = {
                'safety_number': safety_number,
                'local_identity': local_identity,
                'remote_identity': remote_identity,
                'generated_at': time.time()
            }
            
            return safety_number
            
        except Exception as e:
            raise Exception(f"Safety number generation failed: {str(e)}")
    
    def verify_safety_numbers(self, local_number: str, remote_number: str) -> bool:
        """
        Verify that two safety numbers match
        
        Args:
            local_number: Safety number from local party
            remote_number: Safety number from remote party
            
        Returns:
            True if safety numbers match, False otherwise
        """
        try:
            # Normalize numbers (remove spaces, convert to string)
            local_clean = self._normalize_safety_number(local_number)
            remote_clean = self._normalize_safety_number(remote_number)
            
            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(local_clean, remote_clean)
            
        except Exception:
            return False
    
    def format_safety_number(self, safety_number: str) -> str:
        """
        Format safety number for display (groups of 5 digits)
        
        Args:
            safety_number: 60-digit safety number string
            
        Returns:
            Formatted safety number with spaces between groups
        """
        try:
            # Ensure we have exactly 60 digits
            clean_number = self._normalize_safety_number(safety_number)
            if len(clean_number) != 60:
                raise ValueError("Safety number must be exactly 60 digits")
            
            # Format as 12 groups of 5 digits
            formatted = ""
            for i in range(0, 60, 5):
                if i > 0:
                    formatted += " "
                formatted += clean_number[i:i+5]
            
            return formatted
            
        except Exception as e:
            raise Exception(f"Safety number formatting failed: {str(e)}")
    
    def get_safety_number_for_channel(self, channel_id: str) -> Optional[str]:
        """
        Get safety number for a specific channel
        
        Args:
            channel_id: Unique identifier for the channel
            
        Returns:
            Safety number string if found, None otherwise
        """
        if channel_id in self.channel_keys:
            return self.channel_keys[channel_id]['safety_number']
        return None
    
    def establish_secure_channel(self, local_public_key: bytes, remote_public_key: bytes,
                               local_identity: str, remote_identity: str, 
                               channel_id: str) -> Dict:
        """
        Establish secure channel and generate safety numbers
        
        Args:
            local_public_key: Local party's public key
            remote_public_key: Remote party's public key
            local_identity: Local party's identity
            remote_identity: Remote party's identity
            channel_id: Unique channel identifier
            
        Returns:
            Dictionary with channel info and safety numbers
        """
        try:
            # Generate safety numbers
            safety_number = self.generate_safety_numbers(
                local_public_key, remote_public_key,
                local_identity, remote_identity
            )
            
            # Store channel information
            self.channel_keys[channel_id] = {
                'local_public_key': local_public_key,
                'remote_public_key': remote_public_key,
                'local_identity': local_identity,
                'remote_identity': remote_identity,
                'safety_number': safety_number,
                'established_at': time.time()
            }
            
            return {
                'channel_id': channel_id,
                'safety_number': safety_number,
                'formatted_safety_number': self.format_safety_number(safety_number),
                'local_identity': local_identity,
                'remote_identity': remote_identity,
                'established_at': time.time()
            }
            
        except Exception as e:
            raise Exception(f"Secure channel establishment failed: {str(e)}")
    
    def _normalize_safety_number(self, safety_number: str) -> str:
        """
        Normalize safety number by removing spaces and non-digit characters
        
        Args:
            safety_number: Raw safety number string
            
        Returns:
            Normalized safety number with only digits
        """
        return ''.join(c for c in safety_number if c.isdigit())
    
    def _get_key_pair_id(self, local_key: bytes, remote_key: bytes, 
                        local_id: str, remote_id: str) -> str:
        """
        Generate unique identifier for a key pair combination
        
        Args:
            local_key: Local public key
            remote_key: Remote public key
            local_id: Local identity
            remote_id: Remote identity
            
        Returns:
            Unique identifier string
        """
        # Create deterministic ID based on key material and identities
        combined = local_key + remote_key + local_id.encode() + remote_id.encode()
        return hashlib.sha256(combined).hexdigest()[:16]


class SafetyNumberDisplay:
    """
    Handles display and user interaction for safety number verification
    """
    
    def __init__(self, safety_generator: SafetyNumberGenerator):
        self.safety_generator = safety_generator
    
    def display_safety_numbers(self, safety_number: str, local_identity: str, 
                             remote_identity: str) -> str:
        """
        Create formatted display text for safety numbers
        
        Args:
            safety_number: 60-digit safety number
            local_identity: Local party identity
            remote_identity: Remote party identity
            
        Returns:
            Formatted display text
        """
        try:
            formatted_number = self.safety_generator.format_safety_number(safety_number)
            
            display_text = f"""
SAFETY NUMBERS FOR SECURE VERIFICATION

Your Identity: {local_identity}
Contact Identity: {remote_identity}

Safety Numbers:
{formatted_number}

VERIFICATION INSTRUCTIONS:
1. Compare these numbers with your contact
2. Numbers must match exactly on both devices
3. Verify through a separate secure channel (voice call, in person)
4. If numbers don't match, DO NOT proceed with communication

These numbers verify that your communication is end-to-end encrypted
and that you are communicating with the intended recipient.
"""
            return display_text
            
        except Exception as e:
            return f"Error displaying safety numbers: {str(e)}"
    
    def create_verification_prompt(self, safety_number: str) -> str:
        """
        Create user prompt for safety number verification
        
        Args:
            safety_number: Safety number to verify
            
        Returns:
            Verification prompt text
        """
        formatted_number = self.safety_generator.format_safety_number(safety_number)
        
        return f"""
VERIFY SAFETY NUMBERS

Your safety numbers are:
{formatted_number}

Please verify these numbers match exactly with your contact's numbers.

Have you verified that these numbers match? (yes/no): """
    
    def compare_safety_numbers(self, local_number: str, remote_number: str) -> Dict:
        """
        Compare safety numbers and return verification result
        
        Args:
            local_number: Local safety number
            remote_number: Remote safety number
            
        Returns:
            Dictionary with verification result and details
        """
        try:
            matches = self.safety_generator.verify_safety_numbers(local_number, remote_number)
            
            return {
                'verified': matches,
                'local_number': self.safety_generator.format_safety_number(local_number),
                'remote_number': self.safety_generator.format_safety_number(remote_number),
                'message': 'Safety numbers match - secure channel verified!' if matches 
                          else 'WARNING: Safety numbers do not match! Channel may be compromised!',
                'timestamp': time.time()
            }
            
        except Exception as e:
            return {
                'verified': False,
                'error': str(e),
                'message': 'Error during safety number verification',
                'timestamp': time.time()
            }


# Example usage and testing functions
def generate_test_keys() -> Tuple[bytes, bytes]:
    """Generate test RSA key pair for testing"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return private_pem, public_pem


if __name__ == "__main__":
    # Example usage
    generator = SafetyNumberGenerator()
    display = SafetyNumberDisplay(generator)
    
    # Generate test keys
    alice_private, alice_public = generate_test_keys()
    bob_private, bob_public = generate_test_keys()
    
    # Generate safety numbers
    safety_number = generator.generate_safety_numbers(
        alice_public, bob_public,
        "Alice", "Bob"
    )
    
    print("Generated Safety Number:", safety_number)
    print("Formatted:", generator.format_safety_number(safety_number))
    
    # Test verification
    result = display.compare_safety_numbers(safety_number, safety_number)
    print("Verification Result:", result)