"""
Enhanced Decoy Password System
Implements obviously fake decoy passwords for security enhancement
"""

import secrets
import time
import base64


class EnhancedDecoySystem:
    """Enhanced decoy password system with obviously fake patterns"""
    
    def __init__(self):
        self.decoy_patterns = [
            "FAKE_PASSWORD_123",
            "OBVIOUSLY_FAKE_456", 
            "DECOY_MODE_789",
            "NOT_REAL_PASSWORD",
            "FAKE_ADMIN_ACCESS",
            "DUMMY_PASSWORD_XYZ"
        ]
        self.current_decoy = None
        self.decoy_data = []
        
    def setup_obvious_decoy(self) -> str:
        """Setup an obviously fake decoy password"""
        # Choose a random obvious fake pattern
        self.current_decoy = secrets.choice(self.decoy_patterns)
        
        # Generate fake decoy data
        self.decoy_data = [
            {
                'chat_id': 'FAKE_CHAT_' + secrets.token_hex(8),
                'registry_id': 'FAKE_REGISTRY_' + secrets.token_hex(8),
                'encryption_key': base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
                'username': 'FAKE_USER_DECOY',
                'timestamp': time.time() - 86400,
                'is_fake': True
            }
        ]
        
        return self.current_decoy
    
    def is_decoy_password(self, password: str) -> bool:
        """Check if password matches the obvious decoy pattern"""
        if not password or not self.current_decoy:
            return False
            
        # Simple string comparison for decoy detection
        return password == self.current_decoy
    
    def generate_decoy_data(self) -> list:
        """Generate fake data for decoy mode"""
        return self.decoy_data.copy() if self.decoy_data else []
    
    def get_decoy_patterns(self) -> list:
        """Get list of all possible decoy patterns"""
        return self.decoy_patterns.copy()