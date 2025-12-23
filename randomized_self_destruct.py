"""
Randomized Self-Destruct System
Provides unpredictable timing for self-destruct operations to enhance security
"""

import os
import time
import secrets
import threading
from typing import Optional


class RandomizedSelfDestruct:
    """
    Randomized self-destruct system that adds unpredictable delays
    to make self-destruct behavior less predictable to attackers
    """
    
    def __init__(self):
        """Initialize the randomized self-destruct system"""
        self.default_min_delay = 0.5  # Default minimum delay in seconds
        self.default_max_delay = 3.0  # Default maximum delay in seconds
        
    def generate_random_delay(self, min_delay: float, max_delay: float) -> float:
        """
        Generate a cryptographically secure random delay within the specified range
        
        Args:
            min_delay: Minimum delay in seconds
            max_delay: Maximum delay in seconds
            
        Returns:
            Random delay value between min_delay and max_delay
            
        Raises:
            ValueError: If min_delay > max_delay or if delays are negative
        """
        if min_delay < 0 or max_delay < 0:
            raise ValueError("Delays cannot be negative")
        
        if min_delay > max_delay:
            raise ValueError("Minimum delay cannot be greater than maximum delay")
        
        if min_delay == max_delay:
            return min_delay
        
        # Use cryptographically secure random number generation
        # Generate random bytes and convert to float in range [0, 1)
        random_bytes = secrets.token_bytes(8)
        random_int = int.from_bytes(random_bytes, byteorder='big')
        random_float = random_int / (2**64)  # Convert to [0, 1)
        
        # Scale to desired range
        delay = min_delay + (random_float * (max_delay - min_delay))
        
        return delay
    
    def trigger_random_self_destruct(self, file_path: str, 
                                   min_delay: Optional[float] = None,
                                   max_delay: Optional[float] = None,
                                   secure_overwrite: bool = True) -> bool:
        """
        Trigger self-destruct with random delay
        
        Args:
            file_path: Path to file to destroy
            min_delay: Minimum delay before destruction (uses default if None)
            max_delay: Maximum delay before destruction (uses default if None)
            secure_overwrite: Whether to securely overwrite file before deletion
            
        Returns:
            True if destruction was successful, False otherwise
        """
        if min_delay is None:
            min_delay = self.default_min_delay
        if max_delay is None:
            max_delay = self.default_max_delay
        
        try:
            # Generate random delay
            delay = self.generate_random_delay(min_delay, max_delay)
            
            # Wait for the random delay
            time.sleep(delay)
            
            # Perform the actual file destruction
            return self._secure_delete_file(file_path, secure_overwrite)
            
        except Exception as e:
            # Self-destruct failed - handled silently for security
            return False
    
    def trigger_async_self_destruct(self, file_path: str,
                                  min_delay: Optional[float] = None,
                                  max_delay: Optional[float] = None,
                                  callback: Optional[callable] = None) -> threading.Thread:
        """
        Trigger self-destruct asynchronously in a separate thread
        
        Args:
            file_path: Path to file to destroy
            min_delay: Minimum delay before destruction
            max_delay: Maximum delay before destruction
            callback: Optional callback function to call after destruction
            
        Returns:
            Thread object for the async operation
        """
        def async_destruct():
            success = self.trigger_random_self_destruct(file_path, min_delay, max_delay)
            if callback:
                callback(success, file_path)
        
        thread = threading.Thread(target=async_destruct, daemon=True)
        thread.start()
        return thread
    
    def _secure_delete_file(self, file_path: str, secure_overwrite: bool = True) -> bool:
        """
        Securely delete a file with optional overwriting
        
        Args:
            file_path: Path to file to delete
            secure_overwrite: Whether to overwrite file contents before deletion
            
        Returns:
            True if deletion successful, False otherwise
        """
        try:
            if not os.path.exists(file_path):
                return True  # File already doesn't exist
            
            if secure_overwrite:
                # Get file size for overwriting
                file_size = os.path.getsize(file_path)
                
                # Overwrite file multiple times with random data
                with open(file_path, 'wb') as f:
                    for _ in range(3):  # 3 passes of random overwriting
                        f.seek(0)
                        # Write random data
                        random_data = secrets.token_bytes(file_size)
                        f.write(random_data)
                        f.flush()
                        os.fsync(f.fileno())  # Force write to disk
            
            # Finally remove the file
            os.remove(file_path)
            return True
            
        except Exception as e:
            # Deletion failed - handled silently for security
            return False
    
    def schedule_delayed_self_destruct(self, file_paths: list, 
                                     base_delay: float = 0.0,
                                     randomization_range: float = 2.0) -> list:
        """
        Schedule multiple files for destruction with randomized delays
        
        Args:
            file_paths: List of file paths to destroy
            base_delay: Base delay before starting destructions
            randomization_range: Range of additional random delay for each file
            
        Returns:
            List of thread objects for async operations
        """
        threads = []
        
        for file_path in file_paths:
            # Each file gets a different random delay
            min_delay = base_delay
            max_delay = base_delay + randomization_range
            
            thread = self.trigger_async_self_destruct(file_path, min_delay, max_delay)
            threads.append(thread)
        
        return threads
    
    def emergency_self_destruct(self, file_paths: list, 
                              immediate: bool = False) -> bool:
        """
        Emergency self-destruct with minimal or no delay
        
        Args:
            file_paths: List of files to destroy immediately
            immediate: If True, no delay; if False, very short random delay
            
        Returns:
            True if all files destroyed successfully
        """
        if immediate:
            min_delay = 0.0
            max_delay = 0.0
        else:
            # Very short random delay for emergency situations
            min_delay = 0.1
            max_delay = 0.5
        
        success_count = 0
        
        for file_path in file_paths:
            if self.trigger_random_self_destruct(file_path, min_delay, max_delay):
                success_count += 1
        
        return success_count == len(file_paths)
    
    def get_random_delay_preview(self, min_delay: float, max_delay: float, 
                               sample_count: int = 10) -> list:
        """
        Generate sample delays for testing/preview purposes
        
        Args:
            min_delay: Minimum delay
            max_delay: Maximum delay
            sample_count: Number of sample delays to generate
            
        Returns:
            List of sample delay values
        """
        return [self.generate_random_delay(min_delay, max_delay) 
                for _ in range(sample_count)]
    
    def validate_delay_parameters(self, min_delay: float, max_delay: float) -> bool:
        """
        Validate delay parameters for correctness
        
        Args:
            min_delay: Minimum delay to validate
            max_delay: Maximum delay to validate
            
        Returns:
            True if parameters are valid
        """
        try:
            if min_delay < 0 or max_delay < 0:
                return False
            if min_delay > max_delay:
                return False
            return True
        except:
            return False
    
    def set_default_delays(self, min_delay: float, max_delay: float) -> bool:
        """
        Set new default delay range
        
        Args:
            min_delay: New default minimum delay
            max_delay: New default maximum delay
            
        Returns:
            True if defaults were set successfully
        """
        if not self.validate_delay_parameters(min_delay, max_delay):
            return False
        
        self.default_min_delay = min_delay
        self.default_max_delay = max_delay
        return True


# Convenience functions for easy integration
def random_self_destruct(file_path: str, min_delay: float = 0.5, max_delay: float = 3.0) -> bool:
    """
    Convenience function for randomized self-destruct
    """
    destructor = RandomizedSelfDestruct()
    return destructor.trigger_random_self_destruct(file_path, min_delay, max_delay)


def emergency_destruct(file_paths: list) -> bool:
    """
    Convenience function for emergency destruction
    """
    destructor = RandomizedSelfDestruct()
    return destructor.emergency_self_destruct(file_paths, immediate=True)


def generate_random_delay(min_delay: float, max_delay: float) -> float:
    """
    Convenience function to generate a random delay
    """
    destructor = RandomizedSelfDestruct()
    return destructor.generate_random_delay(min_delay, max_delay)