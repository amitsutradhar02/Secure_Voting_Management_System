import hashlib
import secrets
import os

class HashFunction:

    DEFAULT_ITERATIONS = 100000  # Number of hash iterations
    SALT_LENGTH = 32  # Salt length in bytes
    
    @staticmethod
    def generate_salt(length=SALT_LENGTH):
        return secrets.token_bytes(length)
    
    @staticmethod
    def hash_password(password, salt=None, iterations=DEFAULT_ITERATIONS):
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        if salt is None:
            salt = HashFunction.generate_salt()
        elif isinstance(salt, str):
            salt = bytes.fromhex(salt)
        
        # Initial hash with salt
        hashed = hashlib.sha256(salt + password).digest()
        
        # Apply iterations
        for _ in range(iterations - 1):
            hashed = hashlib.sha256(hashed + password).digest()
        
        return hashed.hex(), salt.hex()
    
    @staticmethod
    def verify_password(password, hashed_password_hex, salt_hex, iterations=DEFAULT_ITERATIONS):

        computed_hash, _ = HashFunction.hash_password(password, salt_hex, iterations)

        return HashFunction._secure_compare(computed_hash, hashed_password_hex)
    
    @staticmethod
    def _secure_compare(a, b):
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y) if isinstance(x, str) else x ^ y
        
        return result == 0
    
    @staticmethod
    def hash_data(data):

        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return hashlib.sha256(data).hexdigest()
    
# We didn't implement it yet
    @staticmethod 
    def hash_with_pepper(password, salt, pepper, iterations=DEFAULT_ITERATIONS):

        if isinstance(password, str):
            password = password.encode('utf-8')
        if isinstance(pepper, str):
            pepper = pepper.encode('utf-8')
        if isinstance(salt, str):
            salt = bytes.fromhex(salt)
        
        # Combine password with pepper first
        peppered_password = password + pepper
        
        # Hash with salt
        hashed = hashlib.sha256(salt + peppered_password).digest()
        
        # Apply iterations
        for _ in range(iterations - 1):
            hashed = hashlib.sha256(hashed + peppered_password).digest()
        
        return hashed.hex()
    
    @staticmethod
    def generate_token(length=32):
        return secrets.token_hex(length)
    
    @staticmethod
    def generate_otp(length=6):
        otp = ''.join([str(secrets.randbelow(10)) for _ in range(length)])
        return otp
    
    @staticmethod
    def hash_file(file_path):
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()

