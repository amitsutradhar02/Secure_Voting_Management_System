import hashlib

class HMAC:
  
    def __init__(self, key, hash_function='sha256'):
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        self.key = key
        self.hash_function = hash_function
        
        # Get hash function
        if hash_function == 'sha256':
            self.hash_func = hashlib.sha256
            self.block_size = 64  # SHA-256 block size in bytes
            self.digest_size = 32  # SHA-256 digest size in bytes
        elif hash_function == 'sha512':
            self.hash_func = hashlib.sha512
            self.block_size = 128
            self.digest_size = 64
        else:
            raise ValueError(f"Unsupported hash function: {hash_function}")

        self.key = self._prepare_key(key)
    
    def _prepare_key(self, key):
        # If key is longer than block size, hash it
        if len(key) > self.block_size:
            key = self.hash_func(key).digest()
        
        # Pad key to block size
        if len(key) < self.block_size:
            key = key + b'\x00' * (self.block_size - len(key))
        
        return key
    
    def compute(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Define padding constants
        ipad = b'\x36' * self.block_size  # Inner padding
        opad = b'\x5c' * self.block_size  # Outer padding
        
        # XOR key with ipad and opad
        key_ipad = bytes(a ^ b for a, b in zip(self.key, ipad))
        key_opad = bytes(a ^ b for a, b in zip(self.key, opad))
        
        inner_hash = self.hash_func(key_ipad + message).digest()   
        outer_hash = self.hash_func(key_opad + inner_hash).digest()
        
        return outer_hash.hex()
    
    def verify(self, message, expected_hmac):

        computed_hmac = self.compute(message)
        return self._secure_compare(computed_hmac, expected_hmac)
    
    @staticmethod
    def _secure_compare(a, b):
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y) if isinstance(x, str) else x ^ y
        
        return result == 0
    
    @staticmethod
    def generate_hmac(message, key, hash_function='sha256'):
        hmac = HMAC(key, hash_function)
        return hmac.compute(message)
    
    @staticmethod
    def verify_hmac(message, key, expected_hmac, hash_function='sha256'):
        hmac = HMAC(key, hash_function)
        return hmac.verify(message, expected_hmac)


class CBCMAC: 
    def __init__(self, key, block_size=16):

        if isinstance(key, str):
            key = key.encode('utf-8')
        
        self.key = key
        self.block_size = block_size
        
        if len(key) < block_size:
            self.key = key + b'\x00' * (block_size - len(key))
        elif len(key) > block_size:
            self.key = hashlib.sha256(key).digest()[:block_size]
    
    def _xor_bytes(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))
    
    def _pad_message(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        padding_length = self.block_size - (len(message) % self.block_size)
        if padding_length == 0:
            padding_length = self.block_size
        
        padding = bytes([padding_length] * padding_length)
        return message + padding
    
    def compute(self, message):
        padded = self._pad_message(message)
        mac = b'\x00' * self.block_size
        
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i + self.block_size]
            xored = self._xor_bytes(mac, block)
            mac = hashlib.sha256(self._xor_bytes(xored, self.key)).digest()[:self.block_size]
        
        return mac.hex()
    
    def verify(self, message, expected_mac):
        computed_mac = self.compute(message)
        return computed_mac == expected_mac
