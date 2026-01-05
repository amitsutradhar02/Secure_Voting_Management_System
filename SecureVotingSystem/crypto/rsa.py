import random
import math

class RSA:

    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
    
    @staticmethod
    def is_prime(n, k=5):

        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    @staticmethod
    def generate_prime(bit_length):
        while True:

            num = random.getrandbits(bit_length)
            num |= (1 << bit_length - 1) | 1
            
            if RSA.is_prime(num):
                return num
    
    @staticmethod
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a
    
    @staticmethod
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        
        gcd, x1, y1 = RSA.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y
    
    @staticmethod
    def mod_inverse(e, phi):
        gcd, x, _ = RSA.extended_gcd(e, phi)
        
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        
        return (x % phi + phi) % phi
    
    def generate_keypair(self):
        # Generate two large prime numbers
        bit_length = self.key_size // 2
        p = self.generate_prime(bit_length)
        q = self.generate_prime(bit_length)
        
        while p == q:
            q = self.generate_prime(bit_length)
        
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        while self.gcd(e, phi) != 1:
            e = random.randrange(2, phi)
        
        d = self.mod_inverse(e, phi)
        
        self.public_key = (e, n)
        self.private_key = (d, n)
        
        return self.public_key, self.private_key
    
    @staticmethod
    def encrypt(plaintext, public_key):

        e, n = public_key
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        m = int.from_bytes(plaintext, byteorder='big')
        
        if m >= n:
            raise ValueError("Message too large for key size")
        
        c = pow(m, e, n)
        
        byte_length = (n.bit_length() + 7) // 8
        ciphertext = c.to_bytes(byte_length, byteorder='big')
        
        return ciphertext.hex()
    
    @staticmethod
    def decrypt(ciphertext_hex, private_key):

        d, n = private_key
        ciphertext = bytes.fromhex(ciphertext_hex)
        c = int.from_bytes(ciphertext, byteorder='big')
        m = pow(c, d, n)

        byte_length = (m.bit_length() + 7) // 8
        plaintext_bytes = m.to_bytes(byte_length, byteorder='big')
        
        try:
            return plaintext_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return plaintext_bytes
    
    @staticmethod
    def encrypt_large(plaintext, public_key, block_size=None):

        e, n = public_key
        
        if block_size is None:
            block_size = (n.bit_length() // 8) - 11

        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        encrypted_blocks = []
        for i in range(0, len(plaintext), block_size):
            block = plaintext[i:i + block_size]
            encrypted_block = RSA.encrypt(block, public_key)
            encrypted_blocks.append(encrypted_block)
        
        return '||'.join(encrypted_blocks)
    
    @staticmethod
    def decrypt_large(ciphertext, private_key):

        encrypted_blocks = ciphertext.split('||')
        decrypted_blocks = []
        for block in encrypted_blocks:
            decrypted_block = RSA.decrypt(block, private_key)
            if isinstance(decrypted_block, str):
                decrypted_blocks.append(decrypted_block.encode('utf-8'))
            else:
                decrypted_blocks.append(decrypted_block)

        plaintext = b''.join(decrypted_blocks)
        
        try:
            return plaintext.decode('utf-8')
        except UnicodeDecodeError:
            return plaintext
