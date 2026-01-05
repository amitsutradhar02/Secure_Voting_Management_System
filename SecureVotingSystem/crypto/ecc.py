import random
import hashlib


class Point:
    
    def __init__(self, x, y, curve):
        self.x = x
        self.y = y
        self.curve = curve
    
    def __eq__(self, other):
        if isinstance(other, Point):
            return self.x == other.x and self.y == other.y and self.curve == other.curve
        return False
    
    def __ne__(self, other):
        return not self.__eq__(other)
    
    def is_infinity(self):
        return self.x is None and self.y is None


class EllipticCurve:
    
    def __init__(self, a, b, p, g_x, g_y, n):
        self.a = a
        self.b = b
        self.p = p
        self.g = Point(g_x, g_y, self)  # Generator point
        self.n = n  # Order of the generator
        self.infinity = Point(None, None, self)  # Point at infinity
    
    def is_on_curve(self, point):
        if point.is_infinity():
            return True
        
        left = (point.y * point.y) % self.p
        right = (point.x ** 3 + self.a * point.x + self.b) % self.p
        return left == right
    
    def point_add(self, p1, p2):
        # Point at infinity cases
        if p1.is_infinity():
            return p2
        if p2.is_infinity():
            return p1
        
        # If points are inverses of each other
        if p1.x == p2.x and (p1.y + p2.y) % self.p == 0:
            return self.infinity
        
        # Calculate slope
        if p1 == p2:
            # Point doubling
            if p1.y == 0:
                return self.infinity
            slope = (3 * p1.x * p1.x + self.a) * self.mod_inverse(2 * p1.y, self.p)
        else:
            # Point addition
            slope = (p2.y - p1.y) * self.mod_inverse(p2.x - p1.x, self.p)
        
        slope = slope % self.p
       
        # Calculate new point
        x3 = (slope * slope - p1.x - p2.x) % self.p
        y3 = (slope * (p1.x - x3) - p1.y) % self.p
        
        return Point(x3, y3, self)
    
    def scalar_mult(self, k, point):
        if k == 0:
            return self.infinity
        if k < 0:
            # For negative scalar, invert the point
            k = -k
            point = Point(point.x, -point.y % self.p, self)
        
        result = self.infinity
        addend = point
        
        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        
        return result
    
    @staticmethod
    def mod_inverse(a, m):
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a % m, m)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return (x % m + m) % m


class ECC:
    # secp256k1 parameters
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    A = 0
    B = 7
    G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    G_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    def __init__(self):
        self.curve = EllipticCurve(self.A, self.B, self.P, self.G_X, self.G_Y, self.N)
        self.private_key = None
        self.public_key = None
    
    def generate_keypair(self):
        # Generate random private key
        self.private_key = random.randrange(1, self.curve.n)
        
        # Calculate public key: public_key = private_key * G
        self.public_key = self.curve.scalar_mult(self.private_key, self.curve.g)
        
        return self.public_key, self.private_key
    
    @staticmethod
    def point_to_bytes(point):
        if point.is_infinity():
            return b'\x00'
        
        # Uncompressed format: 0x04 || x || y
        x_bytes = point.x.to_bytes(32, byteorder='big')
        y_bytes = point.y.to_bytes(32, byteorder='big')
        return b'\x04' + x_bytes + y_bytes
    
    @staticmethod
    def bytes_to_point(data, curve):
        if data == b'\x00':
            return curve.infinity
        
        if data[0] != 0x04:
            raise ValueError("Invalid point format")
        
        x = int.from_bytes(data[1:33], byteorder='big')
        y = int.from_bytes(data[33:65], byteorder='big')
        
        return Point(x, y, curve)
    
    def encrypt(self, plaintext, public_key):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        k = random.randrange(1, self.curve.n)
        R = self.curve.scalar_mult(k, self.curve.g)
        S = self.curve.scalar_mult(k, public_key)
        shared_secret = S.x.to_bytes(32, byteorder='big')
        key = hashlib.sha256(shared_secret).digest()
        
        ciphertext = bytearray()
        key_extended = key
        
        for i in range(len(plaintext)):
            if i >= len(key_extended):
                # Extend key using hash
                key_extended += hashlib.sha256(key_extended[-32:]).digest()
            ciphertext.append(plaintext[i] ^ key_extended[i])

        r_bytes = self.point_to_bytes(R)
        return r_bytes.hex() + '::' + ciphertext.hex()
    
    def decrypt(self, ciphertext, private_key):
        # Split R and ciphertext
        parts = ciphertext.split('::')
        if len(parts) != 2:
            raise ValueError("Invalid ciphertext format")
        
        r_bytes = bytes.fromhex(parts[0])
        cipher_bytes = bytes.fromhex(parts[1])
        
        R = self.bytes_to_point(r_bytes, self.curve)
    
        S = self.curve.scalar_mult(private_key, R)

        shared_secret = S.x.to_bytes(32, byteorder='big')
        key = hashlib.sha256(shared_secret).digest()

        plaintext = bytearray()
        key_extended = key
        
        for i in range(len(cipher_bytes)):
            if i >= len(key_extended):
                key_extended += hashlib.sha256(key_extended[-32:]).digest()
            plaintext.append(cipher_bytes[i] ^ key_extended[i])
        
        try:
            return plaintext.decode('utf-8')
        except UnicodeDecodeError:
            return bytes(plaintext)
    
    @staticmethod
    def encrypt_with_public_key(plaintext, public_key_point):
        ecc = ECC()
        return ecc.encrypt(plaintext, public_key_point)
    
    @staticmethod
    def decrypt_with_private_key(ciphertext, private_key_int):
        ecc = ECC()
        return ecc.decrypt(ciphertext, private_key_int)
