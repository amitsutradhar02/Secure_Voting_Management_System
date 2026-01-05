from .rsa import RSA
from .ecc import ECC
from .hmac import HMAC
import json

class MultiLevelEncryption:
    
    def __init__(self, rsa_key_size=2048):
        self.rsa = RSA(key_size=rsa_key_size)
        self.ecc = ECC()
        self.rsa_public_key = None
        self.rsa_private_key = None
        self.ecc_public_key = None
        self.ecc_private_key = None
    
    def generate_keys(self):
        self.rsa_public_key, self.rsa_private_key = self.rsa.generate_keypair()
        self.ecc_public_key, self.ecc_private_key = self.ecc.generate_keypair()
        
        return {
            'rsa_public': self.rsa_public_key,
            'rsa_private': self.rsa_private_key,
            'ecc_public': self.ecc_public_key,
            'ecc_private': self.ecc_private_key
        }
    
    def encrypt(self, plaintext, rsa_public_key=None, ecc_public_key=None):
        if rsa_public_key is None:
            rsa_public_key = self.rsa_public_key
        if ecc_public_key is None:
            ecc_public_key = self.ecc_public_key
        
        if rsa_public_key is None or ecc_public_key is None:
            raise ValueError("Encryption keys not provided or generated")
        
        rsa_encrypted = RSA.encrypt_large(plaintext, rsa_public_key)
        ecc_encrypted = self.ecc.encrypt(rsa_encrypted, ecc_public_key)
        
        return ecc_encrypted
    
    def decrypt(self, ciphertext, rsa_private_key=None, ecc_private_key=None):
        if rsa_private_key is None:
            rsa_private_key = self.rsa_private_key
        if ecc_private_key is None:
            ecc_private_key = self.ecc_private_key
        
        if rsa_private_key is None or ecc_private_key is None:
            raise ValueError("Decryption keys not provided or generated")

        ecc_decrypted = self.ecc.decrypt(ciphertext, ecc_private_key)
        rsa_decrypted = RSA.decrypt_large(ecc_decrypted, rsa_private_key)
        
        return rsa_decrypted
    
    def encrypt_with_integrity(self, plaintext, hmac_key, rsa_public_key=None, ecc_public_key=None):
        encrypted = self.encrypt(plaintext, rsa_public_key, ecc_public_key)
        
        hmac = HMAC.generate_hmac(encrypted, hmac_key)
        
        return f"{encrypted}||{hmac}"
    
    def decrypt_with_integrity(self, ciphertext_with_hmac, hmac_key, rsa_private_key=None, ecc_private_key=None):

        try:
            parts = ciphertext_with_hmac.split('||')
            if len(parts) != 2:
                return None, False
            
            encrypted, expected_hmac = parts
            
            # Verify HMAC
            is_valid = HMAC.verify_hmac(encrypted, hmac_key, expected_hmac)
            
            if not is_valid:
                return None, False
            
            # Decrypt data
            decrypted = self.decrypt(encrypted, rsa_private_key, ecc_private_key)
            
            return decrypted, True
        
        except Exception as e:
            print(f"Decryption error: {e}")
            return None, False
    
    @staticmethod
    def serialize_keys(keys):
        serialized = {}
        
        # Serialize RSA keys
        if 'rsa_public' in keys:
            serialized['rsa_public'] = {
                'e': keys['rsa_public'][0],
                'n': keys['rsa_public'][1]
            }
        
        if 'rsa_private' in keys:
            serialized['rsa_private'] = {
                'd': keys['rsa_private'][0],
                'n': keys['rsa_private'][1]
            }
        
        # Serialize ECC keys
        if 'ecc_public' in keys:
            ecc_pub = keys['ecc_public']
            serialized['ecc_public'] = {
                'x': ecc_pub.x,
                'y': ecc_pub.y
            }
        
        if 'ecc_private' in keys:
            serialized['ecc_private'] = keys['ecc_private']
        
        return serialized
    
    @staticmethod
    def deserialize_keys(serialized_keys):
        keys = {}
        
        # Deserialize RSA keys
        if 'rsa_public' in serialized_keys:
            keys['rsa_public'] = (
                serialized_keys['rsa_public']['e'],
                serialized_keys['rsa_public']['n']
            )
        
        if 'rsa_private' in serialized_keys:
            keys['rsa_private'] = (
                serialized_keys['rsa_private']['d'],
                serialized_keys['rsa_private']['n']
            )
        
        # Deserialize ECC keys
        if 'ecc_public' in serialized_keys:
            from .ecc import Point, ECC
            ecc = ECC()
            keys['ecc_public'] = Point(
                serialized_keys['ecc_public']['x'],
                serialized_keys['ecc_public']['y'],
                ecc.curve
            )
        
        if 'ecc_private' in serialized_keys:
            keys['ecc_private'] = serialized_keys['ecc_private']
        
        return keys
