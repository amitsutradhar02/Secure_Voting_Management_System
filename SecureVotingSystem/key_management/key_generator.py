import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.rsa import RSA
from crypto.ecc import ECC
from crypto.multi_encryption import MultiLevelEncryption
from crypto.hashing import HashFunction
import json
from datetime import datetime


class KeyGenerator:

    def __init__(self, rsa_key_size=2048):
        self.rsa_key_size = rsa_key_size
    
    def generate_user_keys(self, user_id):

        rsa = RSA(key_size=self.rsa_key_size)
        rsa_public, rsa_private = rsa.generate_keypair()
        ecc = ECC()
        ecc_public, ecc_private = ecc.generate_keypair()
        hmac_key = HashFunction.generate_token(32)
        
        keys = {
            'user_id': user_id,
            'rsa_public': {
                'e': rsa_public[0],
                'n': rsa_public[1]
            },
            'rsa_private': {
                'd': rsa_private[0],
                'n': rsa_private[1]
            },
            'ecc_public': {
                'x': ecc_public.x,
                'y': ecc_public.y
            },
            'ecc_private': ecc_private,
            'hmac_key': hmac_key,
            'created_at': datetime.now().isoformat(),
            'key_version': 1
        }   
        return keys
    
    def generate_system_keys(self):
        mle = MultiLevelEncryption(rsa_key_size=self.rsa_key_size)
        keys = mle.generate_keys()
        hmac_key = HashFunction.generate_token(64)
        
        serialized = MultiLevelEncryption.serialize_keys(keys)
        serialized['hmac_key'] = hmac_key
        serialized['created_at'] = datetime.now().isoformat()
        serialized['key_type'] = 'system'
        serialized['key_version'] = 1
        
        return serialized
    
    def generate_session_key(self):
        return HashFunction.generate_token(32)
    
    @staticmethod
    def generate_master_key():
        return HashFunction.generate_token(64)
    
    @staticmethod
    def derive_key_from_password(password, salt=None):
        return HashFunction.hash_password(password, salt, iterations=200000)
    
    def rotate_user_keys(self, old_keys):
        user_id = old_keys.get('user_id')
        old_version = old_keys.get('key_version', 0)
        
        # Generate new keys
        new_keys = self.generate_user_keys(user_id)
        new_keys['key_version'] = old_version + 1
        new_keys['previous_version'] = old_version
        new_keys['rotated_at'] = datetime.now().isoformat()        
        return new_keys

