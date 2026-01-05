import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.multi_encryption import MultiLevelEncryption
from crypto.ecc import Point, ECC
from key_management.key_storage import KeyStorage
from functools import wraps


class EncryptionMiddleware:
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.key_storage = KeyStorage(db_path)
        self.mle = MultiLevelEncryption()
    
    def get_user_keys(self, user_id):

        keys = self.key_storage.retrieve_user_keys(user_id)
        
        if not keys:
            return None, None, None, None
        
        rsa_public = (keys['rsa_public']['e'], keys['rsa_public']['n'])
        rsa_private = (keys['rsa_private']['d'], keys['rsa_private']['n'])
        
        ecc = ECC()
        ecc_public = Point(
            keys['ecc_public']['x'],
            keys['ecc_public']['y'],
            ecc.curve
        )
        ecc_private = keys['ecc_private']
        
        return rsa_public, rsa_private, ecc_public, ecc_private
    
    def encrypt_data(self, plaintext, user_id):

        if not plaintext:
            return None
        
        rsa_public, _, ecc_public, _ = self.get_user_keys(user_id)
        
        if not rsa_public or not ecc_public:
            print(f"Keys not found for user {user_id}")
            return None
        
        try:
            encrypted = self.mle.encrypt(plaintext, rsa_public, ecc_public)
            return encrypted
        except Exception as e:
            print(f"Encryption error: {e}")
            return None
    
    def decrypt_data(self, ciphertext, user_id):

        if not ciphertext:
            return None

        if isinstance(ciphertext, bytes):
            try:
                ciphertext = ciphertext.decode('utf-8')
            except UnicodeDecodeError:
                ciphertext = ciphertext.hex()

        if not isinstance(ciphertext, str):
            return None

        if not ciphertext.strip():
            return None
        
        _, rsa_private, _, ecc_private = self.get_user_keys(user_id)
        
        if not rsa_private or ecc_private is None:
            print(f"Keys not found for user {user_id}")
            return None
        
        try:
            decrypted = self.mle.decrypt(ciphertext, rsa_private, ecc_private)
            return decrypted
        except Exception as e:
            return None


def auto_encrypt(fields):

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):

            user_id = kwargs.get('user_id') or kwargs.get('current_user_id')
            
            if not user_id:

                return f(*args, **kwargs)
            
            from flask import current_app
            em = EncryptionMiddleware(current_app.config['DATABASE_PATH'])
            
            for field in fields:
                if field in kwargs:
                    original_value = kwargs[field]
                    encrypted_value = em.encrypt_data(original_value, user_id)
                    
                    if encrypted_value:
                        kwargs[f"{field}_encrypted"] = encrypted_value
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def auto_decrypt(fields):

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):

            result = f(*args, **kwargs)
            if not result or not isinstance(result, dict):
                return result

            user_id = kwargs.get('user_id') or result.get('user_id')
            
            if not user_id:
                return result
            
            from flask import current_app
            em = EncryptionMiddleware(current_app.config['DATABASE_PATH'])
            
            for field in fields:
                encrypted_field = f"{field}_encrypted"
                
                if encrypted_field in result:
                    encrypted_value = result[encrypted_field]
                    decrypted_value = em.decrypt_data(encrypted_value, user_id)
                    
                    if decrypted_value:
                        result[field] = decrypted_value
            
            return result
        return decorated_function
    return decorator