import sqlite3
import re
from datetime import datetime
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.hashing import HashFunction
from crypto.multi_encryption import MultiLevelEncryption
from key_management.key_generator import KeyGenerator
from key_management.key_storage import KeyStorage


class Registration:
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.key_generator = KeyGenerator()
        self.key_storage = KeyStorage(db_path)
        self.init_database()
    
    def init_database(self):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email_encrypted TEXT NOT NULL,
                full_name_encrypted TEXT NOT NULL,
                phone_encrypted TEXT,
                nid_encrypted TEXT,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                role TEXT DEFAULT 'voter',
                is_verified INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login TEXT,
                failed_login_attempts INTEGER DEFAULT 0,
                lockout_until TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def validate_password(self, password):

        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        return True, "Password is valid"
    
    def validate_email(self, email):

        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(pattern, email):
            return True, "Email is valid"
        return False, "Invalid email format"
    
    def check_username_exists(self, username):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()       
        cursor.execute('SELECT user_id FROM users WHERE username = ?', (username,))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists
    
    def check_nid_exists(self, nid):

        if not nid:
            return False

        nid = nid.strip().replace(' ', '')
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT user_id, nid_encrypted FROM users WHERE nid_encrypted IS NOT NULL
        ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        for user_id, nid_encrypted in rows:
            if not nid_encrypted:
                continue
            
            try:
                decrypted_nid = self.decrypt_user_data(user_id, nid_encrypted)
                
                if decrypted_nid:
                    decrypted_nid = decrypted_nid.strip().replace(' ', '')
                    
                    if decrypted_nid == nid:
                        return True
            except Exception as e:
                print(f"Error decrypting NID for user {user_id}: {e}")
                continue
        
        return False
    
    def generate_user_id(self, username):
        import uuid
        return f"USER_{uuid.uuid4().hex[:12].upper()}"
    
    def register_user(self, username, password, email, full_name, phone=None, nid=None, role='voter'):
        # Validate password
        is_valid, message = self.validate_password(password)
        if not is_valid:
            return False, message, None
        
        # Validate email
        is_valid, message = self.validate_email(email)
        if not is_valid:
            return False, message, None
        
        # Check if username exists
        if self.check_username_exists(username):
            return False, "Username already exists", None
        
        # Check if NID exists (if provided)
        if nid:
            if self.check_nid_exists(nid):
                return False, "National ID already exists. Each NID can only be registered once.", None
        
        # Generate user ID
        user_id = self.generate_user_id(username)
        
        # Generate encryption keys for user
        user_keys = self.key_generator.generate_user_keys(user_id)
        
        # Store keys
        self.key_storage.store_user_keys(user_keys)
        
        # Prepare RSA and ECC keys for encryption
        rsa_public = (user_keys['rsa_public']['e'], user_keys['rsa_public']['n'])
        
        from crypto.ecc import Point, ECC
        ecc = ECC()
        ecc_public = Point(
            user_keys['ecc_public']['x'],
            user_keys['ecc_public']['y'],
            ecc.curve
        )
    
        mle = MultiLevelEncryption()
        email_encrypted = mle.encrypt(email, rsa_public, ecc_public)
        full_name_encrypted = mle.encrypt(full_name, rsa_public, ecc_public)
        phone_encrypted = mle.encrypt(phone, rsa_public, ecc_public) if phone else None
        nid_encrypted = mle.encrypt(nid, rsa_public, ecc_public) if nid else None
        
        # Hash password with salt
        password_hash, password_salt = HashFunction.hash_password(password)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO users (
                    user_id, username, email_encrypted, full_name_encrypted,
                    phone_encrypted, nid_encrypted,
                    password_hash, password_salt, role, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id, username, email_encrypted, full_name_encrypted,
                phone_encrypted, nid_encrypted,
                password_hash, password_salt, role, datetime.now().isoformat()
            ))
            
            conn.commit()
            return True, "Registration successful!", user_id
        
        except sqlite3.IntegrityError as e:
            return False, f"Registration failed: {str(e)}", None
        
        finally:
            conn.close()
    
    def decrypt_user_data(self, user_id, encrypted_data):
        if not encrypted_data:
            return None
        keys = self.key_storage.retrieve_user_keys(user_id)
        
        if not keys:
            return None
        rsa_private = (keys['rsa_private']['d'], keys['rsa_private']['n'])
        ecc_private = keys['ecc_private']
        
        mle = MultiLevelEncryption()
        try:
            decrypted = mle.decrypt(encrypted_data, rsa_private, ecc_private)
            return decrypted
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
