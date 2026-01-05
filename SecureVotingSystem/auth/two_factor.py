import sqlite3
from datetime import datetime, timedelta
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.hashing import HashFunction


class TwoFactorAuth:
    
    OTP_LENGTH = 6
    OTP_EXPIRY_MINUTES = 5
    MAX_OTP_ATTEMPTS = 3
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS otp_codes (
                otp_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                otp_code TEXT NOT NULL,
                otp_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                is_used INTEGER DEFAULT 0,
                verification_attempts INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def generate_otp(self, user_id):

        otp_code = HashFunction.generate_otp(self.OTP_LENGTH)
        otp_hash = HashFunction.hash_data(otp_code)
        # Calculate expiry
        created_at = datetime.now()
        expires_at = created_at + timedelta(minutes=self.OTP_EXPIRY_MINUTES)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE otp_codes 
                SET is_used = 1 
                WHERE user_id = ? AND is_used = 0
            ''', (user_id,))
            
            cursor.execute('''
                INSERT INTO otp_codes (
                    user_id, otp_code, otp_hash, 
                    created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?)
            ''', (
                user_id, otp_code, otp_hash,
                created_at.isoformat(), expires_at.isoformat()
            ))
            
            conn.commit()     
            return True, otp_code, "OTP generated successfully"
        
        except Exception as e:
            return False, None, f"Failed to generate OTP: {str(e)}"
        
        finally:
            conn.close()
    
    def verify_otp(self, user_id, otp_code):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT otp_id, otp_hash, expires_at, verification_attempts
            FROM otp_codes
            WHERE user_id = ? AND is_used = 0
            ORDER BY created_at DESC
            LIMIT 1
        ''', (user_id,))
        
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return False, "No valid OTP found. Please request a new one"
        
        otp_id, otp_hash, expires_at, attempts = row

        expiry_time = datetime.fromisoformat(expires_at)
        if datetime.now() > expiry_time:
            # Mark as used
            cursor.execute('UPDATE otp_codes SET is_used = 1 WHERE otp_id = ?', (otp_id,))
            conn.commit()
            conn.close()
            return False, "OTP has expired. Please request a new one" 
        # Check attempts
        if attempts >= self.MAX_OTP_ATTEMPTS:
            cursor.execute('UPDATE otp_codes SET is_used = 1 WHERE otp_id = ?', (otp_id,))
            conn.commit()
            conn.close()
            return False, "Maximum verification attempts exceeded. Please request a new OTP"
        # Verify OTP
        provided_hash = HashFunction.hash_data(otp_code)
        
        if provided_hash == otp_hash:
            # OTP is correct - mark as used
            cursor.execute('''
                UPDATE otp_codes 
                SET is_used = 1
                WHERE otp_id = ?
            ''', (otp_id,))
            
            # Update user verification status
            cursor.execute('''
                UPDATE users 
                SET is_verified = 1
                WHERE user_id = ?
            ''', (user_id,))
            
            conn.commit()
            conn.close()
            return True, "OTP verified successfully"
        else:
            # Incorrect OTP - increment attempts
            attempts += 1
            cursor.execute('''
                UPDATE otp_codes 
                SET verification_attempts = ?
                WHERE otp_id = ?
            ''', (attempts, otp_id))
            
            conn.commit()
            conn.close()
            
            remaining = self.MAX_OTP_ATTEMPTS - attempts
            if remaining > 0:
                return False, f"Incorrect OTP. {remaining} attempts remaining"
            else:
                return False, "Maximum attempts exceeded. Please request a new OTP"
    
    def send_otp_email(self, user_id, email, otp_code=None):
        if otp_code is None:
            success, otp_code, message = self.generate_otp(user_id)
            if not success:
                return False, message
        print(f"\n{'='*50}")
        print(f"OTP Email to {email}")
        print(f"{'='*50}")
        print(f"Your OTP code is: {otp_code}")
        print(f"This code will expire in {self.OTP_EXPIRY_MINUTES} minutes")
        print(f"{'='*50}\n")
        
        return True, f"OTP sent to {email}"
    
    def send_otp_sms(self, user_id, phone):

        success, otp_code, message = self.generate_otp(user_id)
        
        if not success:
            return False, message

        print(f"\n{'='*50}")
        print(f"OTP SMS to {phone}")
        print(f"{'='*50}")
        print(f"Your OTP: {otp_code}")
        print(f"Expires in {self.OTP_EXPIRY_MINUTES} min")
        print(f"{'='*50}\n")
        
        return True, f"OTP sent to {phone}"
    
    def get_otp_status(self, user_id):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT created_at, expires_at, is_used, verification_attempts
            FROM otp_codes
            WHERE user_id = ? 
            ORDER BY created_at DESC
            LIMIT 1
        ''', (user_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        created_at, expires_at, is_used, attempts = row
        
        expiry_time = datetime.fromisoformat(expires_at)
        is_expired = datetime.now() > expiry_time
        
        return {
            'created_at': created_at,
            'expires_at': expires_at,
            'is_used': bool(is_used),
            'is_expired': is_expired,
            'attempts': attempts,
            'max_attempts': self.MAX_OTP_ATTEMPTS
        }
    
    def cleanup_expired_otps(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # Delete OTPs older than 24 hours
        cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
        
        cursor.execute('''
            DELETE FROM otp_codes 
            WHERE created_at < ?
        ''', (cutoff,))
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted_count
