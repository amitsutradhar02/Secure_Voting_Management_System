import sqlite3
from datetime import datetime, timedelta
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.hashing import HashFunction


class Login:
    
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15
    
    def __init__(self, db_path):
        self.db_path = db_path
    
    def check_account_lockout(self, username):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT lockout_until, failed_login_attempts 
            FROM users WHERE username = ?
        ''', (username,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return False, 0
        
        lockout_until, failed_attempts = row
        
        if lockout_until:
            lockout_time = datetime.fromisoformat(lockout_until)
            
            if datetime.now() < lockout_time:
                remaining = (lockout_time - datetime.now()).seconds
                return True, remaining
            else:
                # Lockout expired, reset
                self.reset_failed_attempts(username)
                return False, 0
        
        return False, 0
    
    def authenticate(self, username, password):

        is_locked, remaining_time = self.check_account_lockout(username)
        
        if is_locked:
            minutes = remaining_time // 60
            seconds = remaining_time % 60
            return False, f"Account locked. Try again in {minutes}m {seconds}s", None

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT user_id, username, password_hash, password_salt, 
                   role, is_verified, is_active, failed_login_attempts
            FROM users WHERE username = ?
        ''', (username,))
        
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return False, "Invalid username or password", None
        
        user_id, username, password_hash, password_salt, role, is_verified, is_active, failed_attempts = row
        
        # Check if account is active
        if not is_active:
            conn.close()
            return False, "Account is deactivated", None
        
        # Verify password
        is_valid = HashFunction.verify_password(password, password_hash, password_salt)
        
        if not is_valid:
            # Increment failed attempts
            failed_attempts += 1
            
            if failed_attempts >= self.MAX_LOGIN_ATTEMPTS:
                # Lock account
                lockout_until = datetime.now() + timedelta(minutes=self.LOCKOUT_MINUTES)
                cursor.execute('''
                    UPDATE users 
                    SET failed_login_attempts = ?, lockout_until = ?
                    WHERE username = ?
                ''', (failed_attempts, lockout_until.isoformat(), username))
                
                conn.commit()
                conn.close()
                return False, f"Account locked due to {self.MAX_LOGIN_ATTEMPTS} failed attempts", None
            else:
                # Update failed attempts
                cursor.execute('''
                    UPDATE users 
                    SET failed_login_attempts = ?
                    WHERE username = ?
                ''', (failed_attempts, username))
                
                conn.commit()
                conn.close()
                remaining_attempts = self.MAX_LOGIN_ATTEMPTS - failed_attempts
                return False, f"Invalid username or password. {remaining_attempts} attempts remaining", None
        
        cursor.execute('''
            UPDATE users 
            SET failed_login_attempts = 0, 
                lockout_until = NULL,
                last_login = ?
            WHERE username = ?
        ''', (datetime.now().isoformat(), username))
        
        conn.commit()
        conn.close()
        user_data = {
            'user_id': user_id,
            'username': username,
            'role': role,
            'is_verified': bool(is_verified)
        }
        
        return True, "Authentication successful", user_data
    
    def reset_failed_attempts(self, username):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users 
            SET failed_login_attempts = 0, lockout_until = NULL
            WHERE username = ?
        ''', (username,))
        
        conn.commit()
        conn.close()
    
    def update_last_login(self, user_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users 
            SET last_login = ?
            WHERE user_id = ?
        ''', (datetime.now().isoformat(), user_id))
        
        conn.commit()
        conn.close()
    
    def change_password(self, user_id, old_password, new_password):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT password_hash, password_salt 
            FROM users WHERE user_id = ?
        ''', (user_id,))
        
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return False, "User not found"
        
        current_hash, current_salt = row
        
        is_valid = HashFunction.verify_password(old_password, current_hash, current_salt)
        
        if not is_valid:
            conn.close()
            return False, "Current password is incorrect"
        
        new_hash, new_salt = HashFunction.hash_password(new_password)
        cursor.execute('''
            UPDATE users 
            SET password_hash = ?, password_salt = ?
            WHERE user_id = ?
        ''', (new_hash, new_salt, user_id))
        
        conn.commit()
        conn.close()
        
        return True, "Password changed successfully"
    
    def get_user_info(self, user_id):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT user_id, username, role, is_verified, 
                   is_active, created_at, last_login
            FROM users WHERE user_id = ?
        ''', (user_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return {
            'user_id': row[0],
            'username': row[1],
            'role': row[2],
            'is_verified': bool(row[3]),
            'is_active': bool(row[4]),
            'created_at': row[5],
            'last_login': row[6]
        }
