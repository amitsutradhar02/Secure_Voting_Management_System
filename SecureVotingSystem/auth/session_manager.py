import sqlite3
from datetime import datetime, timedelta
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.hashing import HashFunction
from crypto.hmac import HMAC


class SessionManager:
    
    SESSION_LIFETIME = 3600  # 1 hour in seconds
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                token_hash TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_activity TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_session(self, user_id, ip_address=None, user_agent=None, lifetime_seconds=None):

        session_token = HashFunction.generate_token(64)
        token_hash = HashFunction.hash_data(session_token)
    
        import uuid
        session_id = f"SESSION_{uuid.uuid4().hex[:16].upper()}"
        created_at = datetime.now()
        session_lifetime = lifetime_seconds if lifetime_seconds is not None else self.SESSION_LIFETIME
        expires_at = created_at + timedelta(seconds=session_lifetime)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO sessions (
                    session_id, user_id, session_token, token_hash,
                    ip_address, user_agent, created_at, expires_at, last_activity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id, user_id, session_token, token_hash,
                ip_address, user_agent,
                created_at.isoformat(), expires_at.isoformat(), created_at.isoformat()
            ))
            
            conn.commit()
            return True, session_token, "Session created successfully"
        
        except Exception as e:
            return False, None, f"Failed to create session: {str(e)}"
        
        finally:
            conn.close()
    
    def validate_session(self, session_token):

        if not session_token:
            return False, None, "No session token provided"
        
        token_hash = HashFunction.hash_data(session_token)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT session_id, user_id, expires_at, is_active
            FROM sessions
            WHERE token_hash = ?
        ''', (token_hash,))
        
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return False, None, "Invalid session token"
        
        session_id, user_id, expires_at, is_active = row
        
        if not is_active:
            conn.close()
            return False, None, "Session has been terminated"
        
        expiry_time = datetime.fromisoformat(expires_at)
        if datetime.now() > expiry_time:
            # Deactivate expired session
            cursor.execute('''
                UPDATE sessions 
                SET is_active = 0
                WHERE session_id = ?
            ''', (session_id,))
            conn.commit()
            conn.close()
            return False, None, "Session has expired"
        
        # Update last activity
        cursor.execute('''
            UPDATE sessions 
            SET last_activity = ?
            WHERE session_id = ?
        ''', (datetime.now().isoformat(), session_id))
        
        conn.commit()
        conn.close()
        
        return True, user_id, "Session is valid"
    
    def extend_session(self, session_token, additional_seconds=None):
        if additional_seconds is None:
            additional_seconds = self.SESSION_LIFETIME
        
        token_hash = HashFunction.hash_data(session_token)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT session_id, expires_at, is_active
            FROM sessions
            WHERE token_hash = ?
        ''', (token_hash,))
        
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return False, "Session not found"
        
        session_id, current_expiry, is_active = row
        
        if not is_active:
            conn.close()
            return False, "Session is not active"
        
        # Extend expiry
        new_expiry = datetime.now() + timedelta(seconds=additional_seconds)
        
        cursor.execute('''
            UPDATE sessions 
            SET expires_at = ?
            WHERE session_id = ?
        ''', (new_expiry.isoformat(), session_id))
        
        conn.commit()
        conn.close()
        
        return True, "Session extended successfully"
    
    def terminate_session(self, session_token):
        token_hash = HashFunction.hash_data(session_token)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE sessions 
            SET is_active = 0
            WHERE token_hash = ?
        ''', (token_hash,))
        
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        if affected > 0:
            return True, "Session terminated successfully"
        else:
            return False, "Session not found"
    
    def terminate_all_user_sessions(self, user_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()  
        cursor.execute('''
            UPDATE sessions 
            SET is_active = 0
            WHERE user_id = ? AND is_active = 1
        ''', (user_id,))
        
        terminated_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        return terminated_count
    
    def get_user_sessions(self, user_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT session_id, ip_address, user_agent, 
                   created_at, expires_at, last_activity
            FROM sessions
            WHERE user_id = ? AND is_active = 1
            ORDER BY last_activity DESC
        ''', (user_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        sessions = []
        for row in rows:
            expiry_time = datetime.fromisoformat(row[4])
            is_expired = datetime.now() > expiry_time
            
            if not is_expired:
                sessions.append({
                    'session_id': row[0],
                    'ip_address': row[1],
                    'user_agent': row[2],
                    'created_at': row[3],
                    'expires_at': row[4],
                    'last_activity': row[5]
                })
        
        return sessions
    
    def cleanup_expired_sessions(self):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        current_time = datetime.now().isoformat() 
        cursor.execute('''
            UPDATE sessions 
            SET is_active = 0
            WHERE expires_at < ? AND is_active = 1
        ''', (current_time,))
        
        deactivated = cursor.rowcount
        
        # Delete sessions older than 7 days
        cutoff = (datetime.now() - timedelta(days=7)).isoformat()
        
        cursor.execute('''
            DELETE FROM sessions 
            WHERE created_at < ?
        ''', (cutoff,))
        
        deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        return {'deactivated': deactivated, 'deleted': deleted}
    
    def get_session_info(self, session_token):

        token_hash = HashFunction.hash_data(session_token)       
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT session_id, user_id, ip_address, user_agent,
                   created_at, expires_at, last_activity, is_active
            FROM sessions
            WHERE token_hash = ?
        ''', (token_hash,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        expiry_time = datetime.fromisoformat(row[5])
        is_expired = datetime.now() > expiry_time
        
        return {
            'session_id': row[0],
            'user_id': row[1],
            'ip_address': row[2],
            'user_agent': row[3],
            'created_at': row[4],
            'expires_at': row[5],
            'last_activity': row[6],
            'is_active': bool(row[7]),
            'is_expired': is_expired
        }
