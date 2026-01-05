import json
import os
import sqlite3
from datetime import datetime
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.rsa import RSA
from crypto.hashing import HashFunction


class KeyStorage:
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
          
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS encryption_keys (
                key_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                key_type TEXT NOT NULL,
                rsa_public_e INTEGER,
                rsa_public_n TEXT,
                rsa_private_d TEXT,
                rsa_private_n TEXT,
                ecc_public_x TEXT,
                ecc_public_y TEXT,
                ecc_private TEXT,
                hmac_key TEXT,
                key_version INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT,
                is_active INTEGER DEFAULT 1,
                UNIQUE(user_id, key_type, key_version)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_name TEXT UNIQUE NOT NULL,
                key_value TEXT NOT NULL,
                key_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def store_user_keys(self, keys):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO encryption_keys (
                    user_id, key_type, 
                    rsa_public_e, rsa_public_n,
                    rsa_private_d, rsa_private_n,
                    ecc_public_x, ecc_public_y,
                    ecc_private, hmac_key,
                    key_version, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                keys['user_id'],
                'user',
                keys['rsa_public']['e'],
                str(keys['rsa_public']['n']),
                str(keys['rsa_private']['d']),
                str(keys['rsa_private']['n']),
                str(keys['ecc_public']['x']),
                str(keys['ecc_public']['y']),
                str(keys['ecc_private']),
                keys['hmac_key'],
                keys['key_version'],
                keys['created_at']
            ))
            
            conn.commit()
            return True
        
        except sqlite3.IntegrityError as e:
            print(f"Key storage error: {e}")
            return False
        finally:
            conn.close()
    
    def retrieve_user_keys(self, user_id, key_version=None):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if key_version:
            cursor.execute('''
                SELECT * FROM encryption_keys 
                WHERE user_id = ? AND key_type = 'user' AND key_version = ?
            ''', (user_id, key_version))
        else:
            cursor.execute('''
                SELECT * FROM encryption_keys 
                WHERE user_id = ? AND key_type = 'user' AND is_active = 1
                ORDER BY key_version DESC LIMIT 1
            ''', (user_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        keys = {
            'user_id': row[1],
            'key_type': row[2],
            'rsa_public': {
                'e': row[3],
                'n': int(row[4])
            },
            'rsa_private': {
                'd': int(row[5]),
                'n': int(row[6])
            },
            'ecc_public': {
                'x': int(row[7]),
                'y': int(row[8])
            },
            'ecc_private': int(row[9]),
            'hmac_key': row[10],
            'key_version': row[11],
            'created_at': row[12]
        }
        
        return keys
    
    def store_system_key(self, key_name, key_value, key_type='system'):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            if isinstance(key_value, dict):
                key_value = json.dumps(key_value)
            
            cursor.execute('''
                INSERT OR REPLACE INTO system_keys (
                    key_name, key_value, key_type, created_at
                ) VALUES (?, ?, ?, ?)
            ''', (
                key_name,
                key_value,
                key_type,
                datetime.now().isoformat()
            ))
            
            conn.commit()
            return True
        
        except Exception as e:
            print(f"System key storage error: {e}")
            return False
        finally:
            conn.close()
    
    def retrieve_system_key(self, key_name):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT key_value FROM system_keys 
            WHERE key_name = ? AND is_active = 1
        ''', (key_name,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        key_value = row[0]
        
        try:
            return json.loads(key_value)
        except json.JSONDecodeError:
            return key_value
    
    def deactivate_old_keys(self, user_id, keep_versions=2):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT key_id, key_version FROM encryption_keys
            WHERE user_id = ? AND key_type = 'user'
            ORDER BY key_version DESC
        ''', (user_id,))
        
        rows = cursor.fetchall()
        
        deactivated = 0
        for i, row in enumerate(rows):
            if i >= keep_versions:
                cursor.execute('''
                    UPDATE encryption_keys 
                    SET is_active = 0, updated_at = ?
                    WHERE key_id = ?
                ''', (datetime.now().isoformat(), row[0]))
                deactivated += 1
        
        conn.commit()
        conn.close()
        
        return deactivated
    
    def list_user_keys(self, user_id):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT key_version, created_at, is_active 
            FROM encryption_keys
            WHERE user_id = ? AND key_type = 'user'
            ORDER BY key_version DESC
        ''', (user_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                'version': row[0],
                'created_at': row[1],
                'is_active': bool(row[2])
            }
            for row in rows
        ]
    
    def delete_user_keys(self, user_id):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                DELETE FROM encryption_keys 
                WHERE user_id = ?
            ''', (user_id,))
            
            conn.commit()
            return True
        except Exception as e:
            print(f"Error deleting keys: {e}")
            return False
        finally:
            conn.close()

