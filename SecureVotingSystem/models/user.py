import sqlite3
from datetime import datetime

class UserModel:
    
    def __init__(self, db_path):
        self.db_path = db_path
    
    def get_user_by_id(self, user_id):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT user_id, username, email_encrypted, full_name_encrypted,
                   phone_encrypted, nid_encrypted, role, is_verified, 
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
            'email_encrypted': row[2],
            'full_name_encrypted': row[3],
            'phone_encrypted': row[4],
            'nid_encrypted': row[5],
            'role': row[6],
            'is_verified': bool(row[7]),
            'is_active': bool(row[8]),
            'created_at': row[9],
            'last_login': row[10]
        }
    
    def get_user_by_username(self, username):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT user_id, username, role, is_verified, is_active
            FROM users WHERE username = ?
        ''', (username,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return {
            'user_id': row[0],
            'username': row[1],
            'role': row[2],
            'is_verified': bool(row[3]),
            'is_active': bool(row[4])
        }
    
    def update_user_profile(self, user_id, **kwargs):

        allowed_fields = ['email_encrypted', 'full_name_encrypted', 
                         'phone_encrypted', 'nid_encrypted']
        
        updates = []
        values = []
        
        for field, value in kwargs.items():
            if field in allowed_fields and value is not None:
                updates.append(f"{field} = ?")
                values.append(value)
        
        if not updates:
            return False
        
        values.append(user_id)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = f"UPDATE users SET {', '.join(updates)} WHERE user_id = ?"
        cursor.execute(query, values)
        
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        
        return success
    
    def deactivate_user(self, user_id):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users SET is_active = 0 WHERE user_id = ?
        ''', (user_id,))
        
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        
        return success
    
    def activate_user(self, user_id):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users SET is_active = 1 WHERE user_id = ?
        ''', (user_id,))
        
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        
        return success
    
    def get_all_users(self, role=None):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if role:
            cursor.execute('''
                SELECT user_id, username, role, is_verified, is_active, created_at
                FROM users WHERE role = ?
                ORDER BY created_at DESC
            ''', (role,))
        else:
            cursor.execute('''
                SELECT user_id, username, role, is_verified, is_active, created_at
                FROM users
                ORDER BY created_at DESC
            ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        users = []
        for row in rows:
            users.append({
                'user_id': row[0],
                'username': row[1],
                'role': row[2],
                'is_verified': bool(row[3]),
                'is_active': bool(row[4]),
                'created_at': row[5]
            })
        
        return users
    
    def count_users(self, role=None):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if role:
            cursor.execute('SELECT COUNT(*) FROM users WHERE role = ?', (role,))
        else:
            cursor.execute('SELECT COUNT(*) FROM users')
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count