import sqlite3

class KeyModel:
    
    def __init__(self, db_path):
        self.db_path = db_path
    
    def get_active_keys(self, user_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM encryption_keys 
            WHERE user_id = ? AND is_active = 1
        """, (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result
