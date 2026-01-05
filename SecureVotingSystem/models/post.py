import sqlite3
from datetime import datetime

class PostModel:
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                post_id TEXT PRIMARY KEY,
                title_encrypted TEXT NOT NULL,
                content_encrypted TEXT NOT NULL,
                author_id TEXT NOT NULL,
                category TEXT DEFAULT 'general',
                is_published INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT,
                FOREIGN KEY (author_id) REFERENCES users(user_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_post(self, title, content, author_id, category, 
                   title_encrypted, content_encrypted):
        import uuid
        post_id = f"POST_{uuid.uuid4().hex[:12].upper()}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO posts (
                    post_id, title_encrypted, content_encrypted,
                    author_id, category, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                post_id, title_encrypted, content_encrypted,
                author_id, category, datetime.now().isoformat()
            ))
            
            conn.commit()
            return True, post_id
        
        except Exception as e:
            print(f"Error creating post: {e}")
            return False, None
        
        finally:
            conn.close()
    
    def get_post(self, post_id):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT post_id, title_encrypted, content_encrypted,
                   author_id, category, is_published, created_at, updated_at
            FROM posts WHERE post_id = ?
        ''', (post_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return {
            'post_id': row[0],
            'title_encrypted': row[1],
            'content_encrypted': row[2],
            'author_id': row[3],
            'category': row[4],
            'is_published': bool(row[5]),
            'created_at': row[6],
            'updated_at': row[7]
        }
    
    def get_all_posts(self, category=None, published_only=True):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if category:
            if published_only:
                cursor.execute('''
                    SELECT post_id, title_encrypted, content_encrypted,
                           author_id, category, created_at, updated_at
                    FROM posts 
                    WHERE category = ? AND is_published = 1
                    ORDER BY created_at DESC
                ''', (category,))
            else:
                cursor.execute('''
                    SELECT post_id, title_encrypted, content_encrypted,
                           author_id, category, created_at, updated_at
                    FROM posts 
                    WHERE category = ?
                    ORDER BY created_at DESC
                ''', (category,))
        else:
            if published_only:
                cursor.execute('''
                    SELECT post_id, title_encrypted, content_encrypted,
                           author_id, category, created_at, updated_at
                    FROM posts 
                    WHERE is_published = 1
                    ORDER BY created_at DESC
                ''')
            else:
                cursor.execute('''
                    SELECT post_id, title_encrypted, content_encrypted,
                           author_id, category, created_at, updated_at
                    FROM posts 
                    ORDER BY created_at DESC
                ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        posts = []
        for row in rows:
            posts.append({
                'post_id': row[0],
                'title_encrypted': row[1],
                'content_encrypted': row[2],
                'author_id': row[3],
                'category': row[4],
                'created_at': row[5],
                'updated_at': row[6]
            })
        
        return posts
    
    def update_post(self, post_id, title_encrypted=None, content_encrypted=None, category=None):

        updates = []
        values = []
        
        if title_encrypted:
            updates.append("title_encrypted = ?")
            values.append(title_encrypted)
        
        if content_encrypted:
            updates.append("content_encrypted = ?")
            values.append(content_encrypted)
        
        if category:
            updates.append("category = ?")
            values.append(category)
        
        if not updates:
            return False
        
        updates.append("updated_at = ?")
        values.append(datetime.now().isoformat())
        
        values.append(post_id)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = f"UPDATE posts SET {', '.join(updates)} WHERE post_id = ?"
        cursor.execute(query, values)
        
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        
        return success
    
    def delete_post(self, post_id):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM posts WHERE post_id = ?', (post_id,))
        
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        
        return success
    
    def publish_post(self, post_id):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE posts SET is_published = 1 WHERE post_id = ?
        ''', (post_id,))
        
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        
        return success
    
    def unpublish_post(self, post_id):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE posts SET is_published = 0 WHERE post_id = ?
        ''', (post_id,))
        
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        
        return success
    
    def count_posts(self, category=None):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if category:
            cursor.execute('SELECT COUNT(*) FROM posts WHERE category = ?', (category,))
        else:
            cursor.execute('SELECT COUNT(*) FROM posts')
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count