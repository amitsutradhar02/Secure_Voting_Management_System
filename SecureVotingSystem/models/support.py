import sqlite3
from datetime import datetime
import uuid


class SupportModel:
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS support_tickets (
                ticket_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                priority TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'open',
                admin_response TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_ticket(self, user_id, username, subject, message, priority='medium'):
        ticket_id = f"TICKET_{uuid.uuid4().hex[:12].upper()}"
        now = datetime.now().isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO support_tickets (
                    ticket_id, user_id, username, subject, message,
                    priority, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ticket_id, user_id, username, subject, message,
                priority, 'open', now, now
            ))
            
            conn.commit()
            return True, ticket_id
        
        except Exception as e:
            print(f"Error creating ticket: {e}")
            return False, None
        
        finally:
            conn.close()
    
    def get_all_tickets(self, status=None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if status:
            cursor.execute('''
                SELECT ticket_id, user_id, username, subject, message,
                       priority, status, admin_response, created_at, updated_at
                FROM support_tickets
                WHERE status = ?
                ORDER BY created_at DESC
            ''', (status,))
        else:
            cursor.execute('''
                SELECT ticket_id, user_id, username, subject, message,
                       priority, status, admin_response, created_at, updated_at
                FROM support_tickets
                ORDER BY created_at DESC
            ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        tickets = []
        for row in rows:
            tickets.append({
                'ticket_id': row[0],
                'user_id': row[1],
                'username': row[2],
                'subject': row[3],
                'message': row[4],
                'priority': row[5],
                'status': row[6],
                'admin_response': row[7],
                'created_at': row[8],
                'updated_at': row[9]
            })
        
        return tickets
    
    def get_ticket(self, ticket_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ticket_id, user_id, username, subject, message,
                   priority, status, admin_response, created_at, updated_at
            FROM support_tickets
            WHERE ticket_id = ?
        ''', (ticket_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return {
            'ticket_id': row[0],
            'user_id': row[1],
            'username': row[2],
            'subject': row[3],
            'message': row[4],
            'priority': row[5],
            'status': row[6],
            'admin_response': row[7],
            'created_at': row[8],
            'updated_at': row[9]
        }
    
    def get_user_tickets(self, user_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ticket_id, subject, message, priority, status,
                   admin_response, created_at, updated_at
            FROM support_tickets
            WHERE user_id = ?
            ORDER BY created_at DESC
        ''', (user_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        tickets = []
        for row in rows:
            tickets.append({
                'ticket_id': row[0],
                'subject': row[1],
                'message': row[2],
                'priority': row[3],
                'status': row[4],
                'admin_response': row[5],
                'created_at': row[6],
                'updated_at': row[7]
            })
        
        return tickets
    
    def respond_to_ticket(self, ticket_id, admin_response, status):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE support_tickets
                SET admin_response = ?, status = ?, updated_at = ?
                WHERE ticket_id = ?
            ''', (admin_response, status, datetime.now().isoformat(), ticket_id))
            
            conn.commit()
            return cursor.rowcount > 0
        
        except Exception as e:
            print(f"Error responding to ticket: {e}")
            return False
        
        finally:
            conn.close()
    
    def count_tickets(self, status=None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if status:
            cursor.execute('SELECT COUNT(*) FROM support_tickets WHERE status = ?', (status,))
        else:
            cursor.execute('SELECT COUNT(*) FROM support_tickets')
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count
