import sqlite3
from datetime import datetime
import json

class ElectionModel:
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS elections (
                election_id TEXT PRIMARY KEY,
                title_encrypted TEXT NOT NULL,
                description_encrypted TEXT,
                start_date TEXT NOT NULL,
                end_date TEXT NOT NULL,
                created_by TEXT NOT NULL,
                status TEXT DEFAULT 'upcoming',
                created_at TEXT NOT NULL,
                FOREIGN KEY (created_by) REFERENCES users(user_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS candidates (
                candidate_id TEXT PRIMARY KEY,
                election_id TEXT NOT NULL,
                name_encrypted TEXT NOT NULL,
                party_encrypted TEXT,
                description_encrypted TEXT,
                symbol_encrypted TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (election_id) REFERENCES elections(election_id)
            )
        ''')    
        conn.commit()
        conn.close()
    
    def create_election(self, title, description, start_date, end_date, created_by, 
                       title_encrypted, description_encrypted):
        import uuid
        election_id = f"ELECTION_{uuid.uuid4().hex[:12].upper()}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO elections (
                    election_id, title_encrypted, description_encrypted,
                    start_date, end_date, created_by, created_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                election_id, title_encrypted, description_encrypted,
                start_date, end_date, created_by, 
                datetime.now().isoformat(), 'upcoming'
            ))
            
            conn.commit()
            return True, election_id
        
        except Exception as e:
            print(f"Error creating election: {e}")
            return False, None
        
        finally:
            conn.close()
    
    def add_candidate(self, election_id, name, party, description, symbol,
                     name_encrypted, party_encrypted, description_encrypted, symbol_encrypted):
        import uuid
        candidate_id = f"CANDIDATE_{uuid.uuid4().hex[:12].upper()}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO candidates (
                    candidate_id, election_id, name_encrypted, 
                    party_encrypted, description_encrypted, symbol_encrypted,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                candidate_id, election_id, name_encrypted,
                party_encrypted, description_encrypted, symbol_encrypted,
                datetime.now().isoformat()
            ))
            
            conn.commit()
            return True, candidate_id
        
        except Exception as e:
            print(f"Error adding candidate: {e}")
            return False, None
        
        finally:
            conn.close()
    
    def get_election(self, election_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT election_id, title_encrypted, description_encrypted,
                   start_date, end_date, created_by, status, created_at
            FROM elections WHERE election_id = ?
        ''', (election_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return {
            'election_id': row[0],
            'title_encrypted': row[1],
            'description_encrypted': row[2],
            'start_date': row[3],
            'end_date': row[4],
            'created_by': row[5],
            'status': row[6],
            'created_at': row[7]
        }
    
    def get_all_elections(self, status=None):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if status:
            cursor.execute('''
                SELECT election_id, title_encrypted, description_encrypted,
                       start_date, end_date, status, created_at
                FROM elections WHERE status = ?
                ORDER BY start_date DESC
            ''', (status,))
        else:
            cursor.execute('''
                SELECT election_id, title_encrypted, description_encrypted,
                       start_date, end_date, status, created_at
                FROM elections
                ORDER BY start_date DESC
            ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        elections = []
        for row in rows:
            elections.append({
                'election_id': row[0],
                'title_encrypted': row[1],
                'description_encrypted': row[2],
                'start_date': row[3],
                'end_date': row[4],
                'status': row[5],
                'created_at': row[6]
            })
        
        return elections
    
    def get_candidates(self, election_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT candidate_id, name_encrypted, party_encrypted,
                   description_encrypted, symbol_encrypted, created_at
            FROM candidates WHERE election_id = ?
            ORDER BY created_at ASC
        ''', (election_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        candidates = []
        for row in rows:
            candidates.append({
                'candidate_id': row[0],
                'name_encrypted': row[1],
                'party_encrypted': row[2],
                'description_encrypted': row[3],
                'symbol_encrypted': row[4],
                'created_at': row[5]
            })
        
        return candidates
    
    def update_election_status(self, election_id, status):
        valid_statuses = ['upcoming', 'active', 'completed', 'cancelled']
        
        if status not in valid_statuses:
            return False
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE elections SET status = ? WHERE election_id = ?
        ''', (status, election_id))
        
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        
        return success
    
    def delete_election(self, election_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Delete candidates first
            cursor.execute('DELETE FROM candidates WHERE election_id = ?', (election_id,))
            
            # Delete election
            cursor.execute('DELETE FROM elections WHERE election_id = ?', (election_id,))
            
            conn.commit()
            return True
        
        except Exception as e:
            print(f"Error deleting election: {e}")
            return False
        
        finally:
            conn.close()
    
    def count_elections(self, status=None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if status:
            cursor.execute('SELECT COUNT(*) FROM elections WHERE status = ?', (status,))
        else:
            cursor.execute('SELECT COUNT(*) FROM elections')
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count