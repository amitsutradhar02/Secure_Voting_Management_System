import sqlite3
from datetime import datetime


class VoteModel:
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS votes (
                vote_id TEXT PRIMARY KEY,
                election_id TEXT NOT NULL,
                voter_id_encrypted TEXT NOT NULL,
                candidate_id_encrypted TEXT NOT NULL,
                vote_hash TEXT NOT NULL,
                vote_hmac TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                ip_address TEXT,
                FOREIGN KEY (election_id) REFERENCES elections(election_id)
            )
        ''')
 
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_election_votes 
            ON votes(election_id)
        ''')
        
        conn.commit()
        conn.close()
    
    def cast_vote(self, election_id, voter_id, candidate_id, 
                  voter_id_encrypted, candidate_id_encrypted, 
                  vote_hash, vote_hmac, ip_address=None):

        if self.has_voted(election_id, voter_id):
            return False, "You have already voted in this election"
        
        import uuid
        vote_id = f"VOTE_{uuid.uuid4().hex[:12].upper()}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO votes (
                    vote_id, election_id, voter_id_encrypted, 
                    candidate_id_encrypted, vote_hash, vote_hmac,
                    timestamp, ip_address
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vote_id, election_id, voter_id_encrypted,
                candidate_id_encrypted, vote_hash, vote_hmac,
                datetime.now().isoformat(), ip_address
            ))
            
            conn.commit()
            return True, "Vote cast successfully"
        
        except Exception as e:
            print(f"Error casting vote: {e}")
            return False, "Failed to cast vote"
        
        finally:
            conn.close()
    
    def has_voted(self, election_id, voter_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vote_tracking (
                election_id TEXT NOT NULL,
                voter_id TEXT NOT NULL,
                voted_at TEXT NOT NULL,
                PRIMARY KEY (election_id, voter_id)
            )
        ''')
        
        cursor.execute('''
            SELECT voter_id FROM vote_tracking 
            WHERE election_id = ? AND voter_id = ?
        ''', (election_id, voter_id))
        
        has_voted = cursor.fetchone() is not None
        conn.close()
        
        return has_voted
    
    def mark_as_voted(self, election_id, voter_id):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO vote_tracking (election_id, voter_id, voted_at)
                VALUES (?, ?, ?)
            ''', (election_id, voter_id, datetime.now().isoformat()))
            
            conn.commit()
            return True
        except:
            return False
        finally:
            conn.close()
    
    def get_vote_count(self, election_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM votes WHERE election_id = ?
        ''', (election_id,))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count
    
    def get_all_votes(self, election_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT vote_id, voter_id_encrypted, candidate_id_encrypted,
                   vote_hash, vote_hmac, timestamp
            FROM votes WHERE election_id = ?
            ORDER BY timestamp DESC
        ''', (election_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        votes = []
        for row in rows:
            votes.append({
                'vote_id': row[0],
                'voter_id_encrypted': row[1],
                'candidate_id_encrypted': row[2],
                'vote_hash': row[3],
                'vote_hmac': row[4],
                'timestamp': row[5]
            })
        
        return votes
    
    def verify_vote_integrity(self, vote_id, expected_hmac):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT vote_hmac FROM votes WHERE vote_id = ?
        ''', (vote_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return False
        
        stored_hmac = row[0]
        return stored_hmac == expected_hmac
    
    def get_voting_history(self, voter_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT election_id, voted_at FROM vote_tracking
            WHERE voter_id = ?
            ORDER BY voted_at DESC
        ''', (voter_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        history = []
        for row in rows:
            history.append({
                'election_id': row[0],
                'voted_at': row[1]
            })
        
        return history
    
    def get_election_results(self, election_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT candidate_id_encrypted, COUNT(*) as vote_count
            FROM votes
            WHERE election_id = ?
            GROUP BY candidate_id_encrypted
            ORDER BY vote_count DESC
        ''', (election_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        results = []
        for row in rows:
            results.append({
                'candidate_id_encrypted': row[0],
                'vote_count': row[1]
            })
        
        return results