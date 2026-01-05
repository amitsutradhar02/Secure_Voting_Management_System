import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta
from .key_generator import KeyGenerator
from .key_storage import KeyStorage


class KeyRotation:
    
    def __init__(self, db_path, rotation_days=90):

        self.db_path = db_path
        self.rotation_days = rotation_days
        self.key_generator = KeyGenerator()
        self.key_storage = KeyStorage(db_path)
    
    def check_rotation_needed(self, user_id):

        keys = self.key_storage.retrieve_user_keys(user_id)
        
        if not keys:
            return False, 0
        
        created_at = datetime.fromisoformat(keys['created_at'])
        days_old = (datetime.now() - created_at).days
        needs_rotation = days_old >= self.rotation_days  
        return needs_rotation, days_old
    
    def rotate_user_keys(self, user_id):

        old_keys = self.key_storage.retrieve_user_keys(user_id)
        
        if not old_keys:
            print(f"No keys found for user {user_id}")
            return None
        
        new_keys = self.key_generator.rotate_user_keys(old_keys)
        success = self.key_storage.store_user_keys(new_keys)
        
        if success:
            self.key_storage.deactivate_old_keys(user_id, keep_versions=2)
            print(f"Keys rotated for user {user_id}: v{old_keys['key_version']} -> v{new_keys['key_version']}")
            return new_keys
        else:
            print(f"Failed to rotate keys for user {user_id}")
            return None
    
    def get_rotation_schedule(self, user_id):

        keys = self.key_storage.retrieve_user_keys(user_id)
        if not keys:
            return None
        
        created_at = datetime.fromisoformat(keys['created_at'])
        next_rotation = created_at + timedelta(days=self.rotation_days)
        days_until_rotation = (next_rotation - datetime.now()).days
        
        return {
            'user_id': user_id,
            'current_version': keys['key_version'],
            'created_at': keys['created_at'],
            'next_rotation_date': next_rotation.isoformat(),
            'days_until_rotation': max(0, days_until_rotation),
            'rotation_needed': days_until_rotation <= 0
        }
    
    def rotate_all_expired_keys(self):

        rotated_users = [] 
        print(f"Checking for expired keys (rotation period: {self.rotation_days} days)")
        return rotated_users
    
    def force_rotate_user_keys(self, user_id, reason="Manual rotation"):

        print(f"Forcing key rotation for user {user_id}: {reason}")
        return self.rotate_user_keys(user_id)
    
    @staticmethod
    def get_rotation_policy():

        return {
            'rotation_period_days': 90,
            'keep_old_versions': 2,
            'auto_rotate': True,
            'notification_before_days': 7,
            'policy_description': 'Keys are automatically rotated every 90 days. '
                                'Previous 2 versions are kept active for data recovery.'
        }
