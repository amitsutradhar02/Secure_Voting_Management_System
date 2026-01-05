from functools import wraps
from flask import session, redirect, url_for, flash, request

def require_auth(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def require_role(*roles):

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):

            if 'user_id' not in session:
                flash('Please log in to access this page', 'error')
                return redirect(url_for('auth.login'))
            
            user_role = session.get('role')
            
            if user_role not in roles:
                flash('You do not have permission to access this page', 'error')
                return redirect(url_for('user.dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def check_permission(user_id, resource_type, resource_id=None):

    user_role = session.get('role')
    
    # Admin has access to everything
    if user_role == 'admin':
        return True
    
    # Resource-specific permissions
    if resource_type == 'election':
        # Only admin can create/edit elections
        return user_role == 'admin'
    
    elif resource_type == 'post':
        # Only admin can create/edit posts
        return user_role == 'admin'
    
    elif resource_type == 'vote':
        # All verified voters can vote
        is_verified = session.get('is_verified', False)
        return user_role == 'voter' and is_verified
    
    elif resource_type == 'profile':
        # Users can only edit their own profile
        if resource_id:
            return user_id == resource_id
        return True
    
    return False

def require_verified(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('auth.login'))
        
        is_verified = session.get('is_verified', False)
        
        if not is_verified:
            flash('Please verify your account first', 'warning')
            return redirect(url_for('auth.verify_2fa'))
        
        return f(*args, **kwargs)
    return decorated_function

def admin_only(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('auth.login'))
        
        if session.get('role') != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('user.dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

def voter_only(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('auth.login'))
        
        if session.get('role') != 'voter':
            flash('Voter access required', 'error')
            return redirect(url_for('user.dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function