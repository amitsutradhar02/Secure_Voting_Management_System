from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from middleware.rbac import require_auth, admin_only
from models.user import UserModel
from models.election import ElectionModel
from models.vote import VoteModel
from models.post import PostModel
from middleware.encryption_middleware import EncryptionMiddleware
from auth.login import Login
from auth.two_factor import TwoFactorAuth
from utils.email_sender import send_otp_email
from config import Config

user_bp = Blueprint('user', __name__)
user_model = UserModel(Config.DATABASE_PATH)
election_model = ElectionModel(Config.DATABASE_PATH)
vote_model = VoteModel(Config.DATABASE_PATH)
post_model = PostModel(Config.DATABASE_PATH)
encryption_middleware = EncryptionMiddleware(Config.DATABASE_PATH)
login_module = Login(Config.DATABASE_PATH)
two_factor = TwoFactorAuth(Config.DATABASE_PATH)

@user_bp.route('/dashboard')
@require_auth
def dashboard():
    user_id = session.get('user_id')
    role = session.get('role')
    user = user_model.get_user_by_id(user_id)
    
    if user:
        user['email'] = encryption_middleware.decrypt_data(user['email_encrypted'], user_id)
        user['full_name'] = encryption_middleware.decrypt_data(user['full_name_encrypted'], user_id)
    
    if role == 'admin':
        # Admin dashboard
        total_users = user_model.count_users()
        total_voters = user_model.count_users('voter')
        total_elections = election_model.count_elections()
        active_elections = election_model.count_elections('active')
        
        # Get recent elections
        elections = election_model.get_all_elections()[:5]
        
        # Decrypt election titles
        for election in elections:
            election['title'] = "Election" 
        
        posts = post_model.get_all_posts()[:5]
        
        return render_template('user/admin_dashboard_complete.html',
                             user=user,
                             total_users=total_users,
                             total_voters=total_voters,
                             total_elections=total_elections,
                             active_elections=active_elections,
                             elections=elections,
                             posts=posts)
    else:
        active_elections = election_model.get_all_elections('active')
        # Get voting history
        voting_history = vote_model.get_voting_history(user_id)
        # Get recent announcements
        posts = post_model.get_all_posts()[:5]
        
        return render_template('user/voter_dashboard.html',
                             user=user,
                             active_elections=active_elections,
                             voting_history=voting_history,
                             posts=posts)

@user_bp.route('/profile')
@require_auth
def profile():
    """User profile page"""
    user_id = session.get('user_id')
    user = user_model.get_user_by_id(user_id)
    
    if user:
        user['email'] = encryption_middleware.decrypt_data(user['email_encrypted'], user_id)
        user['full_name'] = encryption_middleware.decrypt_data(user['full_name_encrypted'], user_id)
        
        if user['phone_encrypted']:
            user['phone'] = encryption_middleware.decrypt_data(user['phone_encrypted'], user_id)
        
        if user['nid_encrypted']:
            user['nid'] = encryption_middleware.decrypt_data(user['nid_encrypted'], user_id)
    
    return render_template('user/profile.html', user=user)

@user_bp.route('/profile/edit', methods=['GET', 'POST'])
@require_auth
def edit_profile():
    user_id = session.get('user_id')
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        full_name = request.form.get('full_name', '').strip()
        phone = request.form.get('phone', '').strip()
        email_encrypted = encryption_middleware.encrypt_data(email, user_id)
        full_name_encrypted = encryption_middleware.encrypt_data(full_name, user_id)
        phone_encrypted = encryption_middleware.encrypt_data(phone, user_id) if phone else None
        success = user_model.update_user_profile(
            user_id,
            email_encrypted=email_encrypted,
            full_name_encrypted=full_name_encrypted,
            phone_encrypted=phone_encrypted
        )
        
        if success:
            flash('Profile updated successfully', 'success')
            return redirect(url_for('user.profile'))
        else:
            flash('Failed to update profile', 'error')
    
    user = user_model.get_user_by_id(user_id)
    
    if user:
        user['email'] = encryption_middleware.decrypt_data(user['email_encrypted'], user_id)
        user['full_name'] = encryption_middleware.decrypt_data(user['full_name_encrypted'], user_id)
        
        if user['phone_encrypted']:
            user['phone'] = encryption_middleware.decrypt_data(user['phone_encrypted'], user_id)
    
    return render_template('user/edit_profile.html', user=user)

@user_bp.route('/change-password/request-otp', methods=['POST'])
@require_auth
def request_password_change_otp():
    user_id = session.get('user_id')
    
    user = user_model.get_user_by_id(user_id)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('user.change_password'))
    
    email = encryption_middleware.decrypt_data(user['email_encrypted'], user_id)
    full_name = encryption_middleware.decrypt_data(user['full_name_encrypted'], user_id)
    success, otp_code, message = two_factor.generate_otp(user_id)
    
    if success:
        send_otp_email(email, otp_code, full_name)
        flash('OTP has been sent to your email address. Please check your inbox.', 'success')
        return redirect(url_for('user.verify_password_change_otp'))
    else:
        flash(f'Failed to generate OTP: {message}', 'error')
        return redirect(url_for('user.change_password'))


@user_bp.route('/change-password/verify-otp', methods=['GET', 'POST'])
@require_auth
def verify_password_change_otp():

    user_id = session.get('user_id')
    must_change = session.get('must_change_password', False)
    
    if request.method == 'POST':
        otp_code = request.form.get('otp', '').strip()
        
        if not otp_code:
            flash('Please enter the OTP code', 'error')
            return render_template('user/verify_password_change_otp.html', must_change=must_change)
        
        success, message = two_factor.verify_otp(user_id, otp_code)
        
        if success:

            session['password_change_otp_verified'] = True
            flash('OTP verified successfully! You can now change your password.', 'success')
            return redirect(url_for('user.change_password'))
        else:
            flash(message, 'error')
    
    return render_template('user/verify_password_change_otp.html', must_change=must_change)


@user_bp.route('/change-password', methods=['GET', 'POST'])
@require_auth
def change_password():

    user_id = session.get('user_id')
    must_change = session.get('must_change_password', False)
    otp_verified = session.get('password_change_otp_verified', False)
    
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('user/change_password.html', 
                                 must_change=must_change, 
                                 otp_verified=otp_verified)
        
        if must_change:
            user = user_model.get_user_by_id(user_id)
            
            if not user:
                flash('User not found', 'error')
                return render_template('user/change_password.html', 
                                     must_change=must_change, 
                                     otp_verified=otp_verified)

            from utils.validators import validate_password
            is_valid_password, msg_password = validate_password(new_password)
            if not is_valid_password:
                flash(msg_password, 'error')
                return render_template('user/change_password.html', 
                                     must_change=must_change, 
                                     otp_verified=otp_verified)
            
            from crypto.hashing import HashFunction
            import sqlite3
            new_hash, new_salt = HashFunction.hash_password(new_password)
            
            conn = sqlite3.connect(Config.DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET password_hash = ?, password_salt = ?
                WHERE user_id = ?
            ''', (new_hash, new_salt, user_id))
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_flags (
                    user_id TEXT PRIMARY KEY,
                    must_change_password INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')
            cursor.execute('''
                INSERT OR REPLACE INTO user_flags (user_id, must_change_password)
                VALUES (?, 0)
            ''', (user_id,))
            
            conn.commit()
            conn.close()
            
            session['must_change_password'] = False
            session.pop('password_change_otp_verified', None)
            
            flash('Password changed successfully! You can now use your new password to login.', 'success')
            return redirect(url_for('user.dashboard'))
        else:
            if not otp_verified:
                flash('Please verify OTP first before changing password', 'error')
                return redirect(url_for('user.change_password'))
            
            from utils.validators import validate_password
            is_valid_password, msg_password = validate_password(new_password)
            if not is_valid_password:
                flash(msg_password, 'error')
                return render_template('user/change_password.html', 
                                     must_change=must_change, 
                                     otp_verified=otp_verified)
            
            from crypto.hashing import HashFunction
            import sqlite3
            new_hash, new_salt = HashFunction.hash_password(new_password)
            
            conn = sqlite3.connect(Config.DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET password_hash = ?, password_salt = ?
                WHERE user_id = ?
            ''', (new_hash, new_salt, user_id))
            
            conn.commit()
            conn.close()
            session.pop('password_change_otp_verified', None)
            
            flash('Password changed successfully!', 'success')
            return redirect(url_for('user.profile'))
    
    if must_change:
        return render_template('user/change_password.html', 
                             must_change=must_change, 
                             otp_verified=True)
    elif otp_verified:
        return render_template('user/change_password.html', 
                             must_change=must_change, 
                             otp_verified=otp_verified)
    else:
        return render_template('user/change_password.html', 
                             must_change=must_change, 
                             otp_verified=False)


@user_bp.route('/users')
@admin_only
def list_users():
    users = user_model.get_all_users()
    return render_template('user/list_users.html', users=users)


@user_bp.route('/users/<user_id>/activate')
@admin_only
def activate_user(user_id):
    success = user_model.activate_user(user_id)
    
    if success:
        flash('User activated successfully', 'success')
    else:
        flash('Failed to activate user', 'error')
    
    return redirect(url_for('user.list_users'))


@user_bp.route('/users/<user_id>/deactivate')
@admin_only
def deactivate_user(user_id):
    success = user_model.deactivate_user(user_id)
    
    if success:
        flash('User deactivated successfully', 'success')
    else:
        flash('Failed to deactivate user', 'error')
    
    return redirect(url_for('user.list_users'))

@user_bp.route('/users/<user_id>/delete', methods=['POST'])
@admin_only
def delete_user(user_id):
    import sqlite3
    
    user = user_model.get_user_by_id(user_id)
    if user and user['role'] == 'admin':
        flash('Cannot delete admin users', 'error')
        return redirect(url_for('user.list_users'))
    
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute('DELETE FROM users WHERE user_id = ?', (user_id,))
        conn.commit()
        flash('User deleted successfully', 'success')
    except Exception as e:
        print(f"Error deleting user: {e}")
        flash('Failed to delete user', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('user.list_users'))