from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from datetime import timedelta
from auth.registration import Registration
from auth.login import Login
from auth.two_factor import TwoFactorAuth
from auth.session_manager import SessionManager
from utils.validators import validate_email, validate_password, validate_phone, validate_nid, sanitize_input
from config import Config

auth_bp = Blueprint('auth', __name__)
registration = Registration(Config.DATABASE_PATH)
login_module = Login(Config.DATABASE_PATH)
two_factor = TwoFactorAuth(Config.DATABASE_PATH)
session_manager = SessionManager(Config.DATABASE_PATH)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('user.dashboard'))
    
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', '').strip())
        password = request.form.get('password', '')
        remember_me = request.form.get('rememberMe') == 'on'  
        
        if not username or not password:
            flash('Please provide both username and password', 'error')
            return render_template('auth/login.html')
        
        # Authenticate user
        success, message, user_data = login_module.authenticate(username, password)
        
        if success:
            # Store remember me preference temporarily
            session['remember_me'] = remember_me
            # Check if this was a recovery OTP login
            import sqlite3
            from datetime import datetime
            from crypto.hashing import HashFunction
            
            conn = sqlite3.connect(Config.DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS recovery_otps (
                    user_id TEXT PRIMARY KEY,
                    otp_hash TEXT NOT NULL,
                    otp_salt TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')
            
            # Check if password matches an active OTP
            cursor.execute('''
                SELECT otp_hash, otp_salt, expires_at 
                FROM recovery_otps 
                WHERE user_id = ? AND expires_at > ?
            ''', (user_data['user_id'], datetime.now().isoformat()))
            
            otp_row = cursor.fetchone()
            is_otp_login = False
            
            if otp_row:
                otp_hash, otp_salt, _ = otp_row
                # Verify if the password they used matches the OTP
                if HashFunction.verify_password(password, otp_hash, otp_salt):
                    is_otp_login = True
                    # Set flag that password must be changed
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS user_flags (
                            user_id TEXT PRIMARY KEY,
                            must_change_password INTEGER DEFAULT 0,
                            FOREIGN KEY (user_id) REFERENCES users(user_id)
                        )
                    ''')
                    cursor.execute('''
                        INSERT OR REPLACE INTO user_flags (user_id, must_change_password)
                        VALUES (?, 1)
                    ''', (user_data['user_id'],))
                    conn.commit()
            
            conn.close()
            session['temp_user_id'] = user_data['user_id']
            session['temp_username'] = user_data['username']
            session['temp_role'] = user_data['role']
            session['temp_is_verified'] = user_data['is_verified']
            session['temp_is_otp_login'] = is_otp_login 
            
            from models.user import UserModel
            user_model = UserModel(Config.DATABASE_PATH)
            user = user_model.get_user_by_id(user_data['user_id'])
            
            if user:
                # Decrypt email
                from middleware.encryption_middleware import EncryptionMiddleware
                em = EncryptionMiddleware(Config.DATABASE_PATH)
                email = em.decrypt_data(user['email_encrypted'], user_data['user_id'])
                
                # Send OTP
                success_otp, otp_code, msg_otp = two_factor.generate_otp(user_data['user_id'])
                
                if success_otp:
                    # For development, we are showing OTP in console
                    print(f"\n{'='*50}\nOTP for {username}: {otp_code}\n{'='*50}\n")
                    
                    if email:
                        two_factor.send_otp_email(user_data['user_id'], email, otp_code=otp_code)
                    
                    flash('OTP sent to your email. Please verify.', 'success')
                    return redirect(url_for('auth.verify_2fa'))
            
            flash('Login successful, but 2FA setup failed', 'warning')
            return redirect(url_for('auth.verify_2fa'))
        else:
            flash(message, 'error')
    
    return render_template('auth/login.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():

    if 'user_id' in session:
        return redirect(url_for('user.dashboard'))
    
    if request.method == 'POST':

        username = sanitize_input(request.form.get('username', '').strip())
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        email = sanitize_input(request.form.get('email', '').strip())
        full_name = sanitize_input(request.form.get('full_name', '').strip())
        phone = sanitize_input(request.form.get('phone', '').strip())
        nid = sanitize_input(request.form.get('nid', '').strip())
        role = request.form.get('role', 'voter')
        
        is_valid_email, msg_email = validate_email(email)
        if not is_valid_email:
            flash(msg_email, 'error')
            return render_template('auth/register.html')
        
        is_valid_password, msg_password = validate_password(password)
        if not is_valid_password:
            flash(msg_password, 'error')
            return render_template('auth/register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('auth/register.html')
        
        if phone:
            is_valid_phone, msg_phone = validate_phone(phone)
            if not is_valid_phone:
                flash(msg_phone, 'error')
                return render_template('auth/register.html')

        if not nid:
            flash('National ID is required', 'error')
            return render_template('auth/register.html')
        
        is_valid_nid, msg_nid = validate_nid(nid)
        if not is_valid_nid:
            flash(msg_nid, 'error')
            return render_template('auth/register.html')
        
        # Register user
        success, message, user_id = registration.register_user(
            username=username,
            password=password,
            email=email,
            full_name=full_name,
            phone=phone,
            nid=nid,
            role=role
        )
        
        if success:
            flash('Registration successful! Please check your email for OTP verification.', 'success')
            
            # Store user ID for 2FA
            session['temp_user_id'] = user_id
            session['temp_username'] = username
            session['temp_role'] = role
            
            # Send OTP
            success_otp, otp_code, msg_otp = two_factor.generate_otp(user_id)
            if success_otp:
                print(f"\n{'='*50}\nOTP for {username}: {otp_code}\n{'='*50}\n")
                # Pass the already-generated OTP to avoid generating a second one
                two_factor.send_otp_email(user_id, email, otp_code=otp_code)
            
            return redirect(url_for('auth.verify_2fa'))
        else:
            flash(message, 'error')
    
    return render_template('auth/register.html')


@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():

    if 'temp_user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        otp_code = request.form.get('otp_code', '').strip()
        user_id = session.get('temp_user_id')
        
        if not otp_code:
            flash('Please enter OTP code', 'error')
            return render_template('auth/verify_2fa.html')
        
        # Verify OTP
        success, message = two_factor.verify_otp(user_id, otp_code)
        
        if success:
            # Check if user must change password (from recovery OTP)
            import sqlite3
            conn = sqlite3.connect(Config.DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_flags (
                    user_id TEXT PRIMARY KEY,
                    must_change_password INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')
            
            cursor.execute('''
                SELECT must_change_password FROM user_flags WHERE user_id = ?
            ''', (user_id,))
            
            flag_row = cursor.fetchone()
            must_change_password = flag_row[0] if flag_row else 0
            
            # Check if this was an OTP login
            is_otp_login = session.get('temp_is_otp_login', False)
            
            # If OTP was used, invalidate it
            if is_otp_login:
                cursor.execute('DELETE FROM recovery_otps WHERE user_id = ?', (user_id,))
                conn.commit()
            
            conn.close()
            
            # Create session
            username = session.get('temp_username')
            role = session.get('temp_role')
            
            # Get client info
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')
            
            # Check if remember me was checked (preserve before clearing session)
            remember_me = session.get('remember_me', False)
            session_lifetime = None  # Use default (1 hour) if not remember me
            
            if remember_me:

                session_lifetime = 30 * 24 * 3600 
                current_app.permanent_session_lifetime = timedelta(days=30)
            else:
                # Set default session lifetime (1 hour)
                current_app.permanent_session_lifetime = timedelta(seconds=Config.SESSION_LIFETIME)
            
            success_session, session_token, msg_session = session_manager.create_session(
                user_id, ip_address, user_agent, lifetime_seconds=session_lifetime
            )
            
            if success_session:
                # Set session variables
                session.clear()
                session['user_id'] = user_id
                session['username'] = username
                session['role'] = role
                session['is_verified'] = True
                session['session_token'] = session_token
                session['must_change_password'] = bool(must_change_password)
                session['ip_address'] = ip_address 
                session['user_agent'] = user_agent  
                session['remember_me'] = remember_me  
                
                session.permanent = True
                
                if must_change_password:
                    flash('Login successful! You must change your password now.', 'warning')
                    return redirect(url_for('user.change_password'))
                else:
                    flash('Login successful!', 'success')
                    return redirect(url_for('user.dashboard'))
            else:
                flash('Session creation failed', 'error')
        else:
            flash(message, 'error')
    
    return render_template('auth/verify_2fa.html')

@auth_bp.route('/resend-otp')
def resend_otp():

    if 'temp_user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('auth.login'))
    
    user_id = session.get('temp_user_id')
    
    from models.user import UserModel
    user_model = UserModel(Config.DATABASE_PATH)
    user = user_model.get_user_by_id(user_id)
    
    if user:
        from middleware.encryption_middleware import EncryptionMiddleware
        em = EncryptionMiddleware(Config.DATABASE_PATH)
        email = em.decrypt_data(user['email_encrypted'], user_id)
        
        success, otp_code, message = two_factor.generate_otp(user_id)
        
        if success:
            print(f"\n{'='*50}\nResent OTP: {otp_code}\n{'='*50}\n")
            if email:

                two_factor.send_otp_email(user_id, email, otp_code=otp_code)
            flash('OTP resent successfully', 'success')
        else:
            flash('Failed to resend OTP', 'error')
    
    return redirect(url_for('auth.verify_2fa'))

@auth_bp.route('/logout')
def logout():

    if 'session_token' in session:
        session_manager.terminate_session(session['session_token'])
    
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():

    if request.method == 'POST':
        email = sanitize_input(request.form.get('email', '').strip())
        
        if not email:
            flash('Please enter your email address', 'error')
            return render_template('auth/forgot_password.html')
        
        from models.user import UserModel
        from middleware.encryption_middleware import EncryptionMiddleware
        from crypto.hashing import HashFunction
        import secrets
        import sqlite3
        from datetime import datetime, timedelta
        
        user_model = UserModel(Config.DATABASE_PATH)
        encryption_middleware = EncryptionMiddleware(Config.DATABASE_PATH)
        
        conn = sqlite3.connect(Config.DATABASE_PATH)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT user_id, username, email_encrypted, role, is_verified, is_active, created_at
            FROM users
        ''')
        
        all_user_rows = cursor.fetchall()
        conn.close()
        found_user = None
        
        print(f"\n{'='*70}")
        print(f"SEARCHING FOR EMAIL: {email}")
        print(f"Total users in database: {len(all_user_rows)}")
        print(f"{'='*70}\n")
        
        for row in all_user_rows:
            user_id = row[0]
            username = row[1]
            email_encrypted = row[2]
            role = row[3]
            is_verified = row[4]
            is_active = row[5]
            created_at = row[6]
            
            if not email_encrypted:
                print(f"User {username} has no email_encrypted field")
                continue
                
            try:

                user_email = encryption_middleware.decrypt_data(email_encrypted, user_id)
                
                if user_email:
                    print(f"Checking user {username}: decrypted email = {user_email}")
                    if user_email.lower().strip() == email.lower().strip():
                        found_user = {
                            'user_id': user_id,
                            'username': username,
                            'role': role,
                            'is_verified': bool(is_verified),
                            'is_active': bool(is_active),
                            'created_at': created_at
                        }
                        print(f"\n{'='*70}")
                        print(f"✓ FOUND USER: Username={username}, Email={user_email}")
                        print(f"{'='*70}\n")
                        break
                else:
                    print(f"User {username}: Failed to decrypt email (returned None)")
            except Exception as e:
                print(f"Error decrypting email for user {username} (ID: {user_id}): {e}")
                import traceback
                traceback.print_exc()
                continue
        
        if found_user:
            # Generate 8-digit OTP
            otp_password = ''.join([str(secrets.randbelow(10)) for _ in range(8)])
            
            # Hash the OTP password
            otp_hash, otp_salt = HashFunction.hash_password(otp_password)
            
            # Store OTP as temporary password in database
            import sqlite3
            conn = sqlite3.connect(Config.DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS recovery_otps (
                    user_id TEXT PRIMARY KEY,
                    otp_hash TEXT NOT NULL,
                    otp_salt TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')
            
            expires_at = (datetime.now() + timedelta(hours=1)).isoformat()
            cursor.execute('''
                INSERT OR REPLACE INTO recovery_otps (user_id, otp_hash, otp_salt, expires_at)
                VALUES (?, ?, ?, ?)
            ''', (found_user['user_id'], otp_hash, otp_salt, expires_at))
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_flags (
                    user_id TEXT PRIMARY KEY,
                    must_change_password INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')
            
            cursor.execute('''
                INSERT OR REPLACE INTO user_flags (user_id, must_change_password)
                VALUES (?, 1)
            ''', (found_user['user_id'],))
            
            # Temporarily set OTP as password (will be invalidated after first use)
            cursor.execute('''
                UPDATE users 
                SET password_hash = ?, password_salt = ?
                WHERE user_id = ?
            ''', (otp_hash, otp_salt, found_user['user_id']))
            
            conn.commit()
            conn.close()
            
            # Print OTP to console
            print("\n" + "="*70)
            print("PASSWORD RECOVERY - ONE-TIME PASSWORD")
            print("="*70)
            print(f"Email: {email}")
            print(f"Username: {found_user.get('username', 'N/A')}")
            print(f"One-Time Password (OTP): {otp_password}")
            print(f"Note: This OTP will work for 1 hour. After login, you MUST change your password.")
            print("="*70 + "\n")
            
            flash('One-time password generated! Enter the OTP below to login.', 'success')
            return redirect(url_for('auth.recover_with_otp'))
        else:
            # Don't reveal if account exists
            print("\n" + "="*70)
            print("PASSWORD RECOVERY ATTEMPT")
            print("="*70)
            print(f"Email requested: {email}")
            print("No account found with this email.")
            print("="*70 + "\n")
            flash('If an account exists with this email, a one-time password has been generated. Check the server console.', 'info')
            return redirect(url_for('auth.recover_with_otp'))
    
    return render_template('auth/forgot_password.html')


@auth_bp.route('/recover-with-otp', methods=['GET', 'POST'])
def recover_with_otp():

    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        
        if not otp or len(otp) != 8 or not otp.isdigit():
            flash('Please enter a valid 8-digit OTP', 'error')
            return render_template('auth/recover_with_otp.html')
        
        # Find user with this OTP
        import sqlite3
        from datetime import datetime
        from crypto.hashing import HashFunction
        
        conn = sqlite3.connect(Config.DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get all active OTPs
        cursor.execute('''
            SELECT user_id, otp_hash, otp_salt, expires_at 
            FROM recovery_otps 
            WHERE expires_at > ?
        ''', (datetime.now().isoformat(),))
        
        otp_rows = cursor.fetchall()
        found_user_id = None
        
        for row in otp_rows:
            user_id, otp_hash, otp_salt, expires_at = row
            # Verify OTP
            if HashFunction.verify_password(otp, otp_hash, otp_salt):
                found_user_id = user_id
                break
        
        if not found_user_id:
            conn.close()
            flash('Invalid or expired OTP. Please request a new one.', 'error')
            return render_template('auth/recover_with_otp.html')
        
        # Get user info
        from models.user import UserModel
        user_model = UserModel(Config.DATABASE_PATH)
        user = user_model.get_user_by_id(found_user_id)
        
        if not user or not user.get('is_active', True):
            conn.close()
            flash('Account not found or inactive', 'error')
            return render_template('auth/recover_with_otp.html')
        
        # Set flag that password must be changed
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_flags (
                user_id TEXT PRIMARY KEY,
                must_change_password INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        cursor.execute('''
            INSERT OR REPLACE INTO user_flags (user_id, must_change_password)
            VALUES (?, 1)
        ''', (found_user_id,))
        
        # Delete the used OTP
        cursor.execute('DELETE FROM recovery_otps WHERE user_id = ?', (found_user_id,))
        conn.commit()
        conn.close()
        
        # Create session directly (skip 2FA for OTP recovery)
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        success_session, session_token, msg_session = session_manager.create_session(
            found_user_id, ip_address, user_agent
        )
        
        if success_session:
            # Set session variables
            session.clear()
            session['user_id'] = found_user_id
            session['username'] = user['username']
            session['role'] = user.get('role', 'voter')
            session['is_verified'] = True
            session['session_token'] = session_token
            session['must_change_password'] = True  
            session['ip_address'] = ip_address  
            session['user_agent'] = user_agent  
            
            flash('Login successful! You must change your password now.', 'warning')
            return redirect(url_for('user.change_password'))
        else:
            flash('Session creation failed', 'error')
    
    return render_template('auth/recover_with_otp.html')