from flask import Flask, render_template, redirect, url_for, session, request
import os
from config import Config


app = Flask(__name__)
app.config.from_object(Config)
app.config['SESSION_COOKIE_HTTPONLY'] = Config.SESSION_COOKIE_HTTPONLY
app.config['SESSION_COOKIE_SECURE'] = Config.SESSION_COOKIE_SECURE
app.config['SESSION_COOKIE_SAMESITE'] = Config.SESSION_COOKIE_SAMESITE


os.makedirs(os.path.dirname(app.config['DATABASE_PATH']), exist_ok=True)

from routes.auth_routes import auth_bp
from routes.user_routes import user_bp
from routes.election_routes import election_bp
from routes.vote_routes import vote_bp
from routes.post_routes import post_bp
from routes.support_routes import support_bp

app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(user_bp, url_prefix='/user')
app.register_blueprint(election_bp, url_prefix='/election')
app.register_blueprint(vote_bp, url_prefix='/vote')
app.register_blueprint(post_bp, url_prefix='/post')
app.register_blueprint(support_bp, url_prefix='/support')

@app.route('/')
def index():

    if 'user_id' in session:
        # Redirect logged-in users to dashboard
        return redirect(url_for('user.dashboard'))
    
    return render_template('index.html')

@app.route('/about')
def about():

    return render_template('about.html')

@app.route('/contact')
def contact():

    return render_template('contact.html')

@app.errorhandler(404)
def not_found_error(error):

    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):

    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):

    return render_template('errors/403.html'), 403

@app.template_filter('format_date')
def format_date(date_string):

    from datetime import datetime
    try:
        dt = datetime.fromisoformat(date_string)
        return dt.strftime('%B %d, %Y at %I:%M %p')
    except:
        return date_string

@app.template_filter('format_date_short')
def format_date_short(date_string):

    from datetime import datetime
    try:
        dt = datetime.fromisoformat(date_string)
        return dt.strftime('%Y-%m-%d')
    except:
        return date_string


@app.template_filter('time_ago')
def time_ago(date_string):

    from datetime import datetime
    try:
        dt = datetime.fromisoformat(date_string)
        diff = datetime.now() - dt
        
        if diff.days > 365:
            return f"{diff.days // 365} years ago"
        elif diff.days > 30:
            return f"{diff.days // 30} months ago"
        elif diff.days > 0:
            return f"{diff.days} days ago"
        elif diff.seconds > 3600:
            return f"{diff.seconds // 3600} hours ago"
        elif diff.seconds > 60:
            return f"{diff.seconds // 60} minutes ago"
        else:
            return "Just now"
    except:
        return date_string


@app.context_processor
def inject_user():

    if 'user_id' in session:
        return {
            'current_user': {
                'user_id': session.get('user_id'),
                'username': session.get('username'),
                'role': session.get('role'),
                'is_verified': session.get('is_verified')
            }
        }
    return {'current_user': None}

@app.before_request
def before_request():
    """Execute before each request"""
    from datetime import timedelta
    from auth.session_manager import SessionManager
    from config import Config

    if request.endpoint and (
        request.endpoint.startswith('static') or
        request.endpoint.startswith('auth.') or 
        request.endpoint == 'index' or
        request.endpoint == 'about' or
        request.endpoint == 'contact'
    ):
        return None

    if 'user_id' in session and 'session_token' in session:
        session_manager = SessionManager(Config.DATABASE_PATH)
        session_token = session.get('session_token')
        
        # Validate session token
        is_valid, validated_user_id, message = session_manager.validate_session(session_token)
        
        if not is_valid or validated_user_id != session.get('user_id'):
            # Session invalid or user mismatch - logout
            session.clear()
            from flask import redirect, url_for, flash
            flash('Your session has expired or is invalid. Please login again.', 'error')
            return redirect(url_for('auth.login'))
        
        # Additional security: Check IP address and user agent for session hijacking protection
        stored_ip = session.get('ip_address')
        stored_user_agent = session.get('user_agent')
        current_ip = request.remote_addr
        current_user_agent = request.headers.get('User-Agent')

        if stored_ip and stored_user_agent:
            # User agent should be consistent
            if stored_user_agent != current_user_agent:
                # Possible session hijacking - terminate session
                session_manager.terminate_session(session_token)
                session.clear()
                from flask import redirect, url_for, flash
                flash('Security alert: Session terminated due to suspicious activity.', 'error')
                return redirect(url_for('auth.login'))
    
    if 'user_id' in session:

        if session.get('remember_me'):
            app.permanent_session_lifetime = timedelta(days=30)
            session.permanent = True
        else:
            app.permanent_session_lifetime = timedelta(seconds=app.config['SESSION_LIFETIME'])
            session.permanent = True
    else:

        app.permanent_session_lifetime = timedelta(seconds=app.config['SESSION_LIFETIME'])

# After request
@app.after_request
def after_request(response):
    """Execute after each request"""
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response

if __name__ == '__main__':
    # Run development server
    print("="*60)
    print("SECURE NATIONAL ELECTION & VOTING MANAGEMENT SYSTEM")
    print("="*60)
    print(f"Database: {app.config['DATABASE_PATH']}")
    print(f"Debug Mode: {app.debug}")
    print("="*60)
    print("\nStarting server...")
    print("Access the application at: http://127.0.0.1:5000")
    print("\nPress CTRL+C to quit\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)