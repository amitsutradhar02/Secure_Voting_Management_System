import os
import secrets

class Config:
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    
    # Database settings
    DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'database', 'voting_system.db')
    
    # Session settings
    SESSION_LIFETIME = 3600  # 1 hour in seconds
    REMEMBER_ME_LIFETIME = 30 * 24 * 3600  # 30 days in seconds 
    SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to cookies 
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS 
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
    
    # Encryption settings
    RSA_KEY_SIZE = 2048  # RSA key size in bits
    ECC_CURVE = 'secp256k1'  # ECC curve name
    KEY_ROTATION_DAYS = 90  # Rotate keys every 90 days
    
    # 2FA settings
    OTP_LENGTH = 6
    OTP_EXPIRY = 300  # 5 minutes in seconds
    
    # Email settings further development
    EMAIL_ENABLED = False  # Set to True when email is configured
    EMAIL_HOST = 'smtp.gmail.com'
    EMAIL_PORT = 587
    EMAIL_USERNAME = 'your_email@gmail.com'
    EMAIL_PASSWORD = 'your_app_password'
    EMAIL_FROM = 'your_email@gmail.com'
    
    # Role definitions
    ROLE_ADMIN = 'admin'
    ROLE_VOTER = 'voter'
    
    # Password requirements
    MIN_PASSWORD_LENGTH = 8
    
    # Application settings
    APP_NAME = 'Secure National Election & Voting System'
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_TIME = 900  # 15 minutes in seconds