from auth.registration import Registration
from config import Config
import getpass

def create_admin_user():
    
    print("\n" + "="*60)
    print("CREATE ADMIN USER - SECURE VOTING SYSTEM")
    print("="*60 + "\n")
    
    # Initialize registration module
    reg = Registration(Config.DATABASE_PATH)
    
    # Get admin details
    print("Enter admin details:\n")
    
    username = input("Username: ").strip()
    
    # Check if username exists
    if reg.check_username_exists(username):
        print(f"\n Error: Username '{username}' already exists!")
        return
    
    email = input("Email: ").strip()
    full_name = input("Full Name: ").strip()
    phone = input("Phone (optional, press Enter to skip): ").strip() or None
    nid = input("National ID (optional, press Enter to skip): ").strip() or None
    
    # Password (hidden input)
    password = getpass.getpass("Password: ")
    confirm_password = getpass.getpass("Confirm Password: ")
    
    if password != confirm_password:
        print("\n Error: Passwords do not match!")
        return
    
    # Confirm admin creation
    print("\n" + "-"*60)
    print("Creating admin user with the following details:")
    print(f"Username: {username}")
    print(f"Email: {email}")
    print(f"Full Name: {full_name}")
    print(f"Role: ADMIN")
    print("-"*60)
    
    confirm = input("\nAre you sure you want to create this admin user? (yes/no): ").strip().lower()
    
    if confirm != 'yes':
        print("\n Admin creation cancelled.")
        return
    
    # Create admin user
    print("\n⏳ Creating admin user...")
    
    success, message, user_id = reg.register_user(
        username=username,
        password=password,
        email=email,
        full_name=full_name,
        phone=phone,
        nid=nid,
        role='admin'  # Set role as admin
    )
    
    if success:
        print(f"\n SUCCESS! Admin user created!")
        print(f"User ID: {user_id}")
        print(f"Username: {username}")
        print(f"Role: ADMIN")
        print("\n  IMPORTANT: Please verify this account using 2FA before logging in.")
        print("Check your console for the OTP code when you first login.")
    else:
        print(f"\n Error: {message}")

if __name__ == "__main__":
    create_admin_user()