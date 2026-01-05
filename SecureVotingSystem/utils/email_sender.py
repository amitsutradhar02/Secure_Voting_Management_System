import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# For further development purpose
def send_email(to_email, subject, body, is_html=False):

    EMAIL_HOST = 'smtp.gmail.com'
    EMAIL_PORT = 587
    EMAIL_USERNAME = 'your_email@gmail.com'
    EMAIL_PASSWORD = 'your_app_password'
    EMAIL_FROM = 'your_email@gmail.com'
    
    # For development, just print the email
    print("\n" + "="*60)
    print("EMAIL NOTIFICATION")
    print("="*60)
    print(f"To: {to_email}")
    print(f"Subject: {subject}")
    print(f"Body:\n{body}")
    print("="*60 + "\n")
    
    return True, "Email sent (development mode)"

def send_otp_email(to_email, otp_code, user_name=None):

    subject = "Your OTP Code - Secure Voting System"
    greeting = f"Hello {user_name},\n\n" if user_name else "Hello,\n\n"
    body = f"""{greeting}Your One-Time Password (OTP) for the Secure National Election & Voting Management System is:
    {otp_code}

This code will expire in 5 minutes.

Please do not share this code with anyone.

If you did not request this code, please ignore this email.

Best regards,
Secure Voting System Team
"""
    
    return send_email(to_email, subject, body)


def send_welcome_email(to_email, user_name, username):

    subject = "Welcome to Secure National Election & Voting System"
    body = f"""Hello {user_name},

Welcome to the Secure National Election & Voting Management System!

Your account has been successfully created with the following details:
- Username: {username}
- Registration Date: Today

To complete your registration, please verify your account using the OTP code sent to you.

Once verified, you will be able to:
- Participate in national elections
- View election results
- Stay updated with election announcements

Thank you for joining us!

Best regards,
Secure Voting System Team
"""
    
    return send_email(to_email, subject, body)

def send_password_reset_email(to_email, reset_code, user_name=None):

    subject = "Password Reset Request - Secure Voting System"
    greeting = f"Hello {user_name},\n\n" if user_name else "Hello,\n\n"
    body = f"""{greeting}We received a request to reset your password.

Your password reset code is:

    {reset_code}

This code will expire in 15 minutes.

If you did not request a password reset, please ignore this email and ensure your account is secure.

Best regards,
Secure Voting System Team
"""
    
    return send_email(to_email, subject, body)


def send_election_notification(to_email, election_title, start_date, end_date, user_name=None):
    subject = f"New Election: {election_title}" 
    greeting = f"Hello {user_name},\n\n" if user_name else "Hello,\n\n" 
    body = f"""{greeting}A new election has been scheduled:

Election: {election_title}
Start Date: {start_date}
End Date: {end_date}

Make sure to cast your vote during the election period!

Login to the Secure Voting System to view more details.

Best regards,
Secure Voting System Team
"""
    
    return send_email(to_email, subject, body)

def send_vote_confirmation(to_email, election_title, user_name=None):

    subject = "Vote Confirmation - Secure Voting System"
    greeting = f"Hello {user_name},\n\n" if user_name else "Hello,\n\n"
    body = f"""{greeting}Your vote has been successfully recorded for:

Election: {election_title}

Your vote is encrypted and stored securely. Thank you for participating in the democratic process!

Note: You cannot change your vote once submitted.

Best regards,
Secure Voting System Team
"""   
    return send_email(to_email, subject, body)