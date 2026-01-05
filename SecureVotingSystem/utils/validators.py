import re

def validate_email(email):

    if not email:
        return False, "Email is required"
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if re.match(pattern, email):
        return True, "Valid email"
    
    return False, "Invalid email format"

def validate_password(password):

    if not password:
        return False, "Password is required"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Valid password"


def validate_phone(phone):

    if not phone:
        return False, "Phone number is required"
    
    # Remove spaces and dashes
    phone = phone.replace(' ', '').replace('-', '')
    
    # Check formats
    patterns = [
        r'^\+8801[3-9]\d{8}$',  # +8801XXXXXXXXX
        r'^01[3-9]\d{8}$',       # 01XXXXXXXXX
        r'^8801[3-9]\d{8}$'      # 8801XXXXXXXXX
    ]
    
    for pattern in patterns:
        if re.match(pattern, phone):
            return True, "Valid phone number"
    
    return False, "Invalid Bangladeshi phone number format"


def validate_nid(nid):
    if not nid:
        return False, "NID is required"
    
    # Remove spaces
    nid = nid.replace(' ', '')
    
    # Check if only digits
    if not nid.isdigit():
        return False, "NID must contain only digits"
    
    # Check length
    if len(nid) in [10, 13, 17]:
        return True, "Valid NID"
    
    return False, "NID must be 10, 13, or 17 digits"

def validate_username(username):

    if not username:
        return False, "Username is required"
    
    if len(username) < 3 or len(username) > 20:
        return False, "Username must be 3-20 characters"
    
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', username):
        return False, "Username must start with letter and contain only letters, numbers, and underscores"
    
    return True, "Valid username"

def validate_full_name(full_name):

    if not full_name:
        return False, "Full name is required"
    
    if len(full_name) < 2:
        return False, "Full name must be at least 2 characters"
    
    if not re.match(r'^[a-zA-Z\s.]+$', full_name):
        return False, "Full name can only contain letters, spaces, and dots"
    
    return True, "Valid full name"


def sanitize_input(text):

    if not text:
        return ""
    
    # Replace dangerous characters
    replacements = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;'
    }
    
    for old, new in replacements.items():
        text = text.replace(old, new)
    
    return text

def validate_date_format(date_str):

    if not date_str:
        return False, "Date is required"
    
    pattern = r'^\d{4}-\d{2}-\d{2}$'
    
    if not re.match(pattern, date_str):
        return False, "Date must be in YYYY-MM-DD format"
    
    try:
        from datetime import datetime
        datetime.strptime(date_str, '%Y-%m-%d')
        return True, "Valid date"
    except ValueError:
        return False, "Invalid date"


def validate_date_range(start_date, end_date):

    try:
        from datetime import datetime
        
        start = datetime.strptime(start_date, '%Y-%m-%d')
        end = datetime.strptime(end_date, '%Y-%m-%d')
        
        if end <= start:
            return False, "End date must be after start date"
        
        return True, "Valid date range"
    
    except ValueError:
        return False, "Invalid date format"