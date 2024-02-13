# auth.py

import jwt
import datetime

JWT_SECRET_KEY = 'pinaca123@'
JWT_EXPIRATION_DELTA = datetime.timedelta(days=1)

def generate_token(login_user):
    payload = {'username': login_user['username']}
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')

def verify_token(token):
    try:
        jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        return True  # Token is verified
    except jwt.ExpiredSignatureError:
        return False  # Token has expired
    except jwt.InvalidTokenError:
        return False  # Invalid token
