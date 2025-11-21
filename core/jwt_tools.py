import jwt
import json

def create_jwt(payload: str, secret: str, algo: str = 'HS256'):
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        data = {"data": payload}
    return jwt.encode(data, secret, algorithm=algo)

def decode_jwt_token(token: str, secret: str = None, verify: bool = False):
    options = {"verify_signature": verify}
    # If verifying, secret is required
    return jwt.decode(token, secret, options=options, algorithms=["HS256", "RS256"])