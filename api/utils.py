import os
from dropbox import DropboxOAuth2FlowNoRedirect
import redis
import datetime
import requests
import jwt

JWT_SECRET = os.getenv("JWT_SECRET")

redis_handle = redis.Redis(
    host=os.getenv("REDIS_HOST"),
    port=os.getenv("REDIS_PORT"),
    password=os.getenv("REDIS_PASSWORD"),
    ssl=True
)

def get_expiration():
    return datetime.datetime.utcnow() + datetime.timedelta(days=30)

def create_flow():
    return DropboxOAuth2FlowNoRedirect(
            os.getenv("DBX_KEY"),
            os.getenv("DBX_SECRET"),
            token_access_type="offline"
        )

def create_jwt_token(user_id):
    payload = {
        "user_id": user_id,
        "exp": get_expiration(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def store_jwt_token(user_id, token):
    redis_handle.set(f"jwt:{user_id}", token, ex=datetime.timedelta(days=30))

def get_jwt_token(user_id):
    return redis_handle.get(f"jwt:{user_id}")

def verify_jwt_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None
    except jwt.ExpiredSignatureError:
        return None
    except Exception as e:
        print(f"Error in verify_jwt_token: {e}")
        return None

def store_token(user_id, access_token, refresh_token, expiration):
    redis_handle.hset(
        f"user:{user_id}", 
        mapping={"access_token": access_token, 
                 "refresh_token": refresh_token, 
                 "expiration": expiration}
        )

def access_token(user_id):
    data = redis_handle.hgetall(f"user:{user_id}")
    
    if not data:
        return None
    
    return {
        "access_token": data.get(b"access_token").decode("utf-8"),
        "refresh_token": data.get(b"refresh_token").decode("utf-8"),
        "expiration": int(data.get(b"expiration").decode("utf-8"))
    }

def refresh_token(refresh_token):
    url = "https://api.dropboxapi.com/oauth2/token"
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    content = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": os.getenv("DBX_KEY"),
        "client_secret": os.getenv("DBX_SECRET")
    }
    
    response = requests.post(url, headers=headers, data=content)
    
    if response.status_code != 200:
        raise Exception("Failed to refresh token")
    
    try:
        data = response.json()
        
        return data["access_token"], data["refresh_token"]
    except Exception as e:
        print(f"Error in refresh_token: {e}")
        return None

def get_token(auth_code):
    flow = create_flow()
    result = flow.finish(auth_code)
    
    return result.access_token, result.refresh_token
