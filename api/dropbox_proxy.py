from flask import Flask, request, jsonify
import os
from dropbox import DropboxOAuth2FlowNoRedirect
import redis
import datetime
import requests
import jwt
import uuid

app = Flask(__name__)


JWT_SECRET = os.getenv("JWT_SECRET")

redis_handle = redis.Redis(
    host=os.getenv("REDIS_HOST"),
    port=os.getenv("REDIS_PORT"),
    password=os.getenv("REDIS_PASSWORD"),
    ssl=True
)

def get_expiration():
    return str(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30))

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


@app.route("/api/refresh-token", methods=["POST"])
def refresh_token_api():
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return jsonify({"error": "No authorization header"}), 401

    access_token = auth_header.split(" ")[1]
    payload = verify_jwt_token(access_token)

    if not payload:
        return jsonify({"error": "Invalid access token"}), 401
    
    user_id = payload["user_id"]
    tokens = access_token(user_id)
    
    if not tokens or not tokens["refresh_token"]:
        return jsonify({"error": "No refresh token"}), 401
    
    try:
        new_access_token, new_refresh_token = refresh_token(tokens["refresh_token"])
        
        expiration = get_expiration()
        store_token(user_id, new_access_token, new_refresh_token, expiration)
        
        return jsonify(
            {"access_token": new_access_token},
            {"refresh_token": new_refresh_token}
        ), 200
        
    except Exception as e:
        print(f"Error in refresh_token: {e}")
        return jsonify({"error": "Failed to refresh token"}), 500


@app.route("/api/get-access-token", methods=["POST"])
def get_access_token_api():
    try:
        data = request.json
        if not data or "auth_code" not in data:
            return jsonify({"error": "Invalid request"}), 400
        
        user_id = uuid.uuid4()
        auth_code = data["auth_code"]
        access_token, refresh_token = get_token(auth_code)
        
        expiration = get_expiration()
        store_token(user_id, access_token, refresh_token, expiration)
        
        return jsonify(
            {"access_token": access_token},
            {"refresh_token": refresh_token},
            {"user_id": user_id}
            ), 200
    except Exception as e:
        print(f"Error in get_access_token: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/get-auth-url", methods=["GET"])
def get_auth_url_api():
    try:
        oauth_flow = create_flow()
        auth_url = oauth_flow.start()
        return jsonify({"auth_url": auth_url}), 200
    except Exception as e:
        print(f"Error in get_auth_url: {e}")
        return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(debug=True)