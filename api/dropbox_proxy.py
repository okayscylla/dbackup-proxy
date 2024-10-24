from flask import Flask, request, jsonify
import utils
import uuid

app = Flask(__name__)


@app.route("/api/refresh-token", methods=["POST"])
def refresh_token():
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return jsonify({"error": "No authorization header"}), 401

    access_token = auth_header.split(" ")[1]
    payload = utils.verify_jwt_token(access_token)

    if not payload:
        return jsonify({"error": "Invalid access token"}), 401
    
    user_id = payload["user_id"]
    tokens = utils.access_token(user_id)
    
    if not tokens or not tokens["refresh_token"]:
        return jsonify({"error": "No refresh token"}), 401
    
    try:
        new_access_token, new_refresh_token = utils.refresh_token(tokens["refresh_token"])
        
        expiration = utils.get_expiration()
        utils.store_token(user_id, new_access_token, new_refresh_token, expiration)
        
        return jsonify(
            {"access_token": new_access_token},
            {"refresh_token": new_refresh_token}
        ), 200
        
    except Exception as e:
        print(f"Error in refresh_token: {e}")
        return jsonify({"error": "Failed to refresh token"}), 500


@app.route("/api/get-access-token", methods=["POST"])
def get_access_token():
    try:
        data = request.json
        if not data or "auth_code" not in data:
            return jsonify({"error": "Invalid request"}), 400
        
        user_id = uuid.uuid4()
        auth_code = data["auth_code"]
        access_token, refresh_token = utils.get_token(auth_code)
        
        expiration = utils.get_expiration()
        utils.store_token(user_id, access_token, refresh_token, expiration)
        
        return jsonify(
            {"access_token": access_token},
            {"refresh_token": refresh_token},
            {"user_id": user_id}
            ), 200
    except Exception as e:
        print(f"Error in get_access_token: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/get-auth-url", methods=["POST"])
def get_auth_url():
    try:
        oauth_flow = utils.create_flow()
        auth_url = oauth_flow.start()
        return jsonify({"auth_url": auth_url}), 200
    except Exception as e:
        print(f"Error in get_auth_url: {e}")
        return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(debug=True)