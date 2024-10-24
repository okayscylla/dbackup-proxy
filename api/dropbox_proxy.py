import os
from flask import Flask, request, jsonify
import dropbox
from dropbox import DropboxOAuth2FlowNoRedirect
# import logging

# log_level = 'INFO'
# logger = logging.getLogger()
# logger.setLevel(log_level)

# console_handler = logging.StreamHandler()
# console_handler.setLevel(log_level)
# logger.addHandler(console_handler)

app = Flask(__name__)


def create_flow():
    return DropboxOAuth2FlowNoRedirect(
            os.getenv("DBX_KEY"),
            os.getenv("DBX_SECRET"),
            token_access_type="legacy"
        )


@app.route("/api/get-auth-url", methods=["GET"])
def get_auth_url():
    try:
        oauth_flow = create_flow()
        
        auth_url = oauth_flow.start()
        
        return jsonify({"auth_url": auth_url}), 200
        
    except Exception as e:
        print(f"Error in api/get_auth_url: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/get-access-token", methods=["POST"])
def get_access_token():
    try:
        data = request.json
        if not data or "auth_code" not in data:
            return jsonify({"error": "Invalid request"}), 400
        
        auth_code = data["auth_code"]
        
        oauth_flow = create_flow()
        
        oauth_result = oauth_flow.finish(auth_code)
        
        return jsonify({
            "access_token": oauth_result.access_token
        })
    
    except dropbox.oauth.NotApprovedException:
        return jsonify({"error": "Not approved"}), 403
    
    except dropbox.oauth.ProviderException as e:
        print(f"ProviderException in api/get_access_token: {e}")
        return jsonify({"error": "An unexpected error occured"}), 500
    
    except Exception as e:
        print(f"Error in api/get_access_token: {e}")
        return jsonify({"error": "Internal server error"}), 500