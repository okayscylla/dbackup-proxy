import os
from flask import Flask, request, jsonify
import dropbox
from dropbox import DropboxOAuth2FlowNoRedirect

app = Flask(__name__)


def create_flow():
    return DropboxOAuth2FlowNoRedirect(
            os.getenv("DBX_KEY"),
            os.getenv("DBX_SECRET"),
        )


@app.route("/api/get-auth-url", methods=["GET"])
def get_auth_url():
    try:
        oauth_flow = create_flow()
        
        auth_url = oauth_flow.start()
        
        return jsonify({"auth_url": auth_url}), 200
        
    except dropbox.oauth.NotApprovedException:
        return jsonify({"error": "Not approved"}), 403
    except Exception as _:
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
    
    except dropbox.oauth.ProviderException:
        return jsonify({"error": "An unexpected error occured"}), 500
    
    except Exception as _:
        return jsonify({"error": "Internal server error"}), 500