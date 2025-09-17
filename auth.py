# C:\Users\rishi\Desktop\fitness\auth.py

from flask import Blueprint, request, jsonify, redirect, url_for, session
import requests
import os
from functools import wraps

auth_blueprint = Blueprint('auth', __name__)

# --- Configuration ---
# ❗ IMPORTANT: Replace these with your actual Google OAuth credentials
GOOGLE_CLIENT_ID = "922804511630-tlln2v1r53iu06iggj0ec96fulmm7ik1.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_REDIRECT_URI = "http://127.0.0.1:5000/api/auth/google/callback"

# ❗ IMPORTANT: Replace these with your actual Facebook OAuth credentials
FACEBOOK_APP_ID = "YOUR_FACEBOOK_APP_ID"
FACEBOOK_APP_SECRET = "YOUR_FACEBOOK_APP_SECRET"
FACEBOOK_REDIRECT_URI = "http://127.0.0.1:5000/api/auth/facebook/callback"

# --- Helper Functions ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            return jsonify({"success": False, "message": "Login required"}), 401
        return f(*args, **kwargs)
    return decorated_function

# --- Google OAuth Routes ---
@auth_blueprint.route('/google')
def google_login():
    auth_url = (
        f"https://accounts.google.com/o/oauth2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={GOOGLE_REDIRECT_URI}&"
        f"scope=openid%20email%20profile&"
        f"response_type=code"
    )
    return redirect(auth_url)

@auth_blueprint.route('/google/callback')
def google_callback():
    code = request.args.get('code')
    if not code:
        return jsonify({"success": False, "message": "Failed to get Google authorization code."}), 400

    token_url = "https://accounts.google.com/o/oauth2/token"
    token_data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    try:
        response = requests.post(token_url, data=token_data)
        response.raise_for_status()
        token_info = response.json()
        access_token = token_info.get("access_token")

        user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        user_info_response = requests.get(user_info_url, headers={'Authorization': f'Bearer {access_token}'})
        user_info_response.raise_for_status()
        user_info = user_info_response.json()
        
        session['logged_in'] = True
        session['user_name'] = user_info.get('given_name', 'User')
        
        return redirect(url_for('dashboard_page'))
    
    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "message": f"Google auth error: {str(e)}"}), 500

# --- Facebook OAuth Routes ---
@auth_blueprint.route('/facebook')
def facebook_login():
    auth_url = (
        f"https://www.facebook.com/v19.0/dialog/oauth?"
        f"client_id={FACEBOOK_APP_ID}&"
        f"redirect_uri={FACEBOOK_REDIRECT_URI}&"
        f"scope=email&"
        f"response_type=code"
    )
    return redirect(auth_url)

@auth_blueprint.route('/facebook/callback')
def facebook_callback():
    code = request.args.get('code')
    if not code:
        return jsonify({"success": False, "message": "Failed to get Facebook authorization code."}), 400
    
    token_url = "https://graph.facebook.com/v19.0/oauth/access_token"
    token_data = {
        "client_id": FACEBOOK_APP_ID,
        "redirect_uri": FACEBOOK_REDIRECT_URI,
        "client_secret": FACEBOOK_APP_SECRET,
        "code": code
    }

    try:
        response = requests.get(token_url, params=token_data)
        response.raise_for_status()
        token_info = response.json()
        access_token = token_info.get("access_token")

        user_info_url = f"https://graph.facebook.com/v19.0/me?fields=id,name,email&access_token={access_token}"
        user_info_response = requests.get(user_info_url)
        user_info_response.raise_for_status()
        user_info = user_info_response.json()
        
        session['logged_in'] = True
        session['user_name'] = user_info.get('name', 'User')
        
        return redirect(url_for('dashboard_page'))

    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "message": f"Facebook auth error: {str(e)}"}), 500