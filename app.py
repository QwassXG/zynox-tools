import os
import json
import re
import logging
import requests
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default_secret_key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username
        
# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    auth_data = load_config_data('auth')
    if not auth_data or 'credentials' not in auth_data:
        return None
    
    for i, cred in enumerate(auth_data['credentials']):
        if str(i) == user_id:
            return User(user_id, cred['username'])
    
    return None

# Discord API endpoint and headers
DISCORD_API = "https://discord.com/api/v9"

# Function to load data from config.json
def load_config_data(key, default=None):
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
            return config.get(key, default if default is not None else [])
    except Exception as e:
        logging.error(f"Error loading config: {str(e)}")
        return default if default is not None else []

# Check for config changes (password updates)
def check_auth_updates():
    if 'auth_last_modified' in session:
        auth_data = load_config_data('auth')
        if auth_data and 'credentials' in auth_data:
            for cred in auth_data['credentials']:
                if 'last_updated' in cred and cred['last_updated'] != session.get('auth_last_modified'):
                    # Force logout if password was changed
                    logout_user()
                    session.clear()
                    flash('Your credentials have been updated. Please login again.', 'info')
                    return redirect(url_for('login'))
    return None

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already authenticated, redirect to index
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        auth_data = load_config_data('auth')
        if not auth_data or 'credentials' not in auth_data:
            error = 'Authentication system not configured'
        else:
            authenticated = False
            user_id = None
            
            for i, cred in enumerate(auth_data['credentials']):
                if cred['username'] == username and cred['password'] == password:
                    authenticated = True
                    user_id = str(i)
                    # Store the last modified date to check for changes
                    if 'last_updated' in cred:
                        session['auth_last_modified'] = cred['last_updated']
                    break
            
            if authenticated:
                user = User(user_id, username)
                login_user(user)
                session.permanent = True
                
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
            else:
                error = 'Invalid username or password'
    
    social_links = load_config_data('social_links')
    return render_template('login.html', error=error, social_links=social_links)

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Route for the main page
@app.route('/')
@login_required
def index():
    # Check if authentication config has changed
    redirect_result = check_auth_updates()
    if redirect_result:
        return redirect_result
    
    discord_links = load_config_data('discord_links')
    products = load_config_data('products')
    social_links = load_config_data('social_links')
    return render_template('index.html', discord_links=discord_links, products=products, social_links=social_links)

# Function to validate Discord token
def validate_token(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json"
    }
    
    try:
        # Get user info
        user_response = requests.get(f"{DISCORD_API}/users/@me", headers=headers)
        
        # If token is invalid
        if user_response.status_code != 200:
            return {
                "valid": False,
                "message": "Invalid token"
            }
        
        user_data = user_response.json()
        
        # Get billing info to check for Nitro
        billing_response = requests.get(f"{DISCORD_API}/users/@me/billing/payment-sources", headers=headers)
        
        # Extract necessary information
        created_at = int(((int(user_data['id']) >> 22) + 1420070400000) / 1000)
        creation_date = datetime.utcfromtimestamp(created_at).strftime('%Y-%m-%d')
        
        account_age = (datetime.utcnow() - datetime.utcfromtimestamp(created_at)).days
        
        # Get user flag properties
        email_verified = user_data.get('verified', False)
        phone_verified = user_data.get('phone') is not None
        
        # Check for Nitro
        nitro_status = "None"
        if user_data.get('premium_type') == 1:
            nitro_status = "Nitro Classic"
        elif user_data.get('premium_type') == 2:
            nitro_status = "Nitro"
        
        return {
            "valid": True,
            "username": f"{user_data.get('username')}#{user_data.get('discriminator')}",
            "email": user_data.get('email', 'Not available'),
            "phone": user_data.get('phone', 'Not available'),
            "email_verified": email_verified,
            "phone_verified": phone_verified,
            "creation_date": creation_date,
            "account_age": account_age,
            "nitro": nitro_status,
            "avatar": user_data.get('avatar', None)
        }
    
    except Exception as e:
        logging.error(f"Error validating token: {str(e)}")
        return {
            "valid": False,
            "message": f"Error: {str(e)}"
        }

# API endpoint to validate a single token
@app.route('/api/validate-token', methods=['POST'])
def api_validate_token():
    data = request.json
    token = data.get('token', '').strip()
    
    if not token:
        return jsonify({"valid": False, "message": "No token provided"})
    
    result = validate_token(token)
    return jsonify(result)

# API endpoint to validate multiple tokens
@app.route('/api/validate-tokens', methods=['POST'])
def api_validate_tokens():
    data = request.json
    tokens = data.get('tokens', [])
    
    if not tokens:
        return jsonify({"valid": False, "message": "No tokens provided"})
    
    results = []
    for token in tokens:
        token = token.strip()
        if token:
            result = validate_token(token)
            result['token'] = token
            results.append(result)
    
    return jsonify({"results": results})

# API endpoint to format combo lists
@app.route('/api/format-combo', methods=['POST'])
def api_format_combo():
    data = request.json
    combo_text = data.get('combo', '').strip()
    
    if not combo_text:
        return jsonify({"success": False, "message": "No combo provided"})
    
    lines = combo_text.strip().split('\n')
    tokens = []
    email_pass = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        parts = line.split(':')
        if len(parts) >= 3:  # email:pass:token format
            email = parts[0]
            password = parts[1]
            token = parts[2]
            
            tokens.append(token)
            email_pass.append(f"{email}:{password}")
    
    return jsonify({
        "success": True,
        "tokens": tokens,
        "email_pass": email_pass
    })

# Function to validate Discord Nitro promo link
def validate_promo_link(promo_url):
    try:
        # Extract the promo code from URL
        promo_code = promo_url.split('/')[-1]
        
        # Make a request to check if the promo is valid
        response = requests.get(f"https://discord.com/api/v9/entitlements/gift-codes/{promo_code}?with_application=false&with_subscription_plan=true")
        
        # If valid, get details
        if response.status_code == 200:
            data = response.json()
            
            # Extract info
            subscription_plan = data.get('subscription_plan', {})
            expires_at = data.get('expires_at')
            expiration = datetime.fromisoformat(expires_at.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S UTC') if expires_at else 'N/A'
            
            return {
                "valid": True,
                "promo_url": promo_url,
                "promo_code": promo_code,
                "name": subscription_plan.get('name', 'Unknown'),
                "description": subscription_plan.get('description', ''),
                "expiration": expiration
            }
        else:
            # Return invalid with specific message based on status code
            message = "Invalid or expired promo link"
            if response.status_code == 404:
                message = "Promo link not found or already redeemed"
            elif response.status_code == 429:
                message = "Rate limited, please try again later"
                
            return {
                "valid": False,
                "promo_url": promo_url,
                "promo_code": promo_code,
                "message": message
            }
    except Exception as e:
        logging.error(f"Error validating promo link: {str(e)}")
        return {
            "valid": False,
            "promo_url": promo_url,
            "message": f"Error: {str(e)}"
        }

# API endpoint to validate Nitro promo links
@app.route('/api/validate-promo-links', methods=['POST'])
def api_validate_promo_links():
    data = request.json
    links = data.get('links', [])
    
    if not links:
        return jsonify({"success": False, "message": "No promo links provided"})
    
    results = []
    for link in links:
        link = link.strip()
        if link and ('discord.gift' in link or 'discordapp.com/gifts' in link or 'discord.com/gifts' in link):
            result = validate_promo_link(link)
            results.append(result)
    
    return jsonify({
        "success": True,
        "results": results
    })

# API endpoint to get Discord links
@app.route('/api/discord-links', methods=['GET'])
def api_discord_links():
    links = load_config_data('discord_links')
    return jsonify({"links": links})

# API endpoint to get products
@app.route('/api/products', methods=['GET'])
def api_products():
    products = load_config_data('products')
    return jsonify({"products": products})

# API endpoint to get social links
@app.route('/api/social-links', methods=['GET'])
def api_social_links():
    social_links = load_config_data('social_links')
    return jsonify({"social_links": social_links})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9284, debug=True)
