import os
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
import secrets
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_limiter.errors import RateLimitExceeded

# Import extensions
from extensions import db, login_manager, bcrypt, limiter

# Load environment variables
load_dotenv()

# Initialize CSRF protection
csrf = CSRFProtect()

# ✅ ROUTES BINDING FUNCTION
def register_routes(app):
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/about')
    def about():
        return render_template('about.html')

    @app.route('/login')
    def login():
        return render_template('login.html')

    @app.route('/register')
    def register():
        return render_template('register.html')

    @app.route('/account')
    def account():
        return render_template('account.html')

    @app.route('/transfer')
    def transfer():
        return render_template('transfer.html')

    @app.route('/confirm-transfer')
    def confirm_transfer():
        return render_template('confirm_transfer.html')

    @app.route('/reset-password-request')
    def reset_password_request():
        return render_template('reset_password_request.html')  # Fix typo here

    @app.route('/reset-password')
    def reset_password():
        return render_template('reset_password.html')

    @app.route('/rate-limit-error')
    def rate_limit_error():
        return render_template('rate_limit_error.html')

    # Admin folder templates
    @app.route('/admin/create-account')
    def admin_create_account():
        return render_template('admin/create_account.html')

    @app.route('/admin/dashboard')
    def admin_dashboard():
        return render_template('admin/dashboard.html')

    @app.route('/admin/deposit')
    def admin_deposit():
        return render_template('admin/deposit.html')

    @app.route('/admin/edit-user')
    def admin_edit_user():
        return render_template('admin/edit_user.html')

    # Manager folder templates
    @app.route('/manager/admin-list')
    def manager_admin_list():
        return render_template('manager/admin_list.html')

    @app.route('/manager/admin-transactions')
    def manager_admin_transactions():
        return render_template('manager/admin_transactions.html')

    @app.route('/manager/create-admin')
    def manager_create_admin():
        return render_template('manager/create_admin.html')

    @app.route('/manager/dashboard')
    def manager_dashboard():
        return render_template('manager/dashboard.html')

    @app.route('/manager/transfers')
    def manager_transfers():
        return render_template('manager/transfers.html')

    @app.route('/manager/user-list')
    def manager_user_list():
        return render_template('manager/user_list.html')

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(16)

    # ✅ Session security settings
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_REFRESH_EACH_REQUEST=True
    )

    # ✅ CSRF Protection
    csrf.init_app(app)

    # ✅ Flask-Talisman for security headers
    Talisman(app, content_security_policy={
        'default-src': "'self'",
        'script-src': ["'self'", "cdnjs.cloudflare.com"]
    })

    # Database configuration - Using SQLite
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'site.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)

    # Register HTML routes
    register_routes(app)

    # Rate limit error handler
    @app.errorhandler(RateLimitExceeded)
    def handle_rate_limit_exceeded(e):
        if request.path.startswith('/api/') or request.headers.get('Accept') == 'application/json':
            return jsonify({"error": "Rate limit exceeded", "message": str(e)}), 429
        return render_template('rate_limit_error.html', message=str(e)), 429

    # Token generator using app's secret key
    def generate_reset_token(email):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return s.dumps(email, salt='password-reset')

    def verify_reset_token(token, max_age=1800):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            email = s.loads(token, salt='password-reset', max_age=max_age)
        except Exception:
            return None
        return email

    # Attach these to app for later usage if needed
    app.generate_reset_token = generate_reset_token
    app.verify_reset_token = verify_reset_token

    return app

# Create Flask app instance
app = create_app()

# Import models after app creation
from models import User, Transaction

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database initialization
def init_db():
    with app.app_context():
        db.create
