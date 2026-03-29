from dotenv import load_dotenv
load_dotenv()
from pathlib import Path
from flask import send_file, Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid
import os
from sqlalchemy import text
import pytz
import random
import string
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
import re

def validate_session_id(session_id: str) -> bool:
    """Only allow alphanumeric + underscore, max 50 chars"""
    return bool(re.match(r'^[A-Z0-9_]{1,50}$', session_id))

# Define IST timezone
IST = pytz.timezone('Asia/Kolkata')

def get_ist_now():
    """Get current time in IST"""
    return datetime.now(IST)

def utc_to_ist(utc_dt):
    """Convert UTC datetime to IST"""
    if utc_dt is None:
        return None
    if utc_dt.tzinfo is None:
        utc_dt = pytz.utc.localize(utc_dt)
    return utc_dt.astimezone(IST)

app = Flask(__name__) 
ALLOWED_ORIGINS = [
    "http://localhost:5001",
    "http://localhost:3000",
    "file://",                                          # Electron app in production
    os.environ.get('ELECTRON_ORIGIN', ''),              # optional override
    os.environ.get('FRONTEND_URL', ''),                 # admin dashboard URL if hosted
]
CORS(app, resources={
    r"/api/*": {
        "origins": [o for o in ALLOWED_ORIGINS if o],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})
limiter = Limiter(get_remote_address, app=app, default_limits=[])
# Configuration - Use absolute path for database
BASE_DIR = Path(__file__).parent
INSTANCE_DIR = BASE_DIR / 'instance'
INSTANCE_DIR.mkdir(exist_ok=True)  # Create instance folder if not exists

database_url = os.environ.get('DATABASE_URL', f'sqlite:///{INSTANCE_DIR / "printshop.db"}')
# Railway gives URLs starting with "postgres://" — SQLAlchemy needs "postgresql://"
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY') or secrets.token_hex(32)
# Raise hard error in production if not set:
if not os.getenv('JWT_SECRET_KEY'):
    import warnings
    warnings.warn("JWT_SECRET_KEY not set! Using random key — sessions will not persist across restarts.")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)

db = SQLAlchemy(app)
jwt = JWTManager(app)
# Database Models
class Shop(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shop_id = db.Column(db.String(50), unique=True, nullable=False)
    shop_name = db.Column(db.String(100), nullable=False)
    owner_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    address = db.Column(db.Text)
    city = db.Column(db.String(50))
    state = db.Column(db.String(50))
    pincode = db.Column(db.String(10))
    whatsapp_number = db.Column(db.String(20))
    subscription_status = db.Column(db.String(20), default='trial')
    subscription_end = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=get_ist_now)
    is_active = db.Column(db.Boolean, default=True)
    orders = db.relationship('Order', back_populates='shop', lazy=True)
    printers = db.relationship('Printer', backref='shop', lazy=True)
    printer_config = db.Column(db.Text)  

class Printer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shop_id = db.Column(db.Integer, db.ForeignKey('shop.id'), nullable=False)
    printer_name = db.Column(db.String(100), nullable=False)
    printer_type = db.Column(db.String(50))
    status = db.Column(db.String(20), default='online')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    total_prints = db.Column(db.Integer, default=0)
    ip_address = db.Column(db.String(50))
    port = db.Column(db.Integer, default=9100)
    protocol = db.Column(db.String(20), default='socket')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.String(50), unique=True, nullable=False)
    shop_id = db.Column(db.Integer, db.ForeignKey('shop.id'), nullable=False)
    session_id = db.Column(db.String(50))
    customer_phone = db.Column(db.String(20))
    total_pages = db.Column(db.Integer)
    total_sheets = db.Column(db.Integer)
    total_price = db.Column(db.Float)
    payment_status = db.Column(db.String(20), default='pending')
    order_status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=get_ist_now)
    completed_at = db.Column(db.DateTime)
    order_data = db.Column(db.Text)
    shop = db.relationship('Shop', foreign_keys=[shop_id], back_populates='orders', lazy='select')
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='admin')

with app.app_context():
    db.create_all()    
    admin_username = os.getenv('ADMIN_USERNAME', 'admin')
    admin_password = os.getenv('ADMIN_PASSWORD')
    if not admin_password:
        print("⚠️ ADMIN_PASSWORD not set — skipping admin creation")
        admin_password = None
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@printshop.com')
    
    print(f"\n🔐 Admin account initialized")
    
    if admin_password:  # ← ADD THIS LINE
        # First, check if there's an admin with the same email but different username
        admin_by_email = Admin.query.filter_by(email=admin_email).first()
        admin_by_username = Admin.query.filter_by(username=admin_username).first()
        
        if admin_by_email and admin_by_email.username != admin_username:
            admin_by_email.username = admin_username
            admin_by_email.password_hash = generate_password_hash(admin_password)
            db.session.commit()
            print(f"✅ Admin user updated: {admin_username}")
        elif admin_by_username:
            admin_by_username.email = admin_email
            admin_by_username.password_hash = generate_password_hash(admin_password)
            db.session.commit()
            print(f"✅ Admin credentials updated")
        else:
            admin = Admin(
                username=admin_username,
                email=admin_email,
                password_hash=generate_password_hash(admin_password)
            )
            db.session.add(admin)
            db.session.commit()
            print(f"✅ Admin user created: {admin_username}")

# ============ WHATSAPP OTP SYSTEM ============
whatsapp_otps = {}
@app.route('/api/shop/send-whatsapp-otp', methods=['POST'])
@jwt_required()
@limiter.limit("3 per minute")
def send_whatsapp_otp():
    """Send OTP to WhatsApp number for verification"""
    try:
        identity = get_jwt_identity()
        shop_id = int(identity) if isinstance(identity, str) else identity

        shop = Shop.query.get(shop_id)
        if not shop:
            return jsonify({'success': False, 'error': 'Shop not found'}), 404

        data = request.json
        whatsapp_number = data.get('whatsapp_number', '').strip()

        if not whatsapp_number or len(whatsapp_number) != 10 or not whatsapp_number.isdigit():
            return jsonify({
                'success': False,
                'error': 'Please enter a valid 10-digit phone number'
            }), 400

        # Eviction block — only ONCE, only here
        if len(whatsapp_otps) > 10000:
            now = datetime.utcnow()
            expired = [k for k, v in whatsapp_otps.items() if now > v['expires_at']]
            for k in expired:
                del whatsapp_otps[k]

        otp = ''.join(random.choices(string.digits, k=6))

        otp_key = f"{shop_id}_{whatsapp_number}"
        whatsapp_otps[otp_key] = {
            'otp': otp,
            'expires_at': datetime.utcnow() + timedelta(minutes=10),
            'attempts': 0
        }

        print(f"📱 OTP generated for shop: {shop.shop_name}")
        if os.getenv('FLASK_DEBUG', 'false').lower() == 'true':
            print(f"   [DEV ONLY] OTP: {otp}")

        return jsonify({
            'success': True,
            'message': 'OTP sent successfully to WhatsApp',
        }), 200

    except Exception as e:
        print(f"Send WhatsApp OTP error: {str(e)}")
        import traceback
        traceback.print_exc()
        print(f"Error: {str(e)}")   # keep the real error in your Railway logs
        return jsonify({'success': False, 'error': 'An unexpected error occurred'}), 500
@app.route('/api/shop/verify-whatsapp-otp', methods=['POST'])
@jwt_required()
def verify_whatsapp_otp():
    """Verify OTP and update WhatsApp number in database"""
    try:
        identity = get_jwt_identity()
        shop_id = int(identity) if isinstance(identity, str) else identity
        
        shop = Shop.query.get(shop_id)
        if not shop:
            return jsonify({'success': False, 'error': 'Shop not found'}), 404
        
        data = request.json
        whatsapp_number = data.get('whatsapp_number', '').strip()
        entered_otp = data.get('otp', '').strip()
        
        if not whatsapp_number or not entered_otp:
            return jsonify({
                'success': False,
                'error': 'Phone number and OTP are required'
            }), 400
        
        # Check if OTP exists
        otp_key = f"{shop_id}_{whatsapp_number}"
        
        if otp_key not in whatsapp_otps:
            return jsonify({
                'success': False,
                'error': 'No OTP found. Please request a new OTP.'
            }), 400
        
        stored_data = whatsapp_otps[otp_key]
        
        # Check if expired
        if datetime.utcnow() > stored_data['expires_at']:
            del whatsapp_otps[otp_key]
            return jsonify({
                'success': False,
                'error': 'OTP has expired. Please request a new one.'
            }), 400
        
        # Check attempts (max 3)
        if stored_data['attempts'] >= 3:
            del whatsapp_otps[otp_key]
            return jsonify({
                'success': False,
                'error': 'Too many failed attempts. Please request a new OTP.'
            }), 400
        
        # Verify OTP
        if stored_data['otp'] != entered_otp:
            stored_data['attempts'] += 1
            return jsonify({
                'success': False,
                'error': f'Invalid OTP. {3 - stored_data["attempts"]} attempts remaining.'
            }), 400
        
        # OTP is valid - update shop's WhatsApp number in database
        shop.whatsapp_number = whatsapp_number
        shop.phone = whatsapp_number
        db.session.commit()
        
        # Clear OTP
        del whatsapp_otps[otp_key]
        
        print(f"✅ WhatsApp number verified and updated in database for shop: {shop.shop_name}")
        print(f"   New number: {whatsapp_number}")
        
        return jsonify({
            'success': True,
            'message': 'WhatsApp number verified and updated successfully',
            'shop': {
                'id': shop.id,
                'shop_id': shop.shop_id,
                'shop_name': shop.shop_name,
                'whatsapp_number': shop.whatsapp_number,
                'phone': shop.phone
            }
        }), 200
        
    except Exception as e:
        print(f"Verify WhatsApp OTP error: {str(e)}")
        import traceback
        traceback.print_exc()
        db.session.rollback()
        print(f"Error: {str(e)}")   # keep the real error in your Railway logs
        return jsonify({'success': False, 'error': 'An unexpected error occurred'}), 500
    
reset_codes = {}
@app.route('/api/shop/forgot-password', methods=['POST'])
@limiter.limit("5 per minute")
def forgot_password():
    """Send password reset code to shop email"""
    try:
        data = request.json
        email = data.get('email') if data else None

        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400

        shop = Shop.query.filter_by(email=email).first()

        # Always return the same response whether email exists or not
        # This prevents attackers from knowing which emails are registered
        if not shop:
            return jsonify({
                'success': True,
                'message': 'If email exists, reset code has been sent'
            })

        # Generate 6-digit code
        code = ''.join(random.choices(string.digits, k=6))

        # Store code with expiry (10 minutes)
        reset_codes[email] = {
            'code': code,
            'expires_at': datetime.utcnow() + timedelta(minutes=10)
        }

        # ── Safe log — no OTP value, no sensitive data ──
        print(f"🔐 Reset code generated for shop: {shop.shop_name} (expires in 10 min)")

        # ── TODO: Send code via real email service here ──
        # e.g. send_email(to=email, subject="Reset Code", body=f"Your code: {code}")
        # For development only — remove this print in production:
        if os.getenv('FLASK_DEBUG', 'false').lower() == 'true':
            print(f"   [DEV ONLY] Code: {code}")

        return jsonify({
            'success': True,
            'message': 'Reset code sent to email'
        })

    except Exception as e:
        print(f"Forgot password error: {e}")
        import traceback
        traceback.print_exc()
        print(f"Error: {str(e)}")   # keep the real error in your Railway logs
        return jsonify({'success': False, 'error': 'An unexpected error occurred'}), 500
    
@app.route('/api/shop/verify-reset-code', methods=['POST'])
def verify_reset_code():
    try:
        data = request.json
        email = data.get('email')
        code = data.get('code')
        
        if not email or not code:
            return jsonify({'success': False, 'error': 'Email and code are required'}), 400
        
        # Check if code exists
        if email not in reset_codes:
            return jsonify({'success': False, 'error': 'Invalid or expired code'}), 400
        
        stored_data = reset_codes[email]
        
        # Check if expired
        if datetime.utcnow() > stored_data['expires_at']:
            del reset_codes[email]
            return jsonify({'success': False, 'error': 'Code has expired'}), 400
        
        # Check if code matches
        if stored_data['code'] != code:
            return jsonify({'success': False, 'error': 'Invalid code'}), 400
        
        # Code is valid
        return jsonify({'success': True, 'message': 'Code verified'})
        
    except Exception as e:
        print(f"Verify code error: {e}")
        print(f"Error: {str(e)}")   # keep the real error in your Railway logs
        return jsonify({'success': False, 'error': 'An unexpected error occurred'}), 500


@app.route('/api/shop/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.json
        email = data.get('email')
        new_password = data.get('password')
        code = data.get('code')  # ← Require code here

        if not email or not new_password or not code:
            return jsonify({'success': False, 'error': 'Email, code, and password are required'}), 400

        # ← Validate reset code before touching the DB
        if email not in reset_codes:
            return jsonify({'success': False, 'error': 'Invalid or expired reset code'}), 400

        stored_data = reset_codes[email]
        if datetime.utcnow() > stored_data['expires_at']:
            del reset_codes[email]
            return jsonify({'success': False, 'error': 'Reset code has expired'}), 400

        if stored_data['code'] != code:
            return jsonify({'success': False, 'error': 'Invalid reset code'}), 400

        shop = Shop.query.filter_by(email=email).first()
        if not shop:
            return jsonify({'success': False, 'error': 'Shop not found'}), 404

        if len(new_password) < 8:
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400

        shop.password_hash = generate_password_hash(new_password)
        db.session.commit()
        del reset_codes[email]

        return jsonify({'success': True, 'message': 'Password reset successful'})

    except Exception as e:
        db.session.rollback()
        print(f"Error: {str(e)}")   # keep the real error in your Railway logs
        return jsonify({'success': False, 'error': 'An unexpected error occurred'}), 500
    
@app.route('/api/shop/register', methods=['POST'])
def shop_register():
    """Shop owner registration"""
    try:
        data = request.json
        
        # Validate required fields
        required = ['shop_name', 'owner_name', 'email', 'phone', 'password']
        if not all(field in data for field in required):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        # Validate email format
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', data['email']):
            return jsonify({'success': False, 'error': 'Invalid email address'}), 400

        # Validate password strength
        if len(data['password']) < 8:
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400

        # Validate phone — 10 digits
        if not re.match(r'^\d{10}$', data['phone']):
            return jsonify({'success': False, 'error': 'Phone must be a 10-digit number'}),
        
        # Check if email already exists
        if Shop.query.filter_by(email=data['email']).first():
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
        
        # Create shop
        shop_id = f"SHOP_{uuid.uuid4().hex[:8].upper()}"
        shop = Shop(
            shop_id=shop_id,
            shop_name=data['shop_name'],
            owner_name=data['owner_name'],
            email=data['email'],
            phone=data['phone'],
            password_hash=generate_password_hash(data['password']),
            address=data.get('address'),
            city=data.get('city'),
            state=data.get('state'),
            pincode=data.get('pincode'),
            whatsapp_number=data.get('whatsapp_number', data['phone']),
            subscription_status='trial',
            subscription_end=get_ist_now() + timedelta(days=30)
        )
        
        db.session.add(shop)
        db.session.commit()
        
        # Create token with string identity
        token = create_access_token(identity=str(shop.id))
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'token': token,
            'shop': {
                'id': shop.id,
                'shop_id': shop.shop_id,
                'shop_name': shop.shop_name,
                'owner_name': shop.owner_name,
                'email': shop.email,
                'subscription_status': shop.subscription_status,
                'subscription_end': shop.subscription_end.isoformat() if shop.subscription_end else None
            },
            'trial_days': 30
        }), 201
    except Exception as e:
        print(f"Registration error: {str(e)}")
        db.session.rollback()
        print(f"Error: {str(e)}")   # keep the real error in your Railway logs
        return jsonify({'success': False, 'error': 'An unexpected error occurred'}), 500

@app.route('/api/shop/login', methods=['POST'])
@limiter.limit("10 per minute")
def shop_login():
    """Shop owner login"""
    try:
        data = request.json
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'success': False, 'error': 'Email and password required'}), 400
        
        shop = Shop.query.filter_by(email=data['email']).first()
        
        if not shop or not check_password_hash(shop.password_hash, data['password']):
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        if not shop.is_active:
            return jsonify({'success': False, 'error': 'Account deactivated'}), 403
        
        # Create token with string identity
        token = create_access_token(identity=str(shop.id))
        
        return jsonify({
            'success': True,
            'token': token,
            'shop': {
                'id': shop.id,
                'shop_id': shop.shop_id,
                'shop_name': shop.shop_name,
                'owner_name': shop.owner_name,
                'email': shop.email,
                'subscription_status': shop.subscription_status,
                'subscription_end': shop.subscription_end.isoformat() if shop.subscription_end else None
            }
        })
    except Exception as e:
        print(f"Error: {str(e)}")   # keep the real error in your Railway logs
        return jsonify({'success': False, 'error': 'An unexpected error occurred'}), 500
    
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    try:
        db.session.execute(text('SELECT 1'))
        db_status = 'ok'
    except Exception as e:
        db_status = f'error: {str(e)}'
    
    return jsonify({
        'status': 'ok',
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat()
    })

# ============ SHOP ROUTES ============

@app.route('/api/shop/dashboard', methods=['GET'])
@jwt_required()
def shop_dashboard():
    """Get shop dashboard data"""
    try:
        from sqlalchemy import func

        identity = get_jwt_identity()
        shop_id = int(identity) if isinstance(identity, str) else identity

        shop = Shop.query.get(shop_id)
        if not shop:
            return jsonify({'error': 'Shop not found'}), 404

        # ── Time boundaries in IST, converted to naive for DB comparison ──
        now_ist = get_ist_now()
        today_start = now_ist.replace(hour=0, minute=0, second=0, microsecond=0).replace(tzinfo=None)
        month_start = now_ist.replace(day=1, hour=0, minute=0, second=0, microsecond=0).replace(tzinfo=None)

        # ── Today stats — DB does the SUM/COUNT, no rows loaded into Python ──
        today_stats = db.session.query(
            func.count(Order.id),
            func.sum(Order.total_price),
            func.sum(Order.total_pages)
        ).filter(
            Order.shop_id == shop.id,
            Order.created_at >= today_start,
            Order.payment_status == 'paid'
        ).first()

        today_order_count = Order.query.filter(
            Order.shop_id == shop.id,
            Order.created_at >= today_start
        ).count()

        # ── Month stats — same pattern ──
        month_stats = db.session.query(
            func.count(Order.id),
            func.sum(Order.total_price),
            func.sum(Order.total_pages)
        ).filter(
            Order.shop_id == shop.id,
            Order.created_at >= month_start,
            Order.payment_status == 'paid'
        ).first()

        month_order_count = Order.query.filter(
            Order.shop_id == shop.id,
            Order.created_at >= month_start
        ).count()

        # ── Printers — only those with a configured IP ──
        printers = Printer.query.filter(
            Printer.shop_id == shop.id,
            Printer.ip_address != None,
            Printer.ip_address != ''
        ).all()

        # ── Recent orders — last 10, no extra queries ──
        recent_orders = Order.query.filter_by(
            shop_id=shop.id
        ).order_by(
            Order.created_at.desc()
        ).limit(10).all()

        # ── Debug log — only when FLASK_DEBUG=true ──
        if os.getenv('FLASK_DEBUG', 'false').lower() == 'true':
            print(f"Dashboard: shop={shop.id}, today_orders={today_order_count}")

        return jsonify({
            'shop': {
                'shop_name': shop.shop_name,
                'subscription_status': shop.subscription_status,
                'subscription_end': shop.subscription_end.isoformat() if shop.subscription_end else None
            },
            'today': {
                'orders': today_order_count,
                'revenue': float(today_stats[1] or 0),
                'pages_printed': today_stats[2] or 0
            },
            'month': {
                'orders': month_order_count,
                'revenue': float(month_stats[1] or 0),
                'pages_printed': month_stats[2] or 0
            },
            'printers': [{
                'name': p.printer_name,
                'status': p.status,
                'total_prints': p.total_prints,
                'last_seen': p.last_seen.isoformat() if p.last_seen else None
            } for p in printers],
            'recent_orders': [{
                'order_id': o.order_id,
                'customer_phone': o.customer_phone,
                'total_pages': o.total_pages,
                'total_price': o.total_price,
                'status': o.order_status,
                'payment_status': o.payment_status,
                'created_at': o.created_at.isoformat() if o.created_at else None
            } for o in recent_orders]
        })

    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

    
@app.route('/api/shop/whatsapp-session', methods=['GET'])
@jwt_required()
def get_whatsapp_session():
    """Get shop's WhatsApp session ID for connecting to bot"""
    try:
        identity = get_jwt_identity()
        shop_id = int(identity) if isinstance(identity, str) else identity
        
        shop = Shop.query.get(shop_id)
        if not shop:
            return jsonify({'error': 'Shop not found'}), 404
        
        # Return shop's unique session ID
        return jsonify({
            'success': True,
            'session_id': shop.shop_id,  # e.g., "SHOP_ABC12345"
            'shop_name': shop.shop_name,
            'whatsapp_number': shop.whatsapp_number
        })
        
    except Exception as e:
        print(f"Get WhatsApp session error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/shop/orders', methods=['GET'])
@jwt_required()
def get_shop_orders():
    """Get all orders for shop"""
    try:
        identity = get_jwt_identity()
        shop_id = int(identity) if isinstance(identity, str) else identity
        shop = Shop.query.get(shop_id)
        
        if not shop:
            return jsonify({'error': 'Shop not found'}), 404
        
        status = request.args.get('status')  # Can be: pending, completed, cancelled
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        
        query = Order.query.filter_by(shop_id=shop.id)
        
        if status:
            query = query.filter_by(order_status=status)
        
        orders = query.order_by(Order.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'orders': [{
                'order_id': o.order_id,
                'customer_phone': o.customer_phone,
                'total_pages': o.total_pages,
                'total_sheets': o.total_sheets,
                'total_price': o.total_price,
                'payment_status': o.payment_status,
                'order_status': o.order_status,
                'created_at': o.created_at.isoformat(),
                'completed_at': o.completed_at.isoformat() if o.completed_at else None
            } for o in orders.items],
            'total': orders.total,
            'pages': orders.pages,
            'current_page': orders.page
        })
    except Exception as e:
        print(f"Get orders error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/shop/order/<order_id>', methods=['GET', 'PUT'])
@jwt_required()
def manage_order(order_id):
    """Get or update specific order"""
    try:
        identity = get_jwt_identity()
        shop_id = int(identity) if isinstance(identity, str) else identity
        shop = Shop.query.get(shop_id)
        
        if not shop:
            return jsonify({'error': 'Shop not found'}), 404
        
        order = Order.query.filter_by(order_id=order_id, shop_id=shop.id).first()
        
        if not order:
            return jsonify({'error': 'Order not found'}), 404
        
        if request.method == 'GET':
            import json
            return jsonify({
                'order_id': order.order_id,
                'customer_phone': order.customer_phone,
                'total_pages': order.total_pages,
                'total_sheets': order.total_sheets,
                'total_price': order.total_price,
                'payment_status': order.payment_status,
                'order_status': order.order_status,
                'created_at': order.created_at.isoformat(),
                'order_data': json.loads(order.order_data) if order.order_data else None
            })
        
        elif request.method == 'PUT':
            data = request.json
            
            if 'order_status' in data:
                order.order_status = data['order_status']
                if data['order_status'] == 'completed':
                    order.completed_at = datetime.utcnow()
            
            if 'payment_status' in data:
                order.payment_status = data['payment_status']
            
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'Order updated'})
    except Exception as e:
        print(f"Manage order error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Admin login"""
    try:
        data = request.json
        
        admin = Admin.query.filter_by(username=data.get('username')).first()
        
        if not admin or not check_password_hash(admin.password_hash, data['password']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # String identity for admin too
        token = create_access_token(identity=f"admin_{admin.id}")
        
        return jsonify({
            'success': True,
            'token': token,
            'admin': {
                'username': admin.username,
                'email': admin.email,
                'role': admin.role
            }
        })
    except Exception as e:
        print(f"Admin login error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    

@app.route('/api/admin/dashboard', methods=['GET'])
@jwt_required()
def admin_dashboard():
    """Admin dashboard with all shops data"""
    try:
        identity = get_jwt_identity()
        if not identity.startswith('admin_'):
            return jsonify({'error': 'Unauthorized'}), 403

        from sqlalchemy import func
        from sqlalchemy.orm import joinedload

        period = request.args.get('period', 'month')
        now = datetime.utcnow()

        # ── Period start date ──
        if period == 'today':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == 'week':
            start_date = now - timedelta(days=7)
        elif period == 'month':
            start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            start_date = datetime(2020, 1, 1)

        today = now.replace(hour=0, minute=0, second=0, microsecond=0)

        # ── Shops list — DB aggregation per shop, not Python filtering ──
        shops = Shop.query.all()
        shops_data = []
        for shop in shops:
            orders_count = Order.query.filter(
                Order.shop_id == shop.id,
                Order.created_at >= start_date
            ).count()

            completed_stats = db.session.query(
                func.count(Order.id),
                func.sum(Order.total_price),
                func.sum(Order.total_pages)
            ).filter(
                Order.shop_id == shop.id,
                Order.created_at >= start_date,
                Order.order_status == 'completed'
            ).first()

            shops_data.append({
                'id': shop.id,
                'shop_id': shop.shop_id,
                'shop_name': shop.shop_name,
                'owner_name': shop.owner_name,
                'email': shop.email,
                'phone': shop.phone,
                'city': shop.city,
                'state': shop.state,
                'is_active': shop.is_active,
                'subscription_status': shop.subscription_status,
                'subscription_end': shop.subscription_end.isoformat() if shop.subscription_end else None,
                'created_at': shop.created_at.isoformat(),
                'orders_count': orders_count,
                'completed_orders': completed_stats[0] or 0,
                'revenue': float(completed_stats[1] or 0),
                'pages_printed': completed_stats[2] or 0,
            })

        # ── Overall stats — all DB-level, no Python filtering ──
        completed_filter = (Order.order_status == 'completed')

        stats = {
            'total_shops': len(shops),
            'active_shops': sum(1 for s in shops if s.is_active),
            'total_orders': Order.query.count(),
            'total_revenue': db.session.query(func.sum(Order.total_price))
                                .filter(completed_filter).scalar() or 0,
            'total_pages': db.session.query(func.sum(Order.total_pages))
                                .filter(completed_filter).scalar() or 0,
            'today_orders': Order.query.filter(Order.created_at >= today).count(),
            'today_revenue': db.session.query(func.sum(Order.total_price))
                                .filter(completed_filter, Order.created_at >= today)
                                .scalar() or 0,
            'today_pages': db.session.query(func.sum(Order.total_pages))
                                .filter(completed_filter, Order.created_at >= today)
                                .scalar() or 0,
        }

        # ── Recent orders — joinedload to avoid N+1 ──
        recent_orders = Order.query.options(joinedload(Order.shop)).order_by(
            Order.created_at.desc()
        ).limit(20).all()

        recent_orders_data = [{
            'order_id': o.order_id,
            'shop_name': o.shop.shop_name if o.shop else 'Unknown',
            'shop_id': o.shop.shop_id if o.shop else None,
            'customer_phone': o.customer_phone,
            'total_pages': o.total_pages,
            'total_price': o.total_price,
            'order_status': o.order_status,
            'payment_status': o.payment_status,
            'created_at': o.created_at.isoformat()
        } for o in recent_orders]

        return jsonify({
            'success': True,
            'period': period,
            'stats': stats,
            'shops': shops_data,
            'recent_orders': recent_orders_data
        })

    except Exception as e:
        print(f"Admin dashboard error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/shops', methods=['GET'])
@jwt_required()
def admin_get_shops():
    """Get all shops with detailed info"""
    try:
        identity = get_jwt_identity()
        if not identity.startswith('admin_'):
            return jsonify({'error': 'Unauthorized'}), 403

        from sqlalchemy import func

        shops = Shop.query.all()
        shops_data = []

        for shop in shops:
            # One query gets count + revenue + pages for completed orders
            completed_stats = db.session.query(
                func.count(Order.id),
                func.sum(Order.total_price),
                func.sum(Order.total_pages)
            ).filter(
                Order.shop_id == shop.id,
                Order.order_status == 'completed'
            ).first()

            total_orders = Order.query.filter_by(shop_id=shop.id).count()
            printers_count = Printer.query.filter_by(shop_id=shop.id).count()

            shops_data.append({
                'id': shop.id,
                'shop_id': shop.shop_id,
                'shop_name': shop.shop_name,
                'owner_name': shop.owner_name,
                'email': shop.email,
                'phone': shop.phone,
                'address': shop.address,
                'city': shop.city,
                'state': shop.state,
                'pincode': shop.pincode,
                'whatsapp_number': shop.whatsapp_number,
                'is_active': shop.is_active,
                'subscription_status': shop.subscription_status,
                'subscription_end': shop.subscription_end.isoformat() if shop.subscription_end else None,
                'created_at': shop.created_at.isoformat(),
                'total_orders': total_orders,
                'completed_orders': completed_stats[0] or 0,
                'total_revenue': float(completed_stats[1] or 0),
                'total_pages': completed_stats[2] or 0,
                'printers_count': printers_count,
            })

        return jsonify({'success': True, 'shops': shops_data})

    except Exception as e:
        print(f"Get shops error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/shop/<int:shop_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def admin_manage_shop(shop_id):
    """Get, update, or delete a specific shop"""
    try:
        identity = get_jwt_identity()
        
        if not identity.startswith('admin_'):
            return jsonify({'error': 'Unauthorized'}), 403
        
        shop = Shop.query.get(shop_id)
        if not shop:
            return jsonify({'error': 'Shop not found'}), 404
        
        if request.method == 'GET':
            from sqlalchemy import func

            total_orders = Order.query.filter_by(shop_id=shop.id).count()

            completed_stats = db.session.query(
                func.count(Order.id),
                func.sum(Order.total_price),
                func.sum(Order.total_pages)
            ).filter(
                Order.shop_id == shop.id,
                Order.order_status == 'completed'
            ).first()

            printers = Printer.query.filter_by(shop_id=shop.id).all()

            return jsonify({
                'success': True,
                'shop': {
                    'id': shop.id,
                    'shop_id': shop.shop_id,
                    'shop_name': shop.shop_name,
                    'owner_name': shop.owner_name,
                    'email': shop.email,
                    'phone': shop.phone,
                    'address': shop.address,
                    'city': shop.city,
                    'state': shop.state,
                    'pincode': shop.pincode,
                    'whatsapp_number': shop.whatsapp_number,
                    'is_active': shop.is_active,
                    'subscription_status': shop.subscription_status,
                    'subscription_end': shop.subscription_end.isoformat() if shop.subscription_end else None,
                    'created_at': shop.created_at.isoformat(),
                    'total_orders': total_orders,
                    'completed_orders': completed_stats[0] or 0,
                    'total_revenue': float(completed_stats[1] or 0),
                    'total_pages': completed_stats[2] or 0,
                    'printers': [{
                        'id': p.id,
                        'name': p.printer_name,
                        'type': p.printer_type,
                        'status': p.status
                    } for p in printers]
                }
            })
        
        elif request.method == 'PUT':
            data = request.json
            
            # Update allowed fields
            if 'is_active' in data:
                shop.is_active = data['is_active']
            if 'subscription_status' in data:
                shop.subscription_status = data['subscription_status']
            if 'subscription_end' in data and data['subscription_end']:
                shop.subscription_end = datetime.fromisoformat(data['subscription_end'])
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Shop updated successfully'
            })
        
        elif request.method == 'DELETE':
            # Soft delete - just deactivate
            shop.is_active = False
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Shop deactivated successfully'
            })
            
    except Exception as e:
        print(f"Manage shop error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/orders', methods=['GET'])
@jwt_required()
def admin_get_all_orders():
    """Get all orders across all shops"""
    try:
        identity = get_jwt_identity()

        if not identity.startswith('admin_'):
            return jsonify({'error': 'Unauthorized'}), 403

        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        status = request.args.get('status')
        shop_id_param = request.args.get('shop_id')

        # ── FIX Issue 12: Use JOIN so we don't query Shop inside the loop ──
        # Instead of doing Shop.query.get(order.shop_id) for each order (N+1),
        # we tell SQLAlchemy to fetch the related Shop row in the SAME query.
        from sqlalchemy.orm import joinedload
        query = Order.query.options(joinedload(Order.shop))

        if status:
            query = query.filter(Order.order_status == status)

        # ── FIX Issue 9: Safely parse shop_id, return 400 if invalid ──
        if shop_id_param is not None:
            # Before fix: int("abc") would raise ValueError → unhandled 500 crash
            # After fix:  we catch it and return a proper 400 response
            try:
                shop_id_int = int(shop_id_param)
            except (ValueError, TypeError):
                return jsonify({'error': 'Invalid shop_id — must be a number'}), 400

            query = query.filter(Order.shop_id == shop_id_int)

        orders = query.order_by(Order.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        orders_data = []
        for order in orders.items:
            # ── FIX Issue 12: order.shop is already loaded — NO extra DB query ──
            # Before fix: shop = Shop.query.get(order.shop_id)  ← hit DB every iteration
            # After fix:  shop = order.shop  ← already in memory from the JOIN above
            shop = order.shop

            orders_data.append({
                'order_id': order.order_id,
                'shop_name': shop.shop_name if shop else 'Unknown',
                'shop_id': shop.shop_id if shop else None,
                'customer_phone': order.customer_phone,
                'total_pages': order.total_pages,
                'total_sheets': order.total_sheets,
                'total_price': order.total_price,
                'payment_status': order.payment_status,
                'order_status': order.order_status,
                'created_at': order.created_at.isoformat(),
                'completed_at': order.completed_at.isoformat() if order.completed_at else None
            })

        return jsonify({
            'success': True,
            'orders': orders_data,
            'total': orders.total,
            'pages': orders.pages,
            'current_page': orders.page
        })

    except Exception as e:
        print(f"Get all orders error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/stats', methods=['GET'])
@jwt_required()
def admin_get_stats():
    """Get detailed statistics for admin"""
    try:
        identity = get_jwt_identity()

        if not identity.startswith('admin_'):
            return jsonify({'error': 'Unauthorized'}), 403

        from sqlalchemy import func

        # Time period boundaries
        now = datetime.utcnow()
        today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_ago = now - timedelta(days=7)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # Reusable filter — only count completed orders for revenue/pages
        completed_filter = (Order.order_status == 'completed')

        stats = {

            # ── Shop counts ──────────────────────────────────────────
            # .count() tells the DB to do COUNT(*) — no rows loaded into Python
            'shops': {
                'total':  Shop.query.count(),
                'active': Shop.query.filter_by(is_active=True).count(),
                'trial':  Shop.query.filter_by(subscription_status='trial').count(),
                'paid':   Shop.query.filter_by(subscription_status='active').count(),
            },

            # ── Order counts ─────────────────────────────────────────
            # DB does COUNT(*) WHERE created_at >= X  — extremely fast with an index
            'orders': {
                'total':     Order.query.count(),
                'today':     Order.query.filter(Order.created_at >= today).count(),
                'week':      Order.query.filter(Order.created_at >= week_ago).count(),
                'month':     Order.query.filter(Order.created_at >= month_start).count(),
                'completed': Order.query.filter_by(order_status='completed').count(),
                'pending':   Order.query.filter_by(order_status='pending').count(),
                'cancelled': Order.query.filter_by(order_status='cancelled').count(),
            },

            # ── Revenue (SUM of total_price) ─────────────────────────
            # func.sum() → DB does SUM(total_price) WHERE ...
            # .scalar() → returns a single value (the sum), not a row object
            # "or 0" → handles the case where there are no rows (scalar returns None)
            'revenue': {
                'total': db.session.query(func.sum(Order.total_price))
                            .filter(completed_filter)
                            .scalar() or 0,

                'today': db.session.query(func.sum(Order.total_price))
                            .filter(completed_filter, Order.created_at >= today)
                            .scalar() or 0,

                'week':  db.session.query(func.sum(Order.total_price))
                            .filter(completed_filter, Order.created_at >= week_ago)
                            .scalar() or 0,

                'month': db.session.query(func.sum(Order.total_price))
                            .filter(completed_filter, Order.created_at >= month_start)
                            .scalar() or 0,
            },

            # ── Pages printed (SUM of total_pages) ───────────────────
            'pages': {
                'total': db.session.query(func.sum(Order.total_pages))
                            .filter(completed_filter)
                            .scalar() or 0,

                'today': db.session.query(func.sum(Order.total_pages))
                            .filter(completed_filter, Order.created_at >= today)
                            .scalar() or 0,

                'week':  db.session.query(func.sum(Order.total_pages))
                            .filter(completed_filter, Order.created_at >= week_ago)
                            .scalar() or 0,

                'month': db.session.query(func.sum(Order.total_pages))
                            .filter(completed_filter, Order.created_at >= month_start)
                            .scalar() or 0,
            },
        }

        return jsonify({
            'success': True,
            'stats': stats
        })

    except Exception as e:
        print(f"Get stats error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============ PUBLIC ORDER SUBMISSION ============
INTERNAL_API_KEY = os.getenv('INTERNAL_API_KEY')
WHATSAPP_BOT_URL = os.environ.get('WHATSAPP_BOT_URL', 'http://localhost:3000')

@app.route('/api/public/order/submit', methods=['POST'])
def submit_order():
    """Submit order from WhatsApp bot"""
    api_key = request.headers.get('X-Internal-Key')
    if not INTERNAL_API_KEY or api_key != INTERNAL_API_KEY:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    try:
        data = request.json
        
        print(f"\n📥 Received order submission:")
        print(f"   Order ID: {data.get('order_id')}")
        print(f"   Shop ID: {data.get('shop_id')}")
        
        shop_identifier = data.get('shop_id')
        
        if not shop_identifier:
            return jsonify({
                'success': False,
                'error': 'Shop ID is required'
            }), 400
        
        # ✅ FIXED: Better shop lookup logic
        shop = None
        
        # Try to find by shop_id (e.g., SHOP_D2B55310) first
        shop = Shop.query.filter_by(shop_id=shop_identifier).first()
        
        # If not found and it's a number, try by database ID
        if not shop and str(shop_identifier).isdigit():
            shop = Shop.query.filter_by(id=int(shop_identifier)).first()
        
        if not shop:
            print(f"❌ Shop not found: {shop_identifier}")
            return jsonify({
                'success': False,
                'error': f'Shop not found: {shop_identifier}'
            }), 404
        
        print(f"✓ Found shop: {shop.shop_name} (ID: {shop.id})")
        
        # Check if order exists
        existing_order = Order.query.filter_by(order_id=data.get('order_id')).first()
        
        if existing_order:
            # ✅ UPDATE existing order
            print(f"⚠️ Order {data.get('order_id')} already exists - UPDATING")
            
            existing_order.payment_status = data.get('payment_status', existing_order.payment_status)
            existing_order.order_status = data.get('order_status', existing_order.order_status)
            existing_order.total_pages = data.get('total_pages', existing_order.total_pages)
            existing_order.total_sheets = data.get('total_sheets', existing_order.total_sheets)
            existing_order.total_price = data.get('total_price', existing_order.total_price)
            existing_order.order_data = data.get('order_data', existing_order.order_data)
            
            if data.get('order_status') == 'confirmed':
                existing_order.completed_at = get_ist_now()
            
            db.session.commit()
            
            print(f"✅ Order {existing_order.order_id} updated successfully!")
            
            return jsonify({
                'success': True,
                'message': 'Order updated successfully',
                'order_id': existing_order.order_id
            }), 200
        
        # ✅ CREATE new order
        import json as json_lib
        order = Order(
            order_id=data.get('order_id'),
            shop_id=shop.id,  # ✅ Use database ID, not shop_id
            session_id=data.get('session_id'),
            customer_phone=data.get('user_id'),
            total_pages=data.get('total_pages', 0),
            total_sheets=data.get('total_sheets', 0),
            total_price=data.get('total_price', 0.0),
            payment_status=data.get('payment_status', 'pending'),
            order_status=data.get('order_status', 'pending'),
            order_data=data.get('order_data')
        )
        
        db.session.add(order)
        db.session.commit()
        
        print(f"✅ Order {order.order_id} created successfully!")
        print(f"   Shop: {shop.shop_name}")
        print(f"   Customer: {data.get('user_id')}")
        print(f"   Total: ₹{data.get('total_price')}")
        
        return jsonify({
            'success': True,
            'order_id': order.order_id,
            'shop_name': shop.shop_name,
            'message': 'Order received successfully'
        }), 201
        
    except Exception as e:
        print(f"❌ Error submitting order: {e}")
        import traceback
        traceback.print_exc()
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/public/order/<order_id>', methods=['GET'])
def get_public_order(order_id):
    """Check if order exists (for sync service)"""
    try:
        order = Order.query.filter_by(order_id=order_id).first()
        
        if not order:
            return jsonify({'error': 'Order not found'}), 404
        
        return jsonify({
            'success': True,
            'order_id': order.order_id,
            'order_status': order.order_status,
            'payment_status': order.payment_status
        })
        
    except Exception as e:
        print(f"❌ Error fetching order: {e}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/shop/order/<order_id>/cancel', methods=['POST'])
@jwt_required()
def cancel_order(order_id):
    """Cancel an order"""
    try:
        identity = get_jwt_identity()
        shop_id = int(identity) if isinstance(identity, str) else identity
        shop = Shop.query.get(shop_id)
        
        if not shop:
            return jsonify({'error': 'Shop not found'}), 404
        
        order = Order.query.filter_by(order_id=order_id, shop_id=shop.id).first()
        
        if not order:
            return jsonify({'error': 'Order not found'}), 404
        
        # Check if already completed
        if order.order_status == 'completed':
            return jsonify({
                'success': False, 
                'error': 'Cannot cancel completed order'
            }), 400
        
        # Check if already cancelled
        if order.order_status == 'cancelled':
            return jsonify({
                'success': False, 
                'error': 'Order already cancelled'
            }), 400
        
        # Cancel the order
        order.order_status = 'cancelled'
        order.completed_at = datetime.utcnow()  # Track when cancelled
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Order cancelled successfully',
            'order_id': order.order_id
        })
        
    except Exception as e:
        print(f"Cancel order error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
# ============ WHATSAPP BOT PROXY ============
@app.route('/api/whatsapp-proxy/api/qr/<session_id>', methods=['GET'])
def whatsapp_proxy_qr(session_id):
    if not validate_session_id(session_id):
        return jsonify({'success': False, 'error': 'Invalid session ID'}), 400
    try:
        target_url = f"{WHATSAPP_BOT_URL}/api/qr/{session_id}"
        
        response = requests.get(target_url, timeout=15)  # ✅ increased from 5 to 15
        return jsonify(response.json()), response.status_code
        
    except requests.exceptions.ConnectionError:
        return jsonify({
            'success': False,
            'error': 'WhatsApp bot not running',
            'message': 'Make sure WhatsApp bot is running on port 3000'
        }), 503
    except requests.exceptions.Timeout:  # ✅ ADD: separate timeout handler
        return jsonify({
            'success': False,
            'error': 'WhatsApp bot is slow to respond',
            'message': 'Bot is starting up, please retry in a moment'
        }), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/whatsapp-proxy/api/init-session/<session_id>', methods=['POST'])
def whatsapp_proxy_init(session_id):
    if not validate_session_id(session_id):
        return jsonify({'success': False, 'error': 'Invalid session ID'}), 400
    try:
        target_url = f"{WHATSAPP_BOT_URL}/api/init-session/{session_id}"
        
        response = requests.post(target_url, timeout=20)  # ✅ increased from 5 to 20
        return jsonify(response.json()), response.status_code
        
    except requests.exceptions.ConnectionError:
        return jsonify({
            'success': False,
            'error': 'WhatsApp bot not running'
        }), 503
    except requests.exceptions.Timeout:  # ✅ ADD
        return jsonify({
            'success': False,
            'error': 'Init timed out - bot may still be starting',
            'message': 'Please retry in a few seconds'
        }), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/whatsapp-proxy/api/logout/<session_id>', methods=['POST'])
@jwt_required()
def whatsapp_logout_proxy(session_id):
    """Proxy logout requests to Node.js WhatsApp service"""
    if not validate_session_id(session_id):
        return jsonify({'success': False, 'error': 'Invalid session ID'}), 400
    try:
        # Get the database ID from JWT
        identity = get_jwt_identity()
        db_shop_id = int(identity) if isinstance(identity, str) else identity
        
        # Get the actual shop to verify ownership
        shop = Shop.query.get(db_shop_id)
        if not shop:
            return jsonify({'success': False, 'error': 'Shop not found'}), 404
        
        # Verify session belongs to THIS shop using shop.shop_id
        if session_id != shop.shop_id:
            print(f'❌ Session mismatch: Expected {shop.shop_id}, got {session_id}')
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        print(f'✅ Session verified for shop: {shop.shop_name}')
        
        node_url = f'{WHATSAPP_BOT_URL}/api/logout/{session_id}'
        print(f'🔄 Proxying logout request to: {node_url}')
        
        response = requests.post(
            node_url,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        return jsonify(response.json()), response.status_code
        
    except requests.exceptions.RequestException as e:
        print(f'❌ Logout proxy error: {str(e)}')
        return jsonify({
            'success': False,
            'error': 'WhatsApp bot service unavailable'
        }), 503
    except Exception as e:
        print(f'❌ Logout proxy error: {str(e)}')
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    
@app.route('/api/public/shop-by-session/<session_id>', methods=['GET'])
def get_shop_by_session(session_id):
    """
    Public endpoint: Get shop info by WhatsApp session ID
    Used by WhatsApp bot to link incoming messages to shops
    """
    try:
        # Find shop by session_id (e.g., SHOP_D2B55310)
        shop = Shop.query.filter_by(shop_id=session_id, is_active=True).first()
        
        if not shop:
            return jsonify({
                'success': False,
                'error': 'Shop not found'
            }), 404
        
        print(f"✅ Found shop for session {session_id}: {shop.shop_name} (ID: {shop.id})")
        
        return jsonify({
            'success': True,
            'shop': {
                'id': shop.id,
                'shop_id': shop.shop_id,
                'shop_name': shop.shop_name,
                'whatsapp_number': shop.whatsapp_number,
                'is_active': shop.is_active
            }
        })
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    
@app.route('/api/shop/whatsapp-connection-status', methods=['GET'])
@jwt_required()
def get_whatsapp_connection_status():
    """Check if shop's WhatsApp is connected to bot"""
    try:
        identity = get_jwt_identity()
        shop_id = int(identity) if isinstance(identity, str) else identity
        
        shop = Shop.query.get(shop_id)
        if not shop:
            return jsonify({'success': False, 'error': 'Shop not found'}), 404
        
        # Check connection status with WhatsApp bot
        try:
            NODEJS_BOT_URL = 'http://localhost:3000'
            session_id = shop.shop_id  # e.g., SHOP_ABC123
            
            status_response = requests.get(
                f"{NODEJS_BOT_URL}/api/status/{session_id}",
                timeout=5
            )
            
            if status_response.ok:
                status_data = status_response.json()
                
                return jsonify({
                    'success': True,
                    'connected': status_data.get('connected', False),
                    'status': status_data.get('status', 'not_initialized'),
                    'phone_number': status_data.get('phoneNumber'),
                    'session_id': session_id
                })
            else:
                return jsonify({
                    'success': True,
                    'connected': False,
                    'status': 'not_initialized',
                    'session_id': session_id
                }), 200
                
        except requests.exceptions.ConnectionError:
            return jsonify({
                'success': False,
                'error': 'WhatsApp bot service not running'
            }), 503
            
    except Exception as e:
        print(f"Connection status error: {str(e)}")# keep the real error in your Railway logs
        return jsonify({'success': False, 'error': 'An unexpected error occurred'}), 500


@app.route('/api/shop/whatsapp-number/verify', methods=['POST'])
@jwt_required()
def verify_whatsapp_number():
    """
    Verify WhatsApp number after connection
    This updates the database after shop scans QR and connects
    """
    try:
        identity = get_jwt_identity()
        shop_id = int(identity) if isinstance(identity, str) else identity
        
        shop = Shop.query.get(shop_id)
        if not shop:
            return jsonify({'success': False, 'error': 'Shop not found'}), 404
        
        # Get the connected phone number from WhatsApp bot
        try:
            NODEJS_BOT_URL = 'http://localhost:3000'
            session_id = shop.shop_id
            
            status_response = requests.get(
                f"{NODEJS_BOT_URL}/api/status/{session_id}",
                timeout=5
            )
            
            if status_response.ok:
                status_data = status_response.json()
                
                if status_data.get('connected') and status_data.get('phoneNumber'):
                    phone_number = status_data.get('phoneNumber')
                    
                    # ✅ CRITICAL FIX: Handle duplicate phone numbers
                    # Clear WhatsApp number from OTHER shops using the same number
                    duplicate_shops = Shop.query.filter(
                        Shop.whatsapp_number == phone_number,
                        Shop.id != shop.id,
                        Shop.is_active == True
                    ).all()
                    
                    if duplicate_shops:
                        print(f"\n⚠️ Found {len(duplicate_shops)} shop(s) with same WhatsApp number!")
                        for dup_shop in duplicate_shops:
                            print(f"   - Clearing from: {dup_shop.shop_name} (ID: {dup_shop.id})")
                            dup_shop.whatsapp_number = None  # ✅ Clear the number
                        
                        db.session.commit()
                        print(f"✅ Cleared WhatsApp number from old shops\n")
                    
                    # ✅ Now set it for THIS shop
                    shop.whatsapp_number = phone_number
                    shop.phone = phone_number
                    db.session.commit()
                    
                    print(f"\n{'='*60}")
                    print(f"✅ WhatsApp Connected & Verified!")
                    print(f"{'='*60}")
                    print(f"Shop: {shop.shop_name}")
                    print(f"Number: {phone_number}")
                    print(f"Session: {session_id}")
                    print(f"{'='*60}")
                    print(f"📱 Orders sent to {phone_number} will appear in")
                    print(f"   {shop.shop_name}'s dashboard!")
                    print(f"{'='*60}\n")
                    
                    return jsonify({
                        'success': True,
                        'message': 'WhatsApp connected and verified!',
                        'phone_number': phone_number,
                        'shop': {
                            'id': shop.id,
                            'shop_id': shop.shop_id,
                            'shop_name': shop.shop_name,
                            'whatsapp_number': shop.whatsapp_number
                        }
                    }), 200
                else:
                    return jsonify({
                        'success': False,
                        'error': 'WhatsApp not connected yet'
                    }), 400
            else:
                return jsonify({
                    'success': False,
                    'error': 'Failed to get connection status'
                }), 500
                
        except requests.exceptions.ConnectionError:
            return jsonify({
                'success': False,
                'error': 'WhatsApp bot service not running'
            }), 503
        except Exception as e:
            print(f"Verify error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': 'Failed to verify connection'
            }), 500
            
    except Exception as e:
        print(f"Verify number error: {str(e)}")
        import traceback
        traceback.print_exc()
        db.session.rollback()
        print(f"Error: {str(e)}")   # keep the real error in your Railway logs
        return jsonify({'success': False, 'error': 'An unexpected error occurred'}), 500
    
@app.route('/api/public/shop-by-phone/<path:phone_number>', methods=['GET'])
def get_shop_by_phone(phone_number):
    """
    Get shop by WhatsApp phone number.
    Used when a customer sends a message to find which shop it belongs to.
    """
    try:
        # Strip WhatsApp suffixes like @s.whatsapp.net or @c.us
        clean_phone = phone_number.replace('@s.whatsapp.net', '').replace('@c.us', '').strip()

        # Keep digits only — removes any leftover special characters
        clean_phone = ''.join(filter(str.isdigit, clean_phone))

        if not clean_phone:
            return jsonify({'success': False, 'error': 'Invalid phone number'}), 400

        print(f"🔍 Searching for shop with phone: {clean_phone}")

        # Search both whatsapp_number and phone columns,
        # and both the cleaned version and original (handles format differences)
        shop = Shop.query.filter(
            Shop.is_active == True,  # only active shops
            (
                (Shop.whatsapp_number == clean_phone) |
                (Shop.whatsapp_number == phone_number) |
                (Shop.phone == clean_phone) |
                (Shop.phone == phone_number)
            )
        ).first()

        if not shop:
            # ✅ FIXED: only log the searched number, NOT all shops' data
            print(f"❌ No active shop found for phone: {clean_phone}")
            return jsonify({'success': False, 'error': 'Shop not found'}), 404

        print(f"✅ Found shop: {shop.shop_name} (ID: {shop.shop_id})")

        return jsonify({
            'success': True,
            'shop': {
                'id': shop.id,
                'shop_id': shop.shop_id,
                'shop_name': shop.shop_name,
                'whatsapp_number': shop.whatsapp_number,
                'is_active': shop.is_active
            }
        })

    except Exception as e:
        print(f"❌ Error in shop-by-phone: {e}")
        import traceback
        traceback.print_exc()
        print(f"Error: {str(e)}")   # keep the real error in your Railway logs
        return jsonify({'success': False, 'error': 'An unexpected error occurred'}), 500
    
@app.route('/api/shop/printer/config', methods=['GET', 'POST'])
@jwt_required()
def shop_printer_config():
    try:
        identity = get_jwt_identity()
        shop_id = int(identity) if isinstance(identity, str) else identity
        shop = Shop.query.get(shop_id)
        if not shop:
            return jsonify({'success': False, 'error': 'Shop not found'}), 404

        if request.method == 'POST':
            import json as json_lib
            config = request.json.get('printer_config')
            shop.printer_config = json_lib.dumps(config)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Printer config saved'})

        else:  # GET
            import json as json_lib
            config = json_lib.loads(shop.printer_config) if shop.printer_config else None
            return jsonify({'success': True, 'printer_config': config})

    except Exception as e:
        db.session.rollback()
        print(f"Error: {str(e)}")   # keep the real error in your Railway logs
        return jsonify({'success': False, 'error': 'An unexpected error occurred'}), 500
@app.route('/api/public/shop-printer-config/<shop_id>', methods=['GET'])
def get_shop_printer_config(shop_id):
    try:
        import json as json_lib
        shop = Shop.query.filter_by(shop_id=shop_id).first()
        if not shop:
            return jsonify({'success': False, 'error': 'Shop not found'}), 404

        # Primary: read from Printer table
        printer = Printer.query.filter_by(shop_id=shop.id).order_by(Printer.id.desc()).first()
        if printer and printer.ip_address:
            return jsonify({
                'success': True,
                'printer_config': {
                    'ip': printer.ip_address,
                    'port': printer.port or 9100,
                    'protocol': printer.protocol or 'socket',
                    'name': printer.printer_name
                }
            })

        # Fallback: read from shop.printer_config JSON blob
        if shop.printer_config:
            return jsonify({
                'success': True,
                'printer_config': json_lib.loads(shop.printer_config)
            })

        return jsonify({'success': False, 'error': 'No printer config'}), 404

    except Exception as e:
        print(f"Error: {str(e)}")   # keep the real error in your Railway logs
        return jsonify({'success': False, 'error': 'An unexpected error occurred'}), 500
    
@app.route('/api/shop/printer/register', methods=['POST'])
@jwt_required()
def register_printer():
    try:
        identity = get_jwt_identity()
        shop_id = int(identity) if isinstance(identity, str) else identity
        shop = Shop.query.get(shop_id)
        if not shop:
            return jsonify({'success': False, 'error': 'Shop not found'}), 404
        
        data = request.json
        printer = Printer(
            shop_id=shop.id,
            printer_name=data.get('printer_name', 'Default Printer'),
            printer_type=data.get('printer_type', 'network'),
            status=data.get('status', 'online'),
            ip_address=data.get('ip_address'),
            port=data.get('port', 9100),
            protocol=data.get('protocol', 'socket')
        )
        db.session.add(printer)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Printer registered'})
    except Exception as e:
        db.session.rollback()
        print(f"Error: {str(e)}")   # keep the real error in your Railway logs
        return jsonify({'success': False, 'error': 'An unexpected error occurred'}), 500

@app.route('/api/printer/probe', methods=['POST'])
@jwt_required()  # ← FIX: Was completely open before, now requires login
def probe_printer():

    try:
        import ipaddress
        import socket

        data = request.json
        ip = data.get('ip', '').strip()
        port_raw = data.get('port', 9100)

        # ── Validate IP is present ──
        if not ip:
            return jsonify({'reachable': False, 'error': 'IP address is required'}), 400

        # ── Validate port is a real number ──
        try:
            port = int(port_raw)
            if not (1 <= port <= 65535):
                raise ValueError
        except (ValueError, TypeError):
            return jsonify({'reachable': False, 'error': 'Invalid port number'}), 400

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'reachable': False, 'error': 'Invalid IP address format'}), 400

        # Block only truly dangerous ranges (localhost, link-local, multicast)
        if addr.is_loopback:
            return jsonify({'reachable': False, 'error': 'Loopback addresses not allowed'}), 400
        if addr.is_link_local:
            return jsonify({'reachable': False, 'error': 'Link-local addresses not allowed'}), 400
        if addr.is_multicast:
            return jsonify({'reachable': False, 'error': 'Multicast addresses not allowed'}), 400

        # ── Probe the printer ──
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        result = s.connect_ex((ip, port))
        s.close()

        reachable = (result == 0)
        print(f"🔍 Probe {ip}:{port} → {'reachable' if reachable else 'closed'}")

        return jsonify({'reachable': reachable})

    except Exception as e:
        print(f"❌ Probe error: {e}")
        return jsonify({'reachable': False, 'error': 'Probe failed'}), 500

@app.route('/api/printer/info', methods=['POST'])
@jwt_required()  
def printer_info():
    try:
        import ipaddress
        import requests as req

        data = request.json
        ip = data.get('ip', '').strip()

        # Validate IP
        if not ip:
            return jsonify({'success': False, 'model': None, 'error': 'IP required'}), 400
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'success': False, 'model': None, 'error': 'Invalid IP'}), 400

        # Block loopback and link-local (same as probe_printer)
        if addr.is_loopback or addr.is_link_local or addr.is_multicast:
            return jsonify({'success': False, 'model': None, 'error': 'Address not allowed'}), 400

        # Validate port
        try:
            port = int(data.get('port', 9100))
            if not (1 <= port <= 65535):
                raise ValueError
        except (ValueError, TypeError):
            return jsonify({'success': False, 'model': None, 'error': 'Invalid port'}), 400

        model = None
        try:
            r = req.get(f"http://{ip}/", timeout=3)
            match = re.search(r'<title>([^<]+)</title>', r.text, re.IGNORECASE)
            if match:
                model = match.group(1).strip()
        except Exception:
            pass

        return jsonify({'success': True, 'model': model})

    except Exception as e:
        return jsonify({'success': False, 'model': None})

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Print Shop Backend API Started!")
    print("="*60)
    print(f"🌐 API running on: http://localhost:5001")
    print(f"📊 Health check: http://localhost:5001/api/health")
    print("="*60 + "\n")
    
    app.run(
    host='0.0.0.0',
    port=5001,
    debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
)


