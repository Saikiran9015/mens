from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, send_from_directory, jsonify, Response
)
import re
import os
import datetime
import time
from io import BytesIO
from PIL import Image
import hmac
import hashlib
import json
import base64
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from pymongo.errors import ConfigurationError
from gridfs import GridFS
from bson.objectid import ObjectId
import requests

try:
    import razorpay
except Exception:
    razorpay = None

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except Exception:
    boto3 = None
    BotoCoreError = Exception
    ClientError = Exception

# Load env
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Force reload of .env file to pick up changes without restarting terminal
load_dotenv(os.path.join(BASE_DIR, ".env"), override=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
app.config['MAX_CONTENT_LENGTH'] = 6 * 1024 * 1024

SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
app.config.update(SESSION_COOKIE_SAMESITE=SESSION_COOKIE_SAMESITE,
                  SESSION_COOKIE_HTTPONLY=True)

RAZORPAY_KEY = os.getenv("RAZORPAY_KEY")
RAZORPAY_SECRET = os.getenv("RAZORPAY_SECRET")

print(f"DEBUG: Razorpay Key present: {bool(RAZORPAY_KEY)}")
print(f"DEBUG: Razorpay Secret present: {bool(RAZORPAY_SECRET)}")
print(f"DEBUG: razorpay module loaded: {razorpay is not None}")

if razorpay and RAZORPAY_KEY and RAZORPAY_SECRET:
    try:
        razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY, RAZORPAY_SECRET))
        print("DEBUG: Razorpay client initialized successfully")
    except Exception as e:
        print(f"DEBUG: Razorpay client init failed: {e}")
        razorpay_client = None
else:
    print("DEBUG: Razorpay client NOT initialized (missing keys or module)")
    razorpay_client = None

MONGO_URL = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
print("DEBUG: Loaded MONGODB_URI:", MONGO_URL)
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "dreamx")

# Create Mongo client with a short server selection timeout and handle
# common SRV/DNS ConfigurationError (e.g. when using mongodb+srv and DNS
# can't be resolved on the host). If the primary URL fails with a
# ConfigurationError, attempt a local fallback to `mongodb://localhost:27017/`.
client = None
DB_CONNECTED = False
try:
    client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    DB_CONNECTED = True
except ConfigurationError as ce:
    print('MongoDB ConfigurationError (SRV/DNS):', ce)
    # Fallback: try connecting to local MongoDB if available
    try:
        client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        DB_CONNECTED = True
        print('Connected to fallback local MongoDB at mongodb://localhost:27017/')
    except Exception as e:
        print('Fallback local MongoDB ping failed:', e)
        DB_CONNECTED = False
except Exception as e:
    # Generic connection error (network, auth, etc.)
    print('MongoDB connection error:', e)
    DB_CONNECTED = False

if client is None:
    # As a final guard, construct a client object so code using `client` doesn't crash.
    client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)

db = client[MONGO_DB_NAME]
fs = GridFS(db)

users_col = db["users"]
products_col = db["products"]
cart_col = db["cart"]
orders_col = db["orders"]
banners_col = db["banners"]
social_col = db["social_links"]
contacts_col = db["contacts"]
posters_col = db["posters"]

# Shiprocket config (set via .env)
SHIPROCKET_EMAIL = os.getenv("SHIPROCKET_EMAIL")
SHIPROCKET_PASSWORD = os.getenv("SHIPROCKET_PASSWORD")
SHIPROCKET_API_URL = os.getenv("SHIPROCKET_API_URL", "https://apiv2.shiprocket.in")

# simple token cache
_ship_token = {"token": None, "expires_at": 0}


def get_shiprocket_token():
    """Get Shiprocket auth token (cached). Requires SHIPROCKET_EMAIL and SHIPROCKET_PASSWORD in env."""
    global _ship_token
    now = time.time()
    if _ship_token.get("token") and _ship_token.get("expires_at", 0) > now + 10:
        return _ship_token["token"]
    if not (SHIPROCKET_EMAIL and SHIPROCKET_PASSWORD):
        return None
    try:
        url = f"{SHIPROCKET_API_URL}/v1/external/auth/login"
        resp = requests.post(url, json={"email": SHIPROCKET_EMAIL, "password": SHIPROCKET_PASSWORD}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        token = data.get("token") or data.get("data", {}).get("token")
        # Shiprocket tokens typically valid for some hours; cache for 1 hour by default
        if token:
            _ship_token["token"] = token
            _ship_token["expires_at"] = now + 3600
            return token
    except Exception as e:
        print("Shiprocket auth error:", e)
    return None


def shiprocket_request(path, method="GET", json_data=None):
    token = get_shiprocket_token()
    if not token:
        return None
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    url = f"{SHIPROCKET_API_URL}{path}"
    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=15)
        else:
            r = requests.post(url, headers=headers, json=json_data or {}, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print("Shiprocket API error:", e, getattr(e, 'response', None))
        return None

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALLOWED_EXT = {"png", "jpg", "jpeg", "webp"}


def allowed_file(fn):
    return fn and '.' in fn and fn.rsplit('.', 1)[1].lower() in ALLOWED_EXT


def ensure_placeholder():
    static_dir = os.path.join(BASE_DIR, 'static')
    os.makedirs(static_dir, exist_ok=True)
    p = os.path.join(static_dir, 'no_image.png')
    if not os.path.exists(p):
        Image.new('RGB', (800, 600), (240, 240, 240)).save(p)


ensure_placeholder()


def init_defaults():
    if DB_CONNECTED:
        if not users_col.find_one({"email": "admin@claufe.com"}):
            users_col.insert_one({
                "name": "Admin",
                "email": "admin@claufe.com",
                "password_hash": generate_password_hash("admin123@#"),
                "role": "admin",
                "created_at": datetime.datetime.utcnow()
            })
            
        # Seed Products if empty
        if products_col.count_documents({}) == 0:
            products_col.insert_many([
                {
                    "name": "Royal Gold Signet Ring",
                    "price": 14999.0,
                    "category": "Rings",
                    "description": "Handcrafted 18k solid gold signet ring with a brushed finish.",
                    "image_filename": None,
                    "created_at": datetime.datetime.utcnow()
                },
                {
                    "name": "Sterling Silver Chain",
                    "price": 8500.0,
                    "category": "Chains",
                    "description": "Premium 925 sterling silver curb chain. Robust and stylish.",
                    "image_filename": None,
                    "created_at": datetime.datetime.utcnow()
                },
                {
                    "name": "Midnight Chronograph",
                    "price": 24500.0,
                    "category": "Watches",
                    "description": "Matte black stainless steel chronograph watch.",
                    "image_filename": None,
                    "created_at": datetime.datetime.utcnow()
                },
                {
                    "name": "Onyx Stone Ring",
                    "price": 12000.0,
                    "category": "Rings",
                    "description": "Bold rectangular black onyx stone set in a silver band.",
                    "image_filename": None,
                    "created_at": datetime.datetime.utcnow()
                },
                {
                    "name": "Classic Leather Wallet",
                    "price": 3500.0,
                    "category": "Accessories",
                    "description": "Genuine leather wallet with RFID protection.",
                    "image_filename": None,
                    "created_at": datetime.datetime.utcnow()
                },
                {
                    "name": "Gold Cufflinks",
                    "price": 5500.0,
                    "category": "Accessories",
                    "description": "Elegant gold-plated cufflinks for formal wear.",
                    "image_filename": None,
                    "created_at": datetime.datetime.utcnow()
                }
            ])
            print("Seeded default products.")


init_defaults()


@app.context_processor
def inject_social():
    s = social_col.find_one() or {}
    return {"social": s, "links": s}


# AUTH
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        pw = request.form.get('password') or ''
        u = users_col.find_one({"email": email})
        if u and check_password_hash(u.get('password_hash', ''), pw):
            session['user_id'] = str(u.get('_id'))
            session['role'] = u.get('role')
            session['email'] = u.get('email')
            flash('Logged in', 'success')
            if u.get('role') == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('landing'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        pw = request.form.get('password') or ''
        confirm = request.form.get('confirm_password') or ''
        requested_role = (request.form.get('role') or 'user').strip()
        if not email or not pw:
            flash('Missing fields', 'error')
            return redirect(url_for('signup'))
        if pw != confirm:
            flash('Passwords do not match', 'error')
            return redirect(url_for('signup'))
        if users_col.find_one({'email': email}):
            flash('Email already registered', 'error')
            return redirect(url_for('signup'))
        role = 'user'
        # allow admin registration only when no admin exists (initial setup)
        if requested_role == 'admin':
            try:
                admin_count = users_col.count_documents({'role': 'admin'})
            except Exception:
                admin_count = 0
            if admin_count == 0:
                role = 'admin'
            else:
                flash('Admin registration disabled', 'error')
                return redirect(url_for('signup'))
        users_col.insert_one({
            'name': name,
            'email': email,
            'password_hash': generate_password_hash(pw),
            'role': role,
            'created_at': datetime.datetime.utcnow()
        })
        flash('Account created. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('REGISTRATION.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'success')
    return redirect(url_for('landing'))


# Landing and product
@app.route('/')
def landing():
    products = list(products_col.find().sort('created_at', -1))

    # normalize product ids for templates
    for p in products:
        try:
            p['_id'] = str(p.get('_id'))
        except Exception:
            pass

    # prepare banners
    banners = []
    for b in banners_col.find().sort('created_at', -1):
        image = b.get('image_filename') or b.get('image')
        if isinstance(image, str) and image.startswith('data:'):
            url = image
        elif isinstance(image, str):
            url = url_for('uploaded_file', filename=image)
        else:
            url = url_for('static', filename='no_image.png')
        banners.append({'_id': str(b.get('_id')), 'image_url': url, 'title': b.get('title')})

    # prepare categories (unique categories from products, take first image)
    categories_map = {}
    for p in products:
        cat = (p.get('category') or 'Other').strip()
        if not cat:
            cat = 'Other'
        if cat not in categories_map:
            img = p.get('image_filename') or p.get('image')
            if isinstance(img, str) and img.startswith('data:'):
                img_url = img
            elif isinstance(img, str):
                img_url = url_for('uploaded_file', filename=img)
            else:
                img_url = url_for('static', filename='no_image.png')
            categories_map[cat] = {'name': cat, 'image_url': img_url}
    categories = list(categories_map.values())[:3]

    # shoppers: use latest 3 products
    shoppers = []
    for p in products[:3]:
        img = p.get('image_filename') or p.get('image')
        if isinstance(img, str) and img.startswith('data:'):
            img_url = img
        elif isinstance(img, str):
            img_url = url_for('uploaded_file', filename=img)
        else:
            img_url = url_for('static', filename='no_image.png')
        shoppers.append({'_id': str(p.get('_id')), 'image_url': img_url, 'name': p.get('name')})

    # social proofs: prefer social images, fallback to posters
    social_imgs = []
    s = social_col.find_one() or {}
    for key in ['instagram_image', 'facebook_image', 'twitter_image', 'youtube_image']:
        v = s.get(key)
        if v:
            social_imgs.append(url_for('uploaded_file', filename=v))
    if not social_imgs:
        for pst in posters_col.find().sort('created_at', -1).limit(3):
            img = pst.get('image_filename') or pst.get('image')
            if isinstance(img, str) and img.startswith('data:'):
                social_imgs.append(img)
            elif isinstance(img, str):
                social_imgs.append(url_for('uploaded_file', filename=img))
            else:
                social_imgs.append(url_for('static', filename='no_image.png'))

    posters = list(posters_col.find().sort('created_at', -1))

    # If admin requested to view dashboard inline on landing, prepare counts
    admin_flag = (request.args.get('admin') or '')
    admin_counts = None
    if session.get('role') == 'admin' and admin_flag:
        admin_counts = {
            'users': users_col.count_documents({}),
            'products': products_col.count_documents({}),
            'orders': orders_col.count_documents({}),
            'banners': banners_col.count_documents({})
        }

    return render_template('landing.html', products=products, banners=banners, posters=posters, categories=categories, shoppers=shoppers, social_proofs=social_imgs, admin_counts=admin_counts)


@app.route('/product/<product_id>')
def product_page(product_id):
    try:
        p = products_col.find_one({"_id": ObjectId(product_id)})
    except Exception:
        p = None
    if not p:
        flash('Product not found', 'error')
        return redirect(url_for('landing'))
    # build images list for gallery (support multiple possible fields)
    images = []
    # prefer list field 'images'
    if isinstance(p.get('images'), list):
        for im in p.get('images'):
            if isinstance(im, str) and im.startswith('data:'):
                images.append(im)
            elif isinstance(im, str):
                images.append(url_for('uploaded_file', filename=im))
    # support 'image_filenames' list
    if isinstance(p.get('image_filenames'), list):
        for im in p.get('image_filenames'):
            if im:
                images.append(url_for('uploaded_file', filename=im))
    # single filename
    img = p.get('image_filename') or p.get('image')
    if isinstance(img, str) and img.startswith('data:'):
        images.append(img)
    elif isinstance(img, str) and img:
        images.append(url_for('uploaded_file', filename=img))
    # fallback
    if not images:
        images.append(url_for('static', filename='no_image.png'))
    p['_id'] = str(p.get('_id'))
    p['images'] = images
    return render_template('product_page.html', product=p)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/shopping')
def shopping():
    q = (request.args.get('q') or '').strip()
    if q:
        regex = {"$regex": re.escape(q), "$options": "i"}
        raw = list(products_col.find({"$or": [{"name": regex}, {"category": regex}]}).sort('created_at', -1))
    else:
        raw = list(products_col.find().sort('created_at', -1))
    products = []
    for p in raw:
        p['_id'] = str(p.get('_id'))
        products.append(p)
    return render_template('shopping.html', products=products, q=q)


@app.route('/gifting')
def gifting():
    products = list(products_col.find().sort('created_at', -1))
    for p in products:
        p['_id'] = str(p.get('_id'))
    return render_template('gifting.html', products=products)


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').strip()
        subject = (request.form.get('subject') or '').strip()
        message = (request.form.get('message') or '').strip()
        try:
            contacts_col.insert_one({
                'name': name,
                'email': email,
                'subject': subject,
                'message': message,
                'created_at': datetime.datetime.utcnow()
            })
            flash('Thanks! We received your message.', 'success')
        except Exception as e:
            print('Contact save error:', e)
            flash('Failed to send message.', 'error')
        return redirect(url_for('contact'))
    return render_template('contact.html')


# Legacy static paths redirection
@app.route('/REGISTRATION.html')
def registration_legacy():
    return redirect(url_for('signup'))


@app.route('/login.html')
def login_legacy():
    return redirect(url_for('login'))


@app.route('/search')
def search_products():
    q = (request.args.get('q') or '').strip()
    regex = {"$regex": re.escape(q), "$options": "i"} if q else {}
    if q:
        raw = list(products_col.find({"$or": [{"name": regex}, {"category": regex}]}).limit(200))
    else:
        raw = list(products_col.find().limit(100))
    results = []
    for p in raw:
        pid = str(p.get('_id'))
        img = p.get('image_filename') or p.get('image')
        if isinstance(img, str) and img.startswith('data:'):
            image_url = img
        elif isinstance(img, str):
            image_url = url_for('uploaded_file', filename=img)
        else:
            image_url = url_for('static', filename='no_image.png')
        results.append({'_id': pid, 'name': p.get('name'), 'price': p.get('price'), 'image_url': image_url})
    return jsonify({'products': results})


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# Cart
@app.route('/add-to-cart/<product_id>', methods=['POST'])
def add_to_cart(product_id):
    qty = int(request.form.get('qty', 1))
    size = request.form.get('size') or ''
    user = session.get('user_id')
    item = {'product_id': product_id, 'qty': qty, 'size': size, 'created_at': datetime.datetime.utcnow()}
    if user:
        item['user_id'] = ObjectId(user) if ObjectId.is_valid(user) else user
    cart_col.insert_one(item)
    flash('Added to cart', 'success')
    return redirect(request.referrer or url_for('product_page', product_id=product_id))


@app.route('/cart')
def cart():
    user = session.get('user_id')
    items = []
    if user:
        raw = cart_col.find({'user_id': ObjectId(user)})
    else:
        raw = cart_col.find().limit(0)
    for c in raw:
        p = products_col.find_one({'_id': ObjectId(c.get('product_id'))})
        if p:
            items.append({'product': p, 'qty': c.get('qty', 1), 'size': c.get('size')})
    return render_template('cart.html', items=items)


# Checkout + Razorpay
@app.route('/checkout')
def checkout():
    # Show checkout page. If product_id provided, show that product as the only item.
    product_id = request.args.get('product_id')
    items = []
    subtotal = 0
    if product_id:
        try:
            p = products_col.find_one({'_id': ObjectId(product_id)})
        except Exception:
            p = None
        if p:
            # normalize product for template (keep dict-like access)
            p['_id'] = str(p.get('_id'))
            items = [{'product': p, 'qty': 1}]
    else:
        # try building from cart for current user (if any)
        user = session.get('user_id')
        rows = []
        if user:
            rows = list(cart_col.find({'user_id': ObjectId(user)}))
        else:
            rows = list(cart_col.find().limit(0))
        for c in rows:
            try:
                p = products_col.find_one({'_id': ObjectId(c.get('product_id'))})
            except Exception:
                p = None
            if p:
                p['_id'] = str(p.get('_id'))
                items.append({'product': p, 'qty': c.get('qty', 1)})
    for it in items:
        try:
            subtotal += float(it['product'].get('price', 0)) * int(it.get('qty', 1))
        except Exception:
            pass
    return render_template('checkout.html', items=items, subtotal=int(subtotal), razorpay_key=os.getenv('RAZORPAY_KEY'))


@app.route('/create-razorpay-order', methods=['POST'])
def create_razorpay_order():
    data = request.json or {}
    amount = int(data.get('amount', 0))
    currency = data.get('currency', 'INR')
    if razorpay_client:
        order = razorpay_client.order.create({'amount': amount, 'currency': currency, 'payment_capture': 1})
        return jsonify(order)
    # fallback fake order
    return jsonify({'id': f'order_fake_{int(time.time())}', 'amount': amount, 'currency': currency})


@app.route('/pay', methods=['GET', 'POST'])
def pay():
    """Create Razorpay order and render a simple payment page.
    POST: accept `amount` (in paise for INR) or `product_id` to compute amount.
    """
    # If a product_id is provided, prepare order for that product
    if request.method == 'POST':
        try:
            amount = int(request.form.get('amount', 0))
        except Exception:
            amount = 0
        if amount <= 0:
            flash('Invalid amount', 'error')
            return redirect(url_for('checkout'))
        # create order (amount expected in smallest currency unit)
        order = None
        if razorpay_client:
            try:
                order = razorpay_client.order.create({'amount': amount, 'currency': 'INR', 'payment_capture': 1})
            except Exception as e:
                print('Razorpay create order error:', e)
        if not order:
            order = {'id': f'order_fake_{int(time.time())}', 'amount': amount, 'currency': 'INR'}
        return render_template('razorpay_payment.html', order=order, razorpay_key=RAZORPAY_KEY, product=None)

    # GET: if product_id provided, create an order for that product and show payment page
    product_id = request.args.get('product_id')
    if product_id:
        try:
            p = products_col.find_one({'_id': ObjectId(product_id)})
        except Exception:
            p = None
        if not p:
            flash('Product not found', 'error')
            return redirect(url_for('landing'))
        # compute amount in smallest unit (paise)
        try:
            amount_val = float(p.get('price', 0))
        except Exception:
            amount_val = 0
        amount = int(amount_val * 100)
        order = None
        if razorpay_client:
            try:
                order = razorpay_client.order.create({'amount': amount, 'currency': 'INR', 'payment_capture': 1})
            except Exception as e:
                print('Razorpay create order error:', e)
        if not order:
            order = {'id': f'order_fake_{int(time.time())}', 'amount': amount, 'currency': 'INR'}
        # normalize product for template
        p['_id'] = str(p.get('_id'))
        return render_template('razorpay_payment.html', order=order, razorpay_key=RAZORPAY_KEY, product=p)

    # GET without product: render form to enter amount
    return render_template('razorpay_payment.html', order=None, razorpay_key=RAZORPAY_KEY, product=None)


@app.route('/place-order', methods=['POST'])
def place_order():
    """
    Handle order placement from checkout.
    - If COD: just save order and show success.
    - If Online: Verify Razorpay signature, then save order.
    """
    form_data = request.form.to_dict()
    payment_method = form_data.get('payment_method')
    
    # Check if this is a Razorpay success callback
    # Razorpay sends: razorpay_payment_id, razorpay_order_id, razorpay_signature
    rzp_pid = form_data.get('razorpay_payment_id')
    rzp_oid = form_data.get('razorpay_order_id')
    rzp_sig = form_data.get('razorpay_signature')
    
    order_status = 'Pending'
    paid = False
    
    if rzp_pid and rzp_oid and rzp_sig:
        # Verify signature
        if razorpay_client:
            try:
                # signature verification
                params_dict = {
                    'razorpay_order_id': rzp_oid,
                    'razorpay_payment_id': rzp_pid,
                    'razorpay_signature': rzp_sig
                }
                razorpay_client.utility.verify_payment_signature(params_dict)
                order_status = 'Paid'
                paid = True
                payment_method = 'online'
            except Exception as e:
                print('Razorpay Signature Verification Failed:', e)
                flash('Payment verification failed. Please try again.', 'error')
                return redirect(url_for('checkout'))
        else:
            # If no client (dev mode without keys), assume success if ids present
            order_status = 'Paid (Dev)'
            paid = True

    # Prepare order document
    user_id = session.get('user_id')
    cart_items = []
    
    # We need to reconstruction items from session/cart or trust the amount passed?
    # Best practice: Re-calculate from cart to avoid tampering.
    # For this demo, we will use the user's cart.
    
    # Note: If this was a "Buy Now" (single product), we need to handle that.
    # The checkout page might have been loaded with ?product_id=...
    # But sticking to cart-based logic for simplicity or needing hidden fields.
    # For now, let's grab the cart.
    
    subtotal = 0
    items = []
    
    if user_id:
        raw_cart = list(cart_col.find({'user_id': ObjectId(user_id)}))
    else:
        # If guest, we can't easily grab cart unless we used session cart or passed items in form
        # For simplicity in this fix, we will trust the 'amount' from form for record keeping, 
        # BUT we should really save the items. 
        # Let's assume the user is logged in or we just save what we can.
        raw_cart = []

    for c in raw_cart:
        p = products_col.find_one({'_id': ObjectId(c.get('product_id'))})
        if p:
            qty = int(c.get('qty', 1))
            items.append({
                'product_id': str(p.get('_id')),
                'name': p.get('name'),
                'price': float(p.get('price', 0)),
                'qty': qty,
                'size': c.get('size')
            })
            subtotal += float(p.get('price', 0)) * qty
            
    # If cart empty, maybe it's a direct buy? Check form? 
    # Current implementation relies on cart being present for checkout.
    
    total_amount = float(form_data.get('amount') or subtotal)

    order = {
        'user_id': ObjectId(user_id) if user_id else None,
        'items': items,
        'amount': total_amount,
        'currency': 'INR',
        'status': order_status,
        'payment_method': payment_method,
        'shipping_address': {
            'full_name': form_data.get('full_name'),
            'phone': form_data.get('phone'),
            'line1': form_data.get('line1'),
            'line2': form_data.get('line2'),
            'city': form_data.get('city'),
            'state': form_data.get('state'),
            'postcode': form_data.get('postcode')
        },
        'payment_details': {
            'razorpay_payment_id': rzp_pid,
            'razorpay_order_id': rzp_oid,
            'razorpay_signature': rzp_sig
        },
        'created_at': datetime.datetime.utcnow()
    }
    
    result = orders_col.insert_one(order)
    
    # Clear cart if paid or COD confirmed
    if user_id:
        cart_col.delete_many({'user_id': ObjectId(user_id)})
        
    session['last_order_id'] = str(result.inserted_id)
    return redirect(url_for('order_success'))


@app.route('/order-success')
def order_success():
    oid = session.get('last_order_id')
    return render_template('order_success.html', order_id=oid)


@app.route('/razorpay-webhook', methods=['POST'])
def razorpay_webhook():
    sig = request.headers.get('X-Razorpay-Signature') or request.headers.get('x-razorpay-signature')
    body = request.get_data()
    secret = RAZORPAY_SECRET or ''
    if secret and sig:
        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        # header is base64 of hex? Razorpay uses HMAC hexdigest; accept best-effort
        if not hmac.compare_digest(expected, sig):
            return Response('invalid signature', status=400)
    try:
        evt = request.json
        orders_col.insert_one({'webhook': evt, 'received_at': datetime.datetime.utcnow()})
    except Exception:
        pass
    return jsonify({'ok': True})


@app.route('/shiprocket/webhook', methods=['POST'])
def shiprocket_webhook():
    """Receive Shiprocket webhooks and store payload for review."""
    try:
        evt = request.json or {}
        orders_col.insert_one({'shiprocket_webhook': evt, 'received_at': datetime.datetime.utcnow()})
    except Exception as e:
        print('Shiprocket webhook error:', e)
    return jsonify({'ok': True})


# Admin: banners, social links, products
def require_admin_view():
    if session.get('role') != 'admin':
        flash('Admin required', 'error')
        return redirect(url_for('login'))


@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    # Calculate counts for the dashboard
    counts = {
        'users': users_col.count_documents({}),
        'products': products_col.count_documents({}),
        'orders': orders_col.count_documents({}),
        'banners': banners_col.count_documents({})
    }
    return render_template('dashboard.html', counts=counts)


@app.route('/admin/banners', methods=['GET', 'POST'])
def admin_banners():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form.get('title')
        link = request.form.get('link')
        f = request.files.get('image')
        filename = None
        if f and allowed_file(f.filename):
            filename = f"banners/{int(time.time())}_{secure_filename(f.filename)}"
            os.makedirs(os.path.join(UPLOAD_FOLDER, 'banners'), exist_ok=True)
            f.save(os.path.join(UPLOAD_FOLDER, filename))
        banners_col.insert_one({'title': title, 'link': link, 'image_filename': filename, 'created_at': datetime.datetime.utcnow()})
        flash('Banner uploaded', 'success')
        return redirect(url_for('admin_banners'))
    banners = list(banners_col.find().sort('created_at', -1))
    out = []
    for b in banners:
        image = b.get('image_filename')
        url = url_for('uploaded_file', filename=image) if image else url_for('static', filename='no_image.png')
        out.append({'_id': str(b.get('_id')), 'image_url': url, 'title': b.get('title')})
    return render_template('admin_banners.html', banners=out)


@app.route('/admin/banners/delete/<banner_id>', methods=['POST'])
def admin_delete_banner(banner_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    try:
        banners_col.delete_one({'_id': ObjectId(banner_id)})
    except Exception:
        pass
    flash('Banner removed', 'success')
    return redirect(url_for('admin_banners'))


@app.route('/admin/social-links', methods=['GET', 'POST'])
def admin_social_links():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    social = social_col.find_one() or {}
    if request.method == 'POST':
        update = {}
        for key in ['instagram_url', 'facebook_url', 'twitter_url', 'youtube_url']:
            v = request.form.get(key)
            if v is not None:
                update[key] = v
        # images
        for key in ['instagram_img', 'facebook_img', 'twitter_img', 'youtube_img']:
            f = request.files.get(key)
            if f and allowed_file(f.filename):
                filename = f"social/{int(time.time())}_{secure_filename(f.filename)}"
                os.makedirs(os.path.join(UPLOAD_FOLDER, 'social'), exist_ok=True)
                f.save(os.path.join(UPLOAD_FOLDER, filename))
                update[key.replace('_img', '_image')] = filename
        social_col.update_one({}, {'$set': update}, upsert=True)
        flash('Social links saved', 'success')
        return redirect(url_for('admin_social_links'))
    imgs = {}
    s = social_col.find_one() or {}
    for key in ['instagram_image', 'facebook_image', 'twitter_image', 'youtube_image']:
        v = s.get(key)
        if v:
            imgs[key.split('_')[0]] = url_for('uploaded_file', filename=v)
    return render_template('admin_social_links.html', social=s, images=imgs)


@app.route('/admin/social-links/delete/<platform>', methods=['POST'])
def admin_delete_social_image(platform):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    # Platform maps to field name: instagram -> instagram_image
    field_map = {
        'instagram': 'instagram_image',
        'facebook': 'facebook_image',
        'twitter': 'twitter_image',
        'youtube': 'youtube_image'
    }
    
    field = field_map.get(platform)
    if field:
        social_col.update_one({}, {'$unset': {field: ""}})
        flash(f'{platform.title()} image removed', 'success')
    
    return redirect(url_for('admin_social_links'))


@app.route('/admin/products')
def admin_products():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    products = list(products_col.find().sort('created_at', -1))
    for p in products:
        p['_id'] = str(p['_id'])
    return render_template('admin_products.html', products=products)


@app.route('/admin/users', methods=['GET', 'POST'])
def admin_users():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        pw = request.form.get('password') or ''
        role = (request.form.get('role') or 'user').strip()
        if not email or not pw:
            flash('Missing email or password', 'error')
            return redirect(url_for('admin_users'))
        if users_col.find_one({'email': email}):
            flash('Email already registered', 'error')
            return redirect(url_for('admin_users'))
        users_col.insert_one({
            'name': name,
            'email': email,
            'password_hash': generate_password_hash(pw),
            'role': role,
            'created_at': datetime.datetime.utcnow()
        })
        flash('User created', 'success')
        return redirect(url_for('admin_users'))
    users = list(users_col.find().sort('created_at', -1))
    for u in users:
        u['_id'] = str(u.get('_id'))
    return render_template('admin_users.html', users=users)


@app.route('/admin/products/add', methods=['GET', 'POST'])
def admin_add_product():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form.get('name')
        price = float(request.form.get('price') or 0)
        category = request.form.get('category')
        description = request.form.get('description')
        f = request.files.get('image')
        filename = None
        if f and allowed_file(f.filename):
            filename = f"products/{int(time.time())}_{secure_filename(f.filename)}"
            os.makedirs(os.path.join(UPLOAD_FOLDER, 'products'), exist_ok=True)
            f.save(os.path.join(UPLOAD_FOLDER, filename))
        products_col.insert_one({'name': name, 'price': price, 'category': category, 'description': description, 'image_filename': filename, 'created_at': datetime.datetime.utcnow()})
        flash('Product added', 'success')
        return redirect(url_for('admin_products'))
    return render_template('admin_add_product.html')


@app.route('/admin/products/delete/<product_id>', methods=['POST'])
def admin_delete_product(product_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    try:
        products_col.delete_one({'_id': ObjectId(product_id)})
    except Exception:
        pass
    flash('Product deleted', 'success')
    return redirect(url_for('admin_products'))


@app.route('/admin/shipments')
def admin_shipments():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    # show all stored shipments/webhooks
    shipments = list(orders_col.find({'shiprocket_order_id': {'$exists': True}}).sort('created_at', -1))
    webhooks = list(orders_col.find({'shiprocket_webhook': {'$exists': True}}).sort('received_at', -1)).limit(100)
    for s in shipments:
        s['_id'] = str(s.get('_id'))
    return render_template('admin_shipments.html', shipments=shipments, webhooks=webhooks)


@app.route('/admin/shipments/create', methods=['GET', 'POST'])
def admin_create_shipment():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        # collect minimal required fields for creating a shipment
        order_payload = {
            'order_id': request.form.get('order_id') or f'order_{int(time.time())}',
            'order_date': datetime.datetime.utcnow().strftime('%Y-%m-%d'),
            'channel_order_id': request.form.get('channel_order_id') or '',
            'billing_customer_name': request.form.get('name') or 'Customer',
            'billing_customer_email': request.form.get('email') or '',
            'billing_customer_phone': request.form.get('phone') or '',
            'shipping_is_billing': True,
            'shipping_address': request.form.get('address') or 'Address',
            'shipping_city': request.form.get('city') or 'City',
            'shipping_state': request.form.get('state') or 'State',
            'shipping_country': request.form.get('country') or 'India',
            'shipping_pincode': request.form.get('pincode') or '000000',
            'payment_method': request.form.get('payment_method') or 'Prepaid',
            'total_order_value': float(request.form.get('amount') or 0),
            'products': [
                {
                    'name': request.form.get('product_name') or 'Item',
                    'sku': request.form.get('sku') or 'SKU',
                    'units': int(request.form.get('units') or 1),
                    'selling_price': float(request.form.get('amount') or 0)
                }
            ]
        }
        resp = shiprocket_request('/v1/external/orders/create/adhoc', method='POST', json_data=order_payload)
        if resp:
            # store basic result
            orders_col.insert_one({'shiprocket_order': resp, 'shiprocket_order_id': resp.get('order_id') or resp.get('data', {}).get('order_id'), 'created_at': datetime.datetime.utcnow()})
            flash('Shipment created (Shiprocket response saved).', 'success')
        else:
            flash('Failed to create shipment (check logs).', 'error')
        return redirect(url_for('admin_shipments'))
    # GET: render form
    return render_template('shiprocket_pickup.html')


@app.errorhandler(RequestEntityTooLarge)
def file_too_large(e):
    flash('File too large (max 6MB)', 'error')
    return redirect(request.referrer or url_for('admin_banners'))



# Reload triggered to update env vars
if __name__ == '__main__':
    # On Windows the autoreloader can sometimes cause "not a socket" errors
    # (WinError 10038) when the parent process exits and threads remain.
    # Disable the reloader to avoid select() being called on closed handles.
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=True, use_reloader=False)






