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
from gridfs import GridFS
from bson.objectid import ObjectId

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
load_dotenv(os.path.join(BASE_DIR, ".env"))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
app.config['MAX_CONTENT_LENGTH'] = 6 * 1024 * 1024

SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
app.config.update(SESSION_COOKIE_SAMESITE=SESSION_COOKIE_SAMESITE,
                  SESSION_COOKIE_HTTPONLY=True)

RAZORPAY_KEY = os.getenv("RAZORPAY_KEY")
RAZORPAY_SECRET = os.getenv("RAZORPAY_SECRET")
if razorpay and RAZORPAY_KEY and RAZORPAY_SECRET:
    try:
        razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY, RAZORPAY_SECRET))
    except Exception:
        razorpay_client = None
else:
    razorpay_client = None

MONGO_URL = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "dreamx")

client = MongoClient(MONGO_URL)
try:
    client.admin.command('ping')
    DB_CONNECTED = True
except Exception:
    DB_CONNECTED = False

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
    posters = list(posters_col.find().sort('created_at', -1))
    return render_template('landing.html', products=products, banners=banners, posters=posters)


@app.route('/product/<product_id>')
def product_page(product_id):
    try:
        p = products_col.find_one({"_id": ObjectId(product_id)})
    except Exception:
        p = None
    if not p:
        flash('Product not found', 'error')
        return redirect(url_for('landing'))
    return render_template('product_page.html', product=p)


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
    return render_template('checkout.html')


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


@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    payload = request.form or request.json or {}
    # minimal verification for demo: accept and write order
    orders_col.insert_one({'payload': payload, 'created_at': datetime.datetime.utcnow()})
    return jsonify({'ok': True})


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


# Admin: banners, social links, products
def require_admin_view():
    if session.get('role') != 'admin':
        flash('Admin required', 'error')
        return redirect(url_for('login'))


@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
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


@app.errorhandler(RequestEntityTooLarge)
def file_too_large(e):
    flash('File too large (max 6MB)', 'error')
    return redirect(request.referrer or url_for('admin_banners'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=True)





