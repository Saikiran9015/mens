#!/usr/bin/env python3
import os
import sys
import getpass
import datetime
from pymongo import MongoClient
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BASE_DIR, '.env'))
except Exception:
    pass

MONGO_URL = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
MONGO_DB_NAME = os.getenv('MONGO_DB_NAME', 'dreamx')

client = MongoClient(MONGO_URL)
db = client[MONGO_DB_NAME]
users_col = db['users']

def upsert_admin(email, password):
    pwh = generate_password_hash(password)
    now = datetime.datetime.utcnow()
    res = users_col.update_one(
        {'email': email},
        {'$set': {'name': 'Admin', 'email': email, 'password_hash': pwh, 'role': 'admin', 'created_at': now}},
        upsert=True
    )
    print('Admin user created/updated:', email)

if __name__ == '__main__':
    # allow non-interactive creation via environment variables
    env_email = os.getenv('ADMIN_EMAIL')
    env_pw = os.getenv('ADMIN_PASSWORD')
    if env_email and env_pw:
        upsert_admin(env_email, env_pw)
        print('Admin created/updated (from env):', env_email)
        sys.exit(0)

    email = input('Admin email [admin@claufe.com]: ').strip() or 'admin@claufe.com'
    pw = getpass.getpass('Admin password (will be hidden): ').strip()
    if not pw:
        print('Password required')
        sys.exit(1)
    upsert_admin(email, pw)
    print('Done')
