import os
import datetime
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

# Load env variables
load_dotenv()

MONGO_URI = os.getenv("MONGODB_URI")
DB_NAME = os.getenv("MONGO_DB_NAME", "mens_ecommerce")

print(f"Connecting to {MONGO_URI}...")

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client[DB_NAME]
    
    # Test connection
    client.admin.command('ping')
    print("Connected to MongoDB successfully!")
    
    # Collections
    products_col = db["products"]
    users_col = db["users"]
    banners_col = db["banners"]

    # 1. Seed Admin User
    admin_email = "admin@claufe.com"
    if not users_col.find_one({"email": admin_email}):
        print("Creating admin user...")
        users_col.insert_one({
            "name": "Admin",
            "email": admin_email,
            "password_hash": generate_password_hash("admin123@#"),
            "role": "admin",
            "created_at": datetime.datetime.utcnow()
        })
    else:
        print("Admin user already exists.")

    # 2. Seed Products
    # Check if products exist
    if products_col.count_documents({}) == 0:
        print("Seeding products...")
        sample_products = [
            {
                "name": "Royal Gold Signet Ring",
                "price": 14999.0,
                "category": "Rings",
                "description": "Handcrafted 18k solid gold signet ring with a brushed finish. A timeless statement piece for the modern man.",
                "image_filename": None, # Will fallback to placeholder
                "created_at": datetime.datetime.utcnow()
            },
            {
                "name": "Sterling Silver Chain Bracelet",
                "price": 8500.0,
                "category": "Bracelets",
                "description": "Premium 925 sterling silver curb chain bracelet. Robust, stylish, and perfect for daily wear.",
                "image_filename": None,
                "created_at": datetime.datetime.utcnow()
            },
            {
                "name": "Midnight Black Chronograph",
                "price": 24500.0,
                "category": "Watches",
                "description": "Matte black stainless steel chronograph watch with a sapphire crystal face. Water-resistant up to 50m.",
                "image_filename": None,
                "created_at": datetime.datetime.utcnow()
            },
            {
                "name": "Cuban Link Chain (Gold)",
                "price": 45000.0,
                "category": "Chains",
                "description": "Heavy duty 10mm Cuban link chain in gold plating. An essential accessory for a bold look.",
                "image_filename": None,
                "created_at": datetime.datetime.utcnow()
            },
            {
                "name": "Onyx Stone Ring",
                "price": 12000.0,
                "category": "Rings",
                "description": "Bold rectangular black onyx stone set in a silver band. Represents strength and style.",
                "image_filename": None,
                "created_at": datetime.datetime.utcnow()
            },
            {
                "name": "Classic Leather Wallet",
                "price": 3500.0,
                "category": "Accessories",
                "description": "Genuine leather wallet with RFID protection. Slim profile with ample storage.",
                "image_filename": None,
                "created_at": datetime.datetime.utcnow()
            }
        ]
        products_col.insert_many(sample_products)
        print(f"Added {len(sample_products)} sample products.")
    else:
        print("Products collection is not empty. Skipping seed.")

    print("Database seeding completed.")

except Exception as e:
    print(f"Error connecting or seeding database: {e}")
    print("Please check your MONGODB_URI and password in .env")
