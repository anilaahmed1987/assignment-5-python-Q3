import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os
from datetime import datetime, timedelta

# Initialize session state for failed attempts and lockout
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'locked_until' not in st.session_state:
    st.session_state.locked_until = None

# Generate or load encryption key
def get_encryption_key():
    if os.path.exists('encryption_key.key'):
        with open('encryption_key.key', 'rb') as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open('encryption_key.key', 'wb') as key_file:
            key_file.write(key)
        return key

# Initialize encryption
KEY = get_encryption_key()
cipher = Fernet(KEY)

# Load or initialize stored data
def load_stored_data():
    if os.path.exists('stored_data.json'):
        with open('stored_data.json', 'r') as file:
            return json.load(file)
    return {}

def save_stored_data(data):
    with open('stored_data.json', 'w') as file:
        json.dump(data, file)

stored_data = load_stored_data()

# Function to hash passkey using PBKDF2
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(32)
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000).hex(), salt

# Function to encrypt data
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    if st.session_state.locked_until and datetime.now() < st.session_state.locked_until:
        st.error(f"🔒 System locked until {st.session_state.locked_until.strftime('%H:%M:%S')}")
        return None

    hashed_passkey, salt = hash_passkey(passkey)
    
    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    
    if st.session_state.failed_attempts >= 3:
        st.session_state.locked_until = datetime.now() + timedelta(minutes=5)
        st.error("🔒 Too many failed attempts! System locked for 5 minutes.")
    
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.write("### Features:")
    st.write("- 🔐 Secure data encryption using Fernet")
    st.write("- 🔑 PBKDF2 password hashing")
    st.write("- ⏱️ 5-minute lockout after 3 failed attempts")
    st.write("- 💾 Persistent data storage")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("⚠️ Passkeys do not match!")
            else:
                hashed_passkey, salt = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data, passkey)
                stored_data[encrypted_text] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey,
                    "salt": salt.hex()
                }
                save_stored_data(stored_data)
                st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            if st.session_state.locked_until and datetime.now() < st.session_state.locked_until:
                st.error(f"🔒 System locked until {st.session_state.locked_until.strftime('%H:%M:%S')}")
            else:
                decrypted_text = decrypt_data(encrypted_text, passkey)
                if decrypted_text:
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted_text)
                else:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # In production, use proper authentication
            st.session_state.failed_attempts = 0
            st.session_state.locked_until = None
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!") 