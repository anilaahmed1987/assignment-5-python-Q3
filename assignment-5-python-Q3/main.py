import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
import base64

# -------------------------------------------
# Utility Functions
# -------------------------------------------

DATA_FILE = "data_store.json"
USERS_FILE = "users.json"

def load_json(file, default={}):
    if os.path.exists(file):
        with open(file, "r") as f:
            return json.load(f)
    return default

def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=2)

def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def encrypt_data(text, key):
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, key):
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_text.encode()).decode()

# -------------------------------------------
# Initialization
# -------------------------------------------

if "key" not in st.session_state:
    st.session_state.key = Fernet.generate_key()

if "user" not in st.session_state:
    st.session_state.user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

users = load_json(USERS_FILE)
data_store = load_json(DATA_FILE)

# -------------------------------------------
# UI Layout
# -------------------------------------------

st.set_page_config(page_title="Secure Data App", page_icon="🔐", layout="centered")
st.title("🔐 Secure Data Storage System")

menu = ["🏠 Home", "🔑 Login", "📝 Register", "📤 Store Data", "📥 Retrieve Data", "📂 Upload", "⬇️ Download", "🚪 Logout"]
choice = st.sidebar.selectbox("Menu", menu)

# -------------------------------------------
# Login/Register Logic
# -------------------------------------------

if choice == "📝 Register":
    st.subheader("👤 Register")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")
    if st.button("Register"):
        if new_user in users:
            st.warning("Username already exists.")
        else:
            users[new_user] = hash_text(new_pass)
            save_json(USERS_FILE, users)
            st.success("✅ User registered successfully!")

elif choice == "🔑 Login":
    st.subheader("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username in users and users[username] == hash_text(password):
            st.session_state.user = username
            st.success(f"✅ Welcome {username}!")
        else:
            st.error("❌ Invalid credentials")

elif choice == "🚪 Logout":
    st.session_state.user = None
    st.success("✅ Logged out successfully!")

# -------------------------------------------
# Store Data
# -------------------------------------------

elif choice == "📤 Store Data":
    if st.session_state.user:
        st.subheader("📦 Store New Data")
        text = st.text_area("Enter your secret text:")
        passkey = st.text_input("Enter a passkey", type="password")
        if st.button("Encrypt & Save"):
            if text and passkey:
                hashed = hash_text(passkey)
                encrypted = encrypt_data(text, st.session_state.key)
                data_store.setdefault(st.session_state.user, []).append({
                    "encrypted_text": encrypted,
                    "passkey": hashed
                })
                save_json(DATA_FILE, data_store)
                st.success("✅ Data stored securely!")
                st.code(encrypted)
            else:
                st.warning("Please fill all fields.")
    else:
        st.warning("🔒 Please log in first.")

# -------------------------------------------
# Retrieve Data
# -------------------------------------------

elif choice == "📥 Retrieve Data":
    if st.session_state.user:
        st.subheader("🔓 Retrieve Your Data")
        encrypted_text = st.text_area("Paste encrypted text:")
        passkey = st.text_input("Enter your passkey", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                for item in data_store.get(st.session_state.user, []):
                    if item["encrypted_text"] == encrypted_text and item["passkey"] == hash_text(passkey):
                        try:
                            decrypted = decrypt_data(encrypted_text, st.session_state.key)
                            st.success("✅ Decrypted Text:")
                            st.text_area("Result:", decrypted, height=150)
                            break
                        except:
                            st.error("⚠️ Decryption error.")
                else:
                    st.session_state.failed_attempts += 1
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"Incorrect passkey. {remaining} attempts left.")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🚫 Too many attempts. Please login again.")
                        st.session_state.user = None
            else:
                st.warning("Fill all fields.")
    else:
        st.warning("🔒 Please log in first.")

# -------------------------------------------
# Upload Encrypted Data
# -------------------------------------------

elif choice == "📂 Upload":
    if st.session_state.user:
        st.subheader("📂 Upload Encrypted File")
        uploaded_file = st.file_uploader("Upload a `.txt` encrypted file", type=["txt"])
        if uploaded_file:
            content = uploaded_file.read().decode()
            st.text_area("Encrypted Content", value=content, height=150)
    else:
        st.warning("🔒 Please log in first.")

# -------------------------------------------
# Download Encrypted/Decrypted File
# -------------------------------------------

elif choice == "⬇️ Download":
    if st.session_state.user:
        st.subheader("⬇️ Download Encrypted or Decrypted File")
        file_content = st.text_area("Enter text to download (Encrypted or Decrypted):", height=150)
        filename = st.text_input("Filename", value="output.txt")

        if st.button("Download"):
            if file_content:
                b64 = base64.b64encode(file_content.encode()).decode()
                href = f'<a href="data:file/txt;base64,{b64}" download="{filename}">📥 Click here to download {filename}</a>'
                st.markdown(href, unsafe_allow_html=True)
            else:
                st.warning("Enter something to download.")
    else:
        st.warning("🔒 Please log in first.")

# -------------------------------------------
# Home Page
# -------------------------------------------

else:
    st.subheader("📚 Welcome")
    st.markdown("""
    This is a **Secure Data Encryption App** built with:
    - 🔐 Fernet Encryption (symmetric)
    - 🧠 SHA-256 hashed passwords
    - 📂 Persistent storage via JSON
    - 📤 File upload/download
    - 🧑 Multi-user authentication
    """)
