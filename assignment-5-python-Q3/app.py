import streamlit as st
import json
import os
import base64
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Security parameters
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds
PBKDF2_ITERATIONS = 480000
DATA_FILE = "secure_vault.json"

# Initialize session state
def init_session():
    if 'auth' not in st.session_state:
        st.session_state.auth = {
            'logged_in': False,
            'username': None,
            'attempts': 0,
            'lockout_until': 0
        }
    if 'vault' not in st.session_state:
        st.session_state.vault = load_vault()

# PBKDF2 Key derivation
def derive_key(passphrase, salt=None):
    salt = salt or os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    return key, salt

# Data persistence
def load_vault():
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {'users': {}, 'data': {}}

def save_vault():
    with open(DATA_FILE, 'w') as f:
        json.dump(st.session_state.vault, f, default=bytes_to_str)

# Data conversion
def bytes_to_str(obj):
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode('utf-8')
    raise TypeError

def str_to_bytes(obj):
    if isinstance(obj, str):
        return base64.b64decode(obj.encode('utf-8'))
    return obj

# Security functions
def handle_failed_attempt():
    st.session_state.auth['attempts'] += 1
    if st.session_state.auth['attempts'] >= MAX_ATTEMPTS:
        st.session_state.auth['lockout_until'] = time.time() + LOCKOUT_TIME
        st.error("Too many failed attempts. System locked for 5 minutes.")
        st.stop()

def check_lockout():
    if time.time() < st.session_state.auth['lockout_until']:
        remaining = int(st.session_state.auth['lockout_until'] - time.time())
        st.error(f"System locked. Try again in {remaining // 60}m {remaining % 60}s")
        st.stop()

# Main application
def user_registration():
    with st.form("Registration"):
        username = st.text_input("New Username")
        password = st.text_input("New Password", type='password')
        if st.form_submit_button("Register"):
            if username and password:
                user_key, salt = derive_key(password)
                st.session_state.vault['users'][username] = {
                    'key': bytes_to_str(user_key),
                    'salt': bytes_to_str(salt)
                }
                st.session_state.vault['data'][username] = []
                save_vault()
                st.success("Registration successful!")
            return True
    return False

def user_login():
    with st.form("Login"):
        username = st.text_input("Username")
        password = st.text_input("Password", type='password')
        if st.form_submit_button("Login"):
            user_data = st.session_state.vault['users'].get(username)
            if user_data:
                try:
                    derived_key, _ = derive_key(
                        password,
                        salt=str_to_bytes(user_data['salt'])
                    )
                    if hmac.compare_digest(derived_key, str_to_bytes(user_data['key'])):
                        st.session_state.auth.update({
                            'logged_in': True,
                            'username': username,
                            'attempts': 0
                        })
                        st.rerun()
                        return True
                except:
                    pass
            handle_failed_attempt()
    return False

def data_storage():
    st.header("Secure Data Storage")
    with st.form("Storage"):
        secret = st.text_area("Enter secret data")
        passkey = st.text_input("Encryption passkey", type='password')
        if st.form_submit_button("Encrypt & Store"):
            if secret and passkey:
                user_key = str_to_bytes(st.session_state.vault['users'][st.session_state.auth['username']]['key'])
                fernet = Fernet(user_key)
                
                # Double encryption: system key + user passkey
                encrypted = fernet.encrypt(passkey.encode())
                data_entry = {
                    'timestamp': time.time(),
                    'data': bytes_to_str(fernet.encrypt(secret.encode())),
                    'passkey_hash': bytes_to_str(encrypted)
                }
                
                st.session_state.vault['data'][st.session_state.auth['username']].append(data_entry)
                save_vault()
                st.success("Data stored securely!")

def data_retrieval():
    st.header("Data Retrieval")
    with st.form("Retrieval"):
        passkey = st.text_input("Enter passkey", type='password')
        if st.form_submit_button("Decrypt Data"):
            user_key = str_to_bytes(st.session_state.vault['users'][st.session_state.auth['username']]['key'])
            fernet = Fernet(user_key)
            
            decrypted_data = []
            for entry in st.session_state.vault['data'][st.session_state.auth['username']]:
                try:
                    stored_passkey = fernet.decrypt(str_to_bytes(entry['passkey_hash'])).decode()
                    if hmac.compare_digest(passkey, stored_passkey):
                        decrypted = fernet.decrypt(str_to_bytes(entry['data'])).decode()
                        decrypted_data.append({
                            'timestamp': entry['timestamp'],
                            'data': decrypted
                        })
                except:
                    continue
            
            if decrypted_data:
                st.success(f"Found {len(decrypted_data)} matching entries:")
                for idx, entry in enumerate(decrypted_data, 1):
                    with st.expander(f"Entry #{idx} - {time.ctime(entry['timestamp'])}"):
                        st.write(entry['data'])
            else:
                st.error("No matching entries found")
                handle_failed_attempt()

# Main app flow
init_session()
check_lockout()

if not st.session_state.auth['logged_in']:
    st.title("🔐 Secure Multi-User Vault")
    if not user_registration():
        if not user_login():
            st.stop()
else:
    st.title(f"Welcome {st.session_state.auth['username']}")
    menu = st.radio("Menu", ["Store Data", "Retrieve Data"], horizontal=True)
    
    if menu == "Store Data":
        data_storage()
    else:
        data_retrieval()
    
    if st.button("Logout"):
        st.session_state.auth.update({'logged_in': False, 'username': None})
        st.rerun()

st.markdown("---")
st.caption(f"Security Status: {MAX_ATTEMPTS - st.session_state.auth['attempts']} attempts remaining")
