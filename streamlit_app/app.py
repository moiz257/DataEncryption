
import streamlit as st
import hashlib
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

# UI Customization
st.set_page_config(page_title="🔐 Secure Data App", layout="centered")
st.markdown("""
<style>
    .css-1d391kg {background-color: #1e1e2f;}
    .stButton>button {
        background-color: #6C63FF;
        color: white;
        font-weight: bold;
        border-radius: 8px;
        padding: 10px 24px;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Secure Data Encryption System")

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Derive Fernet key from passkey using PBKDF2HMAC
def derive_key(passkey: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key

# Encrypt function
def encrypt_data(text, passkey):
    salt = os.urandom(16)
    key = derive_key(passkey, salt)
    cipher = Fernet(key)
    encrypted = cipher.encrypt(text.encode())
    # Store salt + encrypted data (both base64 encoded)
    return base64.urlsafe_b64encode(salt + encrypted).decode()

# Decrypt function
def decrypt_data(token, passkey):
    try:
        data = base64.urlsafe_b64decode(token.encode())
        salt = data[:16]
        encrypted = data[16:]
        key = derive_key(passkey, salt)
        cipher = Fernet(key)
        decrypted = cipher.decrypt(encrypted)
        return decrypted.decode()
    except Exception:
        return None

# Backend API URLs
BACKEND_URL = "http://127.0.0.1:8000"

# Navigation
menu = ["🏠 Home", "📂 Store Data", "🔍 Retrieve Data", "🔑 Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "🏠 Home":
    st.subheader("Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "📂 Store Data":
    st.subheader("Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            # Call backend API to store data
            response = requests.post(f"{BACKEND_URL}/store", json={
                "encrypted_text": encrypted_text,
                "passkey_hash": hashed_passkey
            })
            if response.status_code == 200:
                st.success("✅ Data stored securely!")
                st.code(encrypted_text, language="text")
            else:
                st.error(f"⚠️ Error storing data: {response.json().get('detail', 'Unknown error')}")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "🔍 Retrieve Data":
    st.subheader("Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            # Call backend API to verify passkey
            response = requests.post(f"{BACKEND_URL}/retrieve", json={
                "encrypted_text": encrypted_text,
                "passkey": passkey
            })
            if response.status_code == 200:
                decrypted_text = decrypt_data(encrypted_text, passkey)
                if decrypted_text:
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted_text, language="text")
                    st.session_state.failed_attempts = 0
                else:
                    st.error("❌ Decryption failed!")
            else:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ {response.json().get('detail', 'Incorrect passkey!')} Attempts left: {attempts_left}")
                if attempts_left <= 0:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page...")
                    st.session_state.failed_attempts = 3
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "🔑 Login":
    st.subheader("Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! You can now try again.")
        else:
            st.error("❌ Incorrect master password!")
