
# 🔐 Secure Data Encryption System (Streamlit + Uvicorn)

This project is a secure in-memory data encryption and retrieval system built using Streamlit, designed to run inside a FastAPI/uvicorn-based project structure.

## 📦 Features
- Encrypt & decrypt text using passkeys (with hashing)
- Secure data entry with Fernet encryption
- In-memory only (no database required)
- Reauthorization after 3 failed attempts
- Sleek Streamlit UI
- FastAPI backend placeholder (for UVicorn structure)

## 🚀 Run the Streamlit App
```bash
cd streamlit_app
streamlit run app.py
```

## 🖥️ Run the Backend (Optional)
```bash
uvicorn backend_uvicorn.main:app --reload
```
