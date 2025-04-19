import subprocess
import threading
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict
import hashlib
import time

app = FastAPI()

# In-memory storage for encrypted data
stored_data: Dict[str, Dict[str, str]] = {}

class StoreDataRequest(BaseModel):
    encrypted_text: str
    passkey_hash: str

class RetrieveDataRequest(BaseModel):
    encrypted_text: str
    passkey: str

def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

@app.get("/")
def read_root():
    return {"message": "Secure Data App Backend is running."}

@app.post("/store")
def store_data(request: StoreDataRequest):
    if request.encrypted_text in stored_data:
        raise HTTPException(status_code=400, detail="Data already exists.")
    stored_data[request.encrypted_text] = {
        "encrypted_text": request.encrypted_text,
        "passkey_hash": request.passkey_hash
    }
    return {"message": "Data stored successfully."}

@app.post("/retrieve")
def retrieve_data(request: RetrieveDataRequest):
    data = stored_data.get(request.encrypted_text)
    if not data:
        raise HTTPException(status_code=404, detail="Data not found.")
    if data["passkey_hash"] != hash_passkey(request.passkey):
        raise HTTPException(status_code=401, detail="Invalid passkey.")
    return {"message": "Passkey verified. Data can be decrypted on client side."}

def run_backend():
    uvicorn.run(app, host="0.0.0.0", port=8000)

def run_frontend():
    # Run the Streamlit app as a subprocess
    subprocess.run(["streamlit", "run", "streamlit_app/app.py"])

if __name__ == "__main__":
    # Start backend in a separate thread
    backend_thread = threading.Thread(target=run_backend, daemon=True)
    backend_thread.start()

    # Give backend some time to start
    time.sleep(3)

    # Run frontend (this will block)
    run_frontend()
