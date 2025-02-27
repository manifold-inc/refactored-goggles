import json
import base64
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = FastAPI()

PUBLIC_KEY_PATH = "./keys/public_key.pem"

def load_public_key():
    try:
        with open(PUBLIC_KEY_PATH, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        return public_key
    except Exception as e:
        raise Exception(f"Error loading public key: {e}")

def verify_signature(msg: dict, signature: str, public_key):
    try:
        msg_bytes = json.dumps(msg, separators=(',', ':')).encode("utf-8")

        signature_bytes = base64.b64decode(signature)

        public_key.verify(
            signature_bytes,
            msg_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        return True
    except Exception as e:
        raise Exception(f"Signature verification failed: {e}")

class GPUInfo(BaseModel):
    id: str
    gpu_type: str

class Message(BaseModel):
    no_of_gpus: int
    gpu_info: list[GPUInfo]

class SignedData(BaseModel):
    msg: Message
    signature: str

@app.post("/validate")
def validate_signature(data: SignedData):
    public_key = load_public_key()

    try:
        if verify_signature(data.msg.dict(), data.signature, public_key):
            return {"status": "success", "message": "Signature verified!"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
