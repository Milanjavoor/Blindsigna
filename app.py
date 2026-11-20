from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.asymmetric import rsa

from config import BASE_DIR, APP_NAME, APP_VERSION, load_public_key
from token_service import (
    initialize_service,
    issue_blind_signature,
    redeem_token,
    get_service_statistics
)

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Educational RSA blind-signature anonymous token prototype"
)


class BlindSignRequest(BaseModel):
    blinded_message_hex: str = Field(min_length=1, max_length=1024)


class RedeemRequest(BaseModel):
    message_hex: str = Field(min_length=1, max_length=4096)
    signature_hex: str = Field(min_length=1, max_length=1024)


@app.on_event("startup")
def startup_event():
    initialize_service()


@app.get("/api/health")
def health_check():
    return {
        "status": "running",
        "application": APP_NAME,
        "version": APP_VERSION
    }


@app.get("/api/public-key")
def get_issuer_public_key():
    public_key = load_public_key()
    numbers = public_key.public_numbers()
    return {
        "n_hex": format(numbers.n, "x"),
        "e_hex": format(numbers.e, "x"),
        "key_size": public_key.key_size,
        "signature_bytes": (public_key.key_size + 7) // 8
    }


@app.post("/api/issuance/blind-sign")
def blind_sign_endpoint(request: BlindSignRequest):
    try:
        blinded_message = bytes.fromhex(request.blinded_message_hex)
        if not blinded_message:
            raise ValueError("Empty blinded message.")
        signature = issue_blind_signature(blinded_message)
        return {"success": True, "blind_signature_hex": signature.hex()}
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception:
        raise HTTPException(status_code=500, detail="Blind signing failed.")


@app.post("/api/tokens/redeem")
def redeem_endpoint(request: RedeemRequest):
    try:
        message = bytes.fromhex(request.message_hex)
        signature = bytes.fromhex(request.signature_hex)
        if not message or not signature:
            raise ValueError("Message and signature are required.")

        result = redeem_token(message, signature)
        if not result["success"]:
            raise HTTPException(status_code=400, detail=result["message"])
        return result
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception:
        raise HTTPException(status_code=500, detail="Token redemption failed.")


@app.get("/api/metrics")
def metrics_endpoint():
    return get_service_statistics()


# Serve the three frontend files from the project root without exposing Python files.
@app.get("/", include_in_schema=False)
def home():
    return FileResponse(BASE_DIR / "index.html")


@app.get("/style.css", include_in_schema=False)
def stylesheet():
    return FileResponse(BASE_DIR / "style.css", media_type="text/css")


@app.get("/script.js", include_in_schema=False)
def javascript():
    return FileResponse(BASE_DIR / "script.js", media_type="application/javascript")
