from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "tokens.db"
KEY_DIR = DATA_DIR / "keys"
PRIVATE_KEY_PATH = KEY_DIR / "issuer_private.pem"
PUBLIC_KEY_PATH = KEY_DIR / "issuer_public.pem"

APP_NAME = "BlindToken Anonymous Token System"
APP_VERSION = "1.0.0"


def load_or_create_keys():
    """Load the persistent issuer key pair, or create it once."""
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        private_key = serialization.load_pem_private_key(
            PRIVATE_KEY_PATH.read_bytes(), password=None
        )
        return private_key, private_key.public_key()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    PRIVATE_KEY_PATH.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )
    PUBLIC_KEY_PATH.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    try:
        PRIVATE_KEY_PATH.chmod(0o600)
        PUBLIC_KEY_PATH.chmod(0o644)
    except OSError:
        pass

    return private_key, public_key


def load_private_key():
    return load_or_create_keys()[0]


def load_public_key():
    return load_or_create_keys()[1]
