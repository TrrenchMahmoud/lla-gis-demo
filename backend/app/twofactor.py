import base64
import io

import pyotp
import qrcode

ISSUER = "LLA Land Dashboard"


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_qr_png_b64(email: str, secret: str) -> str:
    """A base64 PNG of the QR code an authenticator app (Google Authenticator, Authy, etc.)
    scans to add this account - built entirely offline, no external service involved."""
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def verify_code(secret: str, code: str) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)
