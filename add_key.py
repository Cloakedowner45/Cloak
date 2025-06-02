from app import db, LicenseKey, app
from datetime import datetime, timedelta
import secrets

def generate_random_key(length=32):
    return secrets.token_hex(length // 2)  # 32 chars total

with app.app_context():
    new_key = generate_random_key()
    expires_at = datetime.utcnow() + timedelta(days=30)  # expires in 30 days

    license_key = LicenseKey(
        key=new_key,
        valid=True,
        expires_at=expires_at,
        ip_address=None,
        hardware_id=None
    )

    db.session.add(license_key)
    db.session.commit()

    # Confirm key was added
    check = LicenseKey.query.filter_by(key=new_key).first()
    if check:
        print(f"✅ Key generated and saved: {new_key}")
    else:
        print("❌ Key not saved properly.")
