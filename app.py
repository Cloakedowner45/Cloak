from datetime import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///licenses.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
limiter = Limiter(app, key_func=get_remote_address)

class LicenseKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    valid = db.Column(db.Boolean, default=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(100), nullable=True)
    hardware_id = db.Column(db.String(100), nullable=True)

class LicenseUsage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.Integer, db.ForeignKey('license_key.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip = db.Column(db.String(100))
    hwid = db.Column(db.String(100))

@app.route('/api/check_key', methods=['POST'])
@limiter.limit("5 per minute")
def check_key():
    data = request.get_json()
    key = data.get('key')
    hwid = data.get('hwid')
    request_ip = request.remote_addr

    if not key:
        return jsonify({'valid': False, 'error': 'Missing key'}), 400

    license_key = LicenseKey.query.filter_by(key=key).first()
    if not license_key or not license_key.valid:
        return jsonify({'valid': False, 'error': 'Invalid key'}), 403

    if license_key.expires_at and license_key.expires_at < datetime.utcnow():
        return jsonify({'valid': False, 'error': 'Key expired'}), 403

    if license_key.ip_address and license_key.ip_address != request_ip:
        return jsonify({'valid': False, 'error': 'Key locked to another IP'}), 403

    if license_key.hardware_id and hwid and license_key.hardware_id != hwid:
        return jsonify({'valid': False, 'error': 'Key locked to another machine'}), 403

    # First-time use sets IP and HWID
    if not license_key.ip_address:
        license_key.ip_address = request_ip
    if hwid and not license_key.hardware_id:
        license_key.hardware_id = hwid
    db.session.commit()

    # Log the usage
    usage = LicenseUsage(key_id=license_key.id, ip=request_ip, hwid=hwid)
    db.session.add(usage)
    db.session.commit()

    return jsonify({'valid': True})

@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    app.run()
