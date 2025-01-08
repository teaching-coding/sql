from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_cors import CORS
from datetime import datetime, timedelta
import random
import bcrypt
import csv

# Initialize the Flask application
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}) 


# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:root@localhost:5432/x'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'riteshmodel18@gmail.com'
app.config['MAIL_PASSWORD'] = 'qafr uxig evmr qtld'

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)

# User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    otp = db.Column(db.String(6), nullable=True)
    otp_expiration = db.Column(db.DateTime, nullable=True)
    is_verified = db.Column(db.Boolean, default=False)

# Create the database tables
with app.app_context():
    db.create_all()

# Helper function to generate OTP
def generate_otp():
    return str(random.randint(100000, 999999))

# Register API
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'message': 'Name, email, and password are required'}), 400

    # Check if the user already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email is already registered'}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Generate OTP for email verification
    otp = generate_otp()
    otp_expiration = datetime.utcnow() + timedelta(minutes=5)

    # Create a new user
    new_user = User(name=name, email=email, password=hashed_password, otp=otp, otp_expiration=otp_expiration)
    db.session.add(new_user)
    db.session.commit()

    # Send OTP via email
    msg = Message('Verify Your Email', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Your OTP is: {otp}\nIt will expire in 5 minutes.'
    try:
        mail.send(msg)
        return jsonify({'message': 'Registration successful'}), 200
    except Exception as e:
        return jsonify({'message': f'Failed to send OTP: {str(e)}'}), 500

# Verify OTP API
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({'message': 'Email and OTP are required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    if user.otp != otp:
        return jsonify({'message': 'Invalid OTP'}), 400

    if datetime.utcnow() > user.otp_expiration:
        return jsonify({'message': 'OTP expired'}), 400

    # Mark user as verified
    user.is_verified = True
    user.otp = None
    user.otp_expiration = None
    db.session.commit()

    return jsonify({'message': 'Email verified successfully'}), 200

# Login API
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    if not user.is_verified:
        return jsonify({'message': 'Email is not verified'}), 403

    if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({'message': 'Invalid password'}), 400

    return jsonify({'message': 'Login successful'}), 200

# Forgot Password - Request Reset
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Generate OTP for password reset
    otp = generate_otp()
    otp_expiration = datetime.utcnow() + timedelta(minutes=5)
    user.otp = otp
    user.otp_expiration = otp_expiration
    db.session.commit()

    # Send OTP via email
    msg = Message('Password Reset OTP', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Your password reset OTP is: {otp}\nIt will expire in 5 minutes.'
    try:
        mail.send(msg)
        return jsonify({'message': 'Password reset OTP sent to your email.'}), 200
    except Exception as e:
        return jsonify({'message': f'Failed to send OTP: {str(e)}'}), 500

# Reset Password API
@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('new_password')

    if not email or not otp or not new_password:
        return jsonify({'message': 'Email, OTP, and new password are required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    if user.otp != otp:
        return jsonify({'message': 'Invalid OTP'}), 400

    if datetime.utcnow() > user.otp_expiration:
        return jsonify({'message': 'OTP expired'}), 400

    # Update the password
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user.password = hashed_password
    user.otp = None
    user.otp_expiration = None
    db.session.commit()

    return jsonify({'message': 'Password reset successfully'}), 200

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)




