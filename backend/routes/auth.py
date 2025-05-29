from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
import hashlib

auth_bp = Blueprint('auth', __name__)

# Simple in-memory user store for Phase 1 (replace with proper DB in production)
USERS = {
    'admin': {
        'password_hash': hashlib.sha256('admin123'.encode()).hexdigest(),
        'role': 'admin',
        'name': 'Security Administrator'
    },
    'analyst': {
        'password_hash': hashlib.sha256('analyst123'.encode()).hexdigest(),
        'role': 'analyst',
        'name': 'Security Analyst'
    }
}

@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate user and return JWT token"""
    try:
        data = request.get_json()
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Username and password required'}), 400
        
        username = data['username']
        password = data['password']
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Check credentials
        if username not in USERS or USERS[username]['password_hash'] != password_hash:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Create JWT token
        user_info = USERS[username]
        additional_claims = {
            'role': user_info['role'],
            'name': user_info['name']
        }
        
        access_token = create_access_token(
            identity=username,
            additional_claims=additional_claims,
            expires_delta=timedelta(hours=8)
        )
        
        return jsonify({
            'success': True,
            'access_token': access_token,
            'user': {
                'username': username,
                'name': user_info['name'],
                'role': user_info['role']
            },
            'expires_in': '8 hours'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get current user profile"""
    try:
        current_user = get_jwt_identity()
        if current_user not in USERS:
            return jsonify({'error': 'User not found'}), 404
        
        user_info = USERS[current_user]
        return jsonify({
            'success': True,
            'user': {
                'username': current_user,
                'name': user_info['name'],
                'role': user_info['role']
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/validate', methods=['GET'])
@jwt_required()
def validate_token():
    """Validate current JWT token"""
    try:
        current_user = get_jwt_identity()
        return jsonify({
            'success': True,
            'valid': True,
            'username': current_user
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500