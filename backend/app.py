from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from backend.config import config
from sqlalchemy import text
import redis
import os

# Import models and database
from backend.models.security_event import db, SecurityEvent
from backend.models.network_device import NetworkDevice
from backend.models.vulnerability import Vulnerability

def create_app(config_name=None):
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Load configuration
    config_name = config_name or os.environ.get('FLASK_CONFIG', 'default')
    app.config.from_object(config[config_name])
    
    # Initialize extensions with app
    db.init_app(app)
    jwt = JWTManager(app)
    CORS(app)
    
    # Initialize Redis connection
    try:
        app.redis = redis.from_url(app.config['REDIS_URL'])
        app.redis.ping()
        print("Redis connected successfully")
    except Exception as e:
        print(f"Redis connection failed: {e}")
        print("   (Redis features will be disabled)")
        app.redis = None
    
    # Register API blueprints
    from backend.routes.events import events_bp
    from backend.routes.dashboard import dashboard_bp
    from backend.routes.auth import auth_bp
    
    app.register_blueprint(events_bp, url_prefix='/api/events')
    app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
    app.register_blueprint(auth_bp, url_prefix='/api/auth')

    # Health check endpoint
    @app.route('/health')
    def health_check():
        db_status = 'connected'
        try:
            # Test database connection
            db.session.execute(text('SELECT 1'))
        except Exception as e:
            db_status = f'error: {str(e)}'
        
        return jsonify({
            'status': 'healthy',
            'service': 'Security Platform API',
            'version': '1.0.0',
            'database': db_status,
            'redis': 'connected' if app.redis else 'disconnected',
            'endpoints': [
                '/health',
                '/api/events',
                '/api/dashboard/stats'
            ]
        })
    
    # Root endpoint
    @app.route('/')
    def root():
        return jsonify({
            'message': 'Enterprise Security Management Platform API',
            'version': '1.0.0',
            'status': 'running',
            'documentation': '/health'
        })
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Endpoint not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error'}), 500
    
    # Create database tables and seed data
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully")
            
            # Check if we need to seed some sample data
            if SecurityEvent.query.count() == 0:
                seed_sample_data()
                print("Sample security events created")
                
        except Exception as e:
            print(f"Database setup failed: {e}")
    
    return app

def seed_sample_data():
    """Create some sample security events for testing"""
    from backend.models.security_event import SecurityEvent, EventType, SeverityLevel
    from datetime import datetime, timedelta
    
    sample_events = [
        {
            'event_type': EventType.PORT_SCAN,
            'severity': SeverityLevel.MEDIUM,
            'title': 'Port Scan Detected',
            'description': 'Multiple port connection attempts from external IP',
            'source_ip': '192.168.1.100',
            'destination_ip': '192.168.1.1',
            'source_port': None,
            'destination_port': 22,
            'protocol': 'TCP',
            'risk_score': 6.5,
            'confidence_score': 0.85
        },
        {
            'event_type': EventType.BRUTE_FORCE,
            'severity': SeverityLevel.HIGH,
            'title': 'SSH Brute Force Attack',
            'description': 'Multiple failed SSH login attempts detected',
            'source_ip': '203.0.113.42',
            'destination_ip': '192.168.1.10',
            'source_port': 45123,
            'destination_port': 22,
            'protocol': 'TCP',
            'risk_score': 8.2,
            'confidence_score': 0.92
        },
        {
            'event_type': EventType.VULNERABILITY_FOUND,
            'severity': SeverityLevel.CRITICAL,
            'title': 'Critical Vulnerability Detected',
            'description': 'CVE-2023-12345: Remote code execution vulnerability found in web server',
            'source_ip': '192.168.1.50',
            'destination_ip': None,
            'source_port': 80,
            'destination_port': None,
            'protocol': 'HTTP',
            'risk_score': 9.8,
            'confidence_score': 0.98
        }
    ]
    
    for event_data in sample_events:
        event = SecurityEvent(**event_data)
        db.session.add(event)
    
    db.session.commit()

# For development server
if __name__ == '__main__':
    app = create_app()
    print("\n" + "="*50)
    print("SECURITY PLATFORM API STARTING")
    print("="*50)
    print("Health Check: http://localhost:5000/health")
    print("API Endpoints: http://localhost:5000/api/")
    print("Redis Status: Connected" if app.redis else "Redis Status: Disconnected")
    print("="*50 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)