import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'your_DB_URL'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SECURITY_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-production'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-change-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours = 8)

    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'

    SCAN_INTERVAL_MINUTES = int(os.environ.get('SCAN_INTERVAL_MINUTES', 30))
    MAX_SCAN_THREADS = int(os.environ.get('MAX_SCAN_THREADS', 10))
    
    DEFAULT_NETWORK_RANGE = os.environ.get('DEFAULT_NETWORK_RANGE', '192.168.1.0/24')

    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}