from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, Float
from backend.models.security_event import db
import uuid

class NetworkDevice(db.Model):
    __tablename__ = 'network_devices'

    id = Column(Integer, primary_key=True)
    device_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    
    # Device identification
    ip_address = Column(String(45), nullable=False, unique=True)
    mac_address = Column(String(17))
    hostname = Column(String(255))
    device_type = Column(String(50))  # router, switch, server, workstation, etc.
    
    # Device details
    os_type = Column(String(100))
    os_version = Column(String(100))
    manufacturer = Column(String(100))
    model = Column(String(100))
    
    # Network information
    open_ports = Column(Text)  # JSON string of open ports
    services = Column(Text)    # JSON string of running services
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    # Security status
    is_managed = Column(Boolean, default=False)
    is_authorized = Column(Boolean, default=True)
    risk_score = Column(Float, default=0.0)
    vulnerability_count = Column(Integer, default=0)
    
    # Monitoring
    is_online = Column(Boolean, default=True)
    response_time = Column(Float)  # in milliseconds
    uptime_percentage = Column(Float, default=100.0)
    
    # Metadata
    first_discovered = Column(DateTime, default=datetime.utcnow)
    last_scanned = Column(DateTime)
    notes = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'hostname': self.hostname,
            'device_type': self.device_type,
            'os_type': self.os_type,
            'os_version': self.os_version,
            'manufacturer': self.manufacturer,
            'model': self.model,
            'open_ports': self.open_ports,
            'services': self.services,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'is_managed': self.is_managed,
            'is_authorized': self.is_authorized,
            'risk_score': self.risk_score,
            'vulnerability_count': self.vulnerability_count,
            'is_online': self.is_online,
            'response_time': self.response_time,
            'uptime_percentage': self.uptime_percentage,
            'first_discovered': self.first_discovered.isoformat() if self.first_discovered else None,
            'last_scanned': self.last_scanned.isoformat() if self.last_scanned else None,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    @classmethod
    def get_online_devices(cls):
        return cls.query.filter_by(is_online=True).all()
    
    @classmethod
    def get_high_risk_devices(cls, threshold=7.0):
        return cls.query.filter(cls.risk_score >= threshold).all()
    
    @classmethod
    def get_unauthorized_devices(cls):
        return cls.query.filter_by(is_authorized=False).all()

    def __repr__(self):
        return f'<NetworkDevice {self.ip_address}: {self.hostname} ({self.device_type})>'