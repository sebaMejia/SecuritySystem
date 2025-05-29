from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Enum, Float
from flask_sqlalchemy import SQLAlchemy
import enum 
import uuid

db = SQLAlchemy()

class SeverityLevel(enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class EventType(enum.Enum):
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE = "BRUTE_FORCE"
    MALWARE_DETECTED = "MALWARE_DETECTED"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    NETWORK_ANOMALY = "NETWORK_ANOMALY"
    VULNERABILITY_FOUND = "VULNERABILITY_FOUND"
    SYSTEM_ALERT = "SYSTEM_ALERT"

class SecurityEvent(db.Model):
    __tablename__ = 'security_events'

    id = Column(Integer, primary_key = True)
    event_id = Column(String(36), unique = True, nullable = False, default = lambda: str(uuid.uuid4()))

    timestamp = Column(DateTime, nullable = False, default = datetime.utcnow)
    event_type = Column(Enum(EventType), nullable = False)
    severity = Column(Enum(SeverityLevel), nullable = False)
    title = Column(String(200), nullable = False)
    description = Column(Text)

    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(10))

    risk_score = Column(Float, default = 0.0)
    confidence_score = Column(Float, default = 0.0)

    status = Column(String(20), default = 'OPEN')
    assigned_to = Column(String(100))
    resolution_notes = Column(Text)
    resolved_at = Column(DateTime)

    raw_data = Column(Text)

    created_at = Column(DateTime, default = datetime.utcnow)
    updated_at = Column(DateTime, default = datetime.utcnow, onupdate = datetime.utcnow)

    def to_dict(self):
        return{
            'id': self.id,
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'event_type': self.event_type.value if self.event_type else None,
            'severity': self.severity.value if self.severity else None,
            'title': self.title,
            'description': self.description,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'risk_score': self.risk_score,
            'confidence_score': self.confidence_score,
            'status': self.status,
            'assigned_to': self.assigned_to,
            'resolution_notes': self.resolution_notes,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

@classmethod
def get_recent_events(cls, limit = 50):
    return cls.query.order_by(cls.timestamp.desc()).limit(limit).all()

@classmethod
def get_events_by_severity(cls, severity_level):
    return cls.query.filter_by(severity = severity_level).order_by(cls.timestamp.desc()).all()

def __repr__(self):
    return f'<SecurityEvent {self.event_id}: {self.title} ({self.severity.value})>'