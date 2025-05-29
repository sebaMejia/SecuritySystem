from flask import Blueprint, jsonify, current_app
from backend.models.security_event import SecurityEvent, SeverityLevel, EventType
from backend.models.network_device import NetworkDevice
from backend.models.vulnerability import Vulnerability
from datetime import datetime, timedelta
import json

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/stats', methods=['GET'])
def get_dashboard_stats():
    """Get comprehensive dashboard statistics"""
    try:
        # Security Events Stats
        total_events = SecurityEvent.query.count()
        open_events = SecurityEvent.query.filter_by(status='OPEN').count()
        
        # Recent activity (last 24 hours)
        recent_cutoff = datetime.utcnow() - timedelta(hours=24)
        recent_events = SecurityEvent.query.filter(SecurityEvent.timestamp >= recent_cutoff).count()
        
        # Events by severity
        critical_events = SecurityEvent.query.filter_by(severity=SeverityLevel.CRITICAL).count()
        high_events = SecurityEvent.query.filter_by(severity=SeverityLevel.HIGH).count()
        
        # Network Devices Stats
        total_devices = NetworkDevice.query.count()
        online_devices = NetworkDevice.query.filter_by(is_online=True).count()
        unauthorized_devices = NetworkDevice.query.filter_by(is_authorized=False).count()
        
        # Vulnerability Stats
        total_vulns = Vulnerability.query.count()
        critical_vulns = Vulnerability.query.filter_by(severity='CRITICAL').count()
        open_vulns = Vulnerability.query.filter_by(status='OPEN').count()
        
        # Risk calculation
        avg_risk_score = 0.0
        if total_devices > 0:
            risk_sum = sum([device.risk_score for device in NetworkDevice.query.all()])
            avg_risk_score = risk_sum / total_devices
        
        return jsonify({
            'success': True,
            'timestamp': datetime.utcnow().isoformat(),
            'security_events': {
                'total': total_events,
                'open': open_events,
                'recent_24h': recent_events,
                'critical': critical_events,
                'high': high_events
            },
            'network_devices': {
                'total': total_devices,
                'online': online_devices,
                'offline': total_devices - online_devices,
                'unauthorized': unauthorized_devices,
                'avg_risk_score': round(avg_risk_score, 2)
            },
            'vulnerabilities': {
                'total': total_vulns,
                'critical': critical_vulns,
                'open': open_vulns,
                'patched': total_vulns - open_vulns
            },
            'overall_health': {
                'status': 'healthy' if critical_events == 0 and unauthorized_devices == 0 else 'warning',
                'risk_level': 'high' if avg_risk_score > 7.0 else 'medium' if avg_risk_score > 4.0 else 'low'
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/recent-activity', methods=['GET'])
def get_recent_activity():
    """Get recent security activity for timeline"""
    try:
        # Get recent events (last 7 days)
        week_ago = datetime.utcnow() - timedelta(days=7)
        recent_events = SecurityEvent.query.filter(
            SecurityEvent.timestamp >= week_ago
        ).order_by(SecurityEvent.timestamp.desc()).limit(20).all()
        
        # Format for timeline
        activity = []
        for event in recent_events:
            activity.append({
                'id': event.id,
                'timestamp': event.timestamp.isoformat(),
                'type': 'security_event',
                'title': event.title,
                'severity': event.severity.value,
                'description': event.description[:100] + '...' if event.description and len(event.description) > 100 else event.description,
                'source_ip': event.source_ip
            })
        
        return jsonify({
            'success': True,
            'activity': activity,
            'count': len(activity)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/threat-summary', methods=['GET'])
def get_threat_summary():
    """Get current threat landscape summary"""
    try:
        # Top threats by frequency
        from sqlalchemy import func
        threat_types = SecurityEvent.query.with_entities(
            SecurityEvent.event_type,
            func.count(SecurityEvent.id).label('count')
        ).group_by(SecurityEvent.event_type).order_by(func.count(SecurityEvent.id).desc()).all()
        
        # Top source IPs
        top_sources = SecurityEvent.query.with_entities(
            SecurityEvent.source_ip,
            func.count(SecurityEvent.id).label('count')
        ).filter(SecurityEvent.source_ip.isnot(None)).group_by(
            SecurityEvent.source_ip
        ).order_by(func.count(SecurityEvent.id).desc()).limit(10).all()
        
        # High-risk devices
        high_risk_devices = NetworkDevice.query.filter(
            NetworkDevice.risk_score >= 7.0
        ).limit(10).all()
        
        return jsonify({
            'success': True,
            'threat_types': [
                {'type': tt[0].value, 'count': tt[1]} for tt in threat_types
            ],
            'top_sources': [
                {'ip': ts[0], 'count': ts[1]} for ts in top_sources
            ],
            'high_risk_devices': [
                {
                    'ip': device.ip_address,
                    'hostname': device.hostname,
                    'risk_score': device.risk_score,
                    'vuln_count': device.vulnerability_count
                } for device in high_risk_devices
            ]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/health', methods=['GET'])
def dashboard_health():
    """Dashboard-specific health check"""
    try:
        # Test all model connections
        event_count = SecurityEvent.query.count()
        device_count = NetworkDevice.query.count()
        vuln_count = Vulnerability.query.count()
        
        return jsonify({
            'success': True,
            'dashboard_status': 'healthy',
            'models': {
                'security_events': event_count,
                'network_devices': device_count,
                'vulnerabilities': vuln_count
            },
            'redis_status': 'connected' if current_app.redis else 'disconnected'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500