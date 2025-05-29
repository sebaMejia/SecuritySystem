from flask import Blueprint, request, jsonify, current_app
from backend.models.security_event import db, SecurityEvent, EventType, SeverityLevel
from datetime import datetime
import json

events_bp = Blueprint('events', __name__)

@events_bp.route('/', methods=['GET'])
def get_events():
    """Get security events with optional filtering"""
    try:
        # Get query parameters
        limit = request.args.get('limit', 50, type=int)
        severity = request.args.get('severity')
        event_type = request.args.get('type')
        status = request.args.get('status')
        
        # Build query
        query = SecurityEvent.query
        
        # Apply filters
        if severity:
            try:
                severity_enum = SeverityLevel(severity.upper())
                query = query.filter(SecurityEvent.severity == severity_enum)
            except ValueError:
                return jsonify({'error': f'Invalid severity level: {severity}'}), 400
        
        if event_type:
            try:
                type_enum = EventType(event_type.upper())
                query = query.filter(SecurityEvent.event_type == type_enum)
            except ValueError:
                return jsonify({'error': f'Invalid event type: {event_type}'}), 400
        
        if status:
            query = query.filter(SecurityEvent.status == status.upper())
        
        # Execute query
        events = query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
        
        return jsonify({
            'success': True,
            'count': len(events),
            'events': [event.to_dict() for event in events]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@events_bp.route('/', methods=['POST'])
def create_event():
    """Create a new security event"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields
        required_fields = ['event_type', 'severity', 'title']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Convert enum fields
        try:
            event_type = EventType(data['event_type'].upper())
            severity = SeverityLevel(data['severity'].upper())
        except ValueError as e:
            return jsonify({'error': f'Invalid enum value: {str(e)}'}), 400
        
        # Create new event
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            title=data['title'],
            description=data.get('description'),
            source_ip=data.get('source_ip'),
            destination_ip=data.get('destination_ip'),
            source_port=data.get('source_port'),
            destination_port=data.get('destination_port'),
            protocol=data.get('protocol'),
            risk_score=data.get('risk_score', 0.0),
            confidence_score=data.get('confidence_score', 0.0),
            raw_data=json.dumps(data.get('raw_data', {}))
        )
        
        db.session.add(event)
        db.session.commit()
        
        # Cache in Redis if available
        if current_app.redis:
            try:
                current_app.redis.lpush('recent_events', json.dumps(event.to_dict()))
                current_app.redis.ltrim('recent_events', 0, 99)  # Keep last 100 events
            except Exception as e:
                print(f"Redis caching failed: {e}")
        
        return jsonify({
            'success': True,
            'message': 'Security event created successfully',
            'event': event.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@events_bp.route('/<int:event_id>', methods=['GET'])
def get_event(event_id):
    """Get a specific security event by ID"""
    try:
        event = SecurityEvent.query.get_or_404(event_id)
        return jsonify({
            'success': True,
            'event': event.to_dict()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@events_bp.route('/<int:event_id>', methods=['PUT'])
def update_event(event_id):
    """Update a security event (e.g., change status, add resolution notes)"""
    try:
        event = SecurityEvent.query.get_or_404(event_id)
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update allowed fields
        updatable_fields = ['status', 'assigned_to', 'resolution_notes']
        for field in updatable_fields:
            if field in data:
                setattr(event, field, data[field])
        
        # If resolving the event, set resolved_at timestamp
        if data.get('status') == 'RESOLVED' and not event.resolved_at:
            event.resolved_at = datetime.utcnow()
        
        event.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Security event updated successfully',
            'event': event.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@events_bp.route('/stats', methods=['GET'])
def get_event_stats():
    """Get statistics about security events"""
    try:
        # Count by severity
        severity_counts = {}
        for severity in SeverityLevel:
            count = SecurityEvent.query.filter_by(severity=severity).count()
            severity_counts[severity.value] = count
        
        # Count by event type
        type_counts = {}
        for event_type in EventType:
            count = SecurityEvent.query.filter_by(event_type=event_type).count()
            type_counts[event_type.value] = count
        
        # Count by status
        status_counts = {}
        statuses = ['OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE']
        for status in statuses:
            count = SecurityEvent.query.filter_by(status=status).count()
            status_counts[status] = count
        
        # Recent activity (last 24 hours)
        from datetime import timedelta
        recent_cutoff = datetime.utcnow() - timedelta(hours=24)
        recent_count = SecurityEvent.query.filter(SecurityEvent.timestamp >= recent_cutoff).count()
        
        return jsonify({
            'success': True,
            'total_events': SecurityEvent.query.count(),
            'recent_24h': recent_count,
            'by_severity': severity_counts,
            'by_type': type_counts,
            'by_status': status_counts
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500