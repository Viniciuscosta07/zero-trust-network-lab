#!/usr/bin/env python3
"""
Zero Trust SDP Controller

The SDP Controller serves as the orchestration layer for the zero trust network.
It manages policies, authentication, and authorization for all network access requests.
"""

import os
import logging
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/sdp_controller.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'zero-trust-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=8)

# Initialize extensions
jwt = JWTManager(app)
api = Api(app)
CORS(app)

class DatabaseManager:
    """Manages SQLite database operations for the SDP Controller"""
    
    def __init__(self, db_path='sdp_controller.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # Devices table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    device_name TEXT NOT NULL,
                    device_type TEXT,
                    mac_address TEXT,
                    certificate_fingerprint TEXT,
                    compliance_status TEXT DEFAULT 'unknown',
                    last_seen TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Access policies table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS access_policies (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    source_zone TEXT,
                    destination_zone TEXT,
                    protocol TEXT,
                    port_range TEXT,
                    action TEXT DEFAULT 'deny',
                    conditions TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # Active sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS active_sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    device_id TEXT,
                    gateway_id TEXT,
                    session_token TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (device_id) REFERENCES devices (id)
                )
            ''')
            
            # Security events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    user_id TEXT,
                    device_id TEXT,
                    source_ip TEXT,
                    description TEXT,
                    severity TEXT DEFAULT 'info',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (device_id) REFERENCES devices (id)
                )
            ''')
            
            conn.commit()
            
            # Create default admin user if not exists
            cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
            if not cursor.fetchone():
                admin_id = str(uuid.uuid4())
                password_hash = hashlib.sha256('zero-trust-admin'.encode()).hexdigest()
                cursor.execute('''
                    INSERT INTO users (id, username, password_hash, role)
                    VALUES (?, ?, ?, ?)
                ''', (admin_id, 'admin', password_hash, 'admin'))
                conn.commit()
                logger.info("Created default admin user")

db_manager = DatabaseManager()

class AuthenticationResource(Resource):
    """Handles user authentication and token generation"""
    
    def post(self):
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            device_info = data.get('device_info', {})
            
            if not username or not password:
                return {'error': 'Username and password required'}, 400
            
            # Verify credentials
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            with sqlite3.connect(db_manager.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, role, is_active FROM users 
                    WHERE username = ? AND password_hash = ?
                ''', (username, password_hash))
                
                user = cursor.fetchone()
                if not user or not user[2]:  # User not found or inactive
                    self._log_security_event('authentication_failed', None, None, 
                                           request.remote_addr, f'Failed login attempt for {username}')
                    return {'error': 'Invalid credentials'}, 401
                
                user_id, role, is_active = user
                
                # Update last login
                cursor.execute('''
                    UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
                ''', (user_id,))
                
                # Register or update device
                device_id = self._register_device(user_id, device_info)
                
                # Create access token
                additional_claims = {
                    'role': role,
                    'device_id': device_id,
                    'user_id': user_id
                }
                access_token = create_access_token(
                    identity=username,
                    additional_claims=additional_claims
                )
                
                # Log successful authentication
                self._log_security_event('authentication_success', user_id, device_id,
                                       request.remote_addr, f'Successful login for {username}')
                
                conn.commit()
                
                return {
                    'access_token': access_token,
                    'user_id': user_id,
                    'device_id': device_id,
                    'role': role,
                    'expires_in': 28800  # 8 hours
                }, 200
                
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return {'error': 'Authentication failed'}, 500
    
    def _register_device(self, user_id, device_info):
        """Register or update device information"""
        device_id = device_info.get('device_id')
        if not device_id:
            device_id = str(uuid.uuid4())
        
        with sqlite3.connect(db_manager.db_path) as conn:
            cursor = conn.cursor()
            
            # Check if device exists
            cursor.execute('SELECT id FROM devices WHERE id = ?', (device_id,))
            if cursor.fetchone():
                # Update existing device
                cursor.execute('''
                    UPDATE devices SET 
                        last_seen = CURRENT_TIMESTAMP,
                        device_name = ?,
                        device_type = ?,
                        mac_address = ?
                    WHERE id = ?
                ''', (
                    device_info.get('name', 'Unknown'),
                    device_info.get('type', 'Unknown'),
                    device_info.get('mac_address'),
                    device_id
                ))
            else:
                # Create new device
                cursor.execute('''
                    INSERT INTO devices (id, user_id, device_name, device_type, mac_address, last_seen)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    device_id,
                    user_id,
                    device_info.get('name', 'Unknown'),
                    device_info.get('type', 'Unknown'),
                    device_info.get('mac_address')
                ))
            
            conn.commit()
        
        return device_id
    
    def _log_security_event(self, event_type, user_id, device_id, source_ip, description):
        """Log security events"""
        with sqlite3.connect(db_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO security_events (id, event_type, user_id, device_id, source_ip, description)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (str(uuid.uuid4()), event_type, user_id, device_id, source_ip, description))
            conn.commit()

class AccessPolicyResource(Resource):
    """Manages access control policies"""
    
    @jwt_required()
    def get(self, policy_id=None):
        """Retrieve access policies"""
        try:
            with sqlite3.connect(db_manager.db_path) as conn:
                cursor = conn.cursor()
                
                if policy_id:
                    cursor.execute('''
                        SELECT * FROM access_policies WHERE id = ? AND is_active = 1
                    ''', (policy_id,))
                    policy = cursor.fetchone()
                    if not policy:
                        return {'error': 'Policy not found'}, 404
                    
                    return self._format_policy(policy), 200
                else:
                    cursor.execute('''
                        SELECT * FROM access_policies WHERE is_active = 1
                        ORDER BY created_at DESC
                    ''')
                    policies = cursor.fetchall()
                    
                    return {
                        'policies': [self._format_policy(p) for p in policies]
                    }, 200
                    
        except Exception as e:
            logger.error(f"Error retrieving policies: {str(e)}")
            return {'error': 'Failed to retrieve policies'}, 500
    
    @jwt_required()
    def post(self):
        """Create new access policy"""
        try:
            data = request.get_json()
            required_fields = ['name', 'source_zone', 'destination_zone', 'action']
            
            for field in required_fields:
                if field not in data:
                    return {'error': f'Missing required field: {field}'}, 400
            
            policy_id = str(uuid.uuid4())
            
            with sqlite3.connect(db_manager.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO access_policies 
                    (id, name, source_zone, destination_zone, protocol, port_range, action, conditions)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    policy_id,
                    data['name'],
                    data['source_zone'],
                    data['destination_zone'],
                    data.get('protocol', 'any'),
                    data.get('port_range', 'any'),
                    data['action'],
                    json.dumps(data.get('conditions', {}))
                ))
                conn.commit()
            
            logger.info(f"Created access policy: {data['name']}")
            return {'policy_id': policy_id, 'message': 'Policy created successfully'}, 201
            
        except Exception as e:
            logger.error(f"Error creating policy: {str(e)}")
            return {'error': 'Failed to create policy'}, 500
    
    def _format_policy(self, policy_row):
        """Format policy database row for API response"""
        return {
            'id': policy_row[0],
            'name': policy_row[1],
            'source_zone': policy_row[2],
            'destination_zone': policy_row[3],
            'protocol': policy_row[4],
            'port_range': policy_row[5],
            'action': policy_row[6],
            'conditions': json.loads(policy_row[7] or '{}'),
            'created_at': policy_row[8],
            'is_active': policy_row[9]
        }

class AccessRequestResource(Resource):
    """Handles network access requests and authorization"""
    
    @jwt_required()
    def post(self):
        """Process access request and return authorization decision"""
        try:
            data = request.get_json()
            user_id = get_jwt_identity()
            
            required_fields = ['source_zone', 'destination_zone', 'protocol', 'destination_port']
            for field in required_fields:
                if field not in data:
                    return {'error': f'Missing required field: {field}'}, 400
            
            # Evaluate access policies
            decision = self._evaluate_access_request(data, user_id)
            
            # Log access request
            self._log_access_request(user_id, data, decision)
            
            return decision, 200
            
        except Exception as e:
            logger.error(f"Error processing access request: {str(e)}")
            return {'error': 'Failed to process access request'}, 500
    
    def _evaluate_access_request(self, request_data, user_id):
        """Evaluate access request against policies"""
        with sqlite3.connect(db_manager.db_path) as conn:
            cursor = conn.cursor()
            
            # Get applicable policies
            cursor.execute('''
                SELECT * FROM access_policies 
                WHERE is_active = 1 
                AND (source_zone = ? OR source_zone = 'any')
                AND (destination_zone = ? OR destination_zone = 'any')
                ORDER BY created_at DESC
            ''', (request_data['source_zone'], request_data['destination_zone']))
            
            policies = cursor.fetchall()
            
            for policy in policies:
                if self._policy_matches_request(policy, request_data):
                    action = policy[6]  # action column
                    
                    if action == 'allow':
                        return {
                            'decision': 'allow',
                            'policy_id': policy[0],
                            'policy_name': policy[1],
                            'session_duration': 3600,  # 1 hour default
                            'tunnel_config': self._generate_tunnel_config()
                        }
                    else:
                        return {
                            'decision': 'deny',
                            'policy_id': policy[0],
                            'policy_name': policy[1],
                            'reason': 'Access denied by policy'
                        }
            
            # Default deny
            return {
                'decision': 'deny',
                'reason': 'No matching allow policy found'
            }
    
    def _policy_matches_request(self, policy, request_data):
        """Check if policy matches the access request"""
        # Protocol check
        if policy[4] != 'any' and policy[4] != request_data['protocol']:
            return False
        
        # Port range check
        if policy[5] != 'any':
            # Simple port range implementation
            try:
                port_range = policy[5]
                dest_port = int(request_data['destination_port'])
                
                if '-' in port_range:
                    start_port, end_port = map(int, port_range.split('-'))
                    if not (start_port <= dest_port <= end_port):
                        return False
                elif port_range != str(dest_port):
                    return False
            except ValueError:
                return False
        
        return True
    
    def _generate_tunnel_config(self):
        """Generate tunnel configuration for allowed connections"""
        return {
            'tunnel_type': 'wireguard',
            'gateway_endpoint': 'sdp-gateway:51820',
            'encryption': 'chacha20poly1305',
            'key_exchange': 'x25519'
        }
    
    def _log_access_request(self, user_id, request_data, decision):
        """Log access request for audit purposes"""
        description = f"Access request: {request_data['source_zone']} -> {request_data['destination_zone']}:{request_data['destination_port']} - {decision['decision']}"
        
        with sqlite3.connect(db_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO security_events (id, event_type, user_id, description, severity)
                VALUES (?, ?, ?, ?, ?)
            ''', (str(uuid.uuid4()), 'access_request', user_id, description, 'info'))
            conn.commit()

# Register API endpoints
api.add_resource(AuthenticationResource, '/api/auth/login')
api.add_resource(AccessPolicyResource, '/api/policies', '/api/policies/<policy_id>')
api.add_resource(AccessRequestResource, '/api/access/request')

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return {'status': 'healthy', 'service': 'sdp-controller', 'timestamp': datetime.utcnow().isoformat()}

@app.route('/api/status')
@jwt_required()
def get_status():
    """Get controller status and statistics"""
    try:
        with sqlite3.connect(db_manager.db_path) as conn:
            cursor = conn.cursor()
            
            # Get statistics
            cursor.execute('SELECT COUNT(*) FROM users WHERE is_active = 1')
            active_users = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM devices')
            registered_devices = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM access_policies WHERE is_active = 1')
            active_policies = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM active_sessions WHERE is_active = 1')
            active_sessions = cursor.fetchone()[0]
            
            return {
                'status': 'operational',
                'statistics': {
                    'active_users': active_users,
                    'registered_devices': registered_devices,
                    'active_policies': active_policies,
                    'active_sessions': active_sessions
                },
                'timestamp': datetime.utcnow().isoformat()
            }
    except Exception as e:
        logger.error(f"Error getting status: {str(e)}")
        return {'error': 'Failed to get status'}, 500

if __name__ == '__main__':
    logger.info("Starting SDP Controller...")
    app.run(host='0.0.0.0', port=8001, debug=True)
