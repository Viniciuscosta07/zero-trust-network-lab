#!/usr/bin/env python3
"""
Zero Trust SDP Gateway

The SDP Gateway creates secure tunnel endpoints for authorized network connections.
It implements WireGuard-based VPN tunnels and enforces access policies from the controller.
"""

import os
import logging
import json
import subprocess
import ipaddress
from datetime import datetime
from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_cors import CORS
import requests
import sqlite3
import uuid
import threading
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/sdp_gateway.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
api = Api(app)
CORS(app)

class WireGuardManager:
    """Manages WireGuard VPN tunnel configurations"""
    
    def __init__(self):
        self.config_path = '/etc/wireguard'
        self.interface_name = 'wg0'
        self.server_private_key = None
        self.server_public_key = None
        self.network_range = ipaddress.IPv4Network('10.8.0.0/24')
        self.assigned_ips = set()
        self.init_wireguard()
    
    def init_wireguard(self):
        """Initialize WireGuard server configuration"""
        try:
            # Generate server keys if they don't exist
            if not os.path.exists(f'{self.config_path}/server_private.key'):
                self._generate_server_keys()
            else:
                self._load_server_keys()
            
            # Create server configuration
            self._create_server_config()
            
            # Start WireGuard interface
            self._start_wireguard()
            
            logger.info("WireGuard initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize WireGuard: {str(e)}")
    
    def _generate_server_keys(self):
        """Generate WireGuard server key pair"""
        try:
            # Generate private key
            result = subprocess.run(['wg', 'genkey'], capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception("Failed to generate private key")
            
            self.server_private_key = result.stdout.strip()
            
            # Generate public key
            result = subprocess.run(
                ['wg', 'pubkey'], 
                input=self.server_private_key, 
                capture_output=True, 
                text=True
            )
            if result.returncode != 0:
                raise Exception("Failed to generate public key")
            
            self.server_public_key = result.stdout.strip()
            
            # Save keys
            os.makedirs(self.config_path, exist_ok=True)
            with open(f'{self.config_path}/server_private.key', 'w') as f:
                f.write(self.server_private_key)
            with open(f'{self.config_path}/server_public.key', 'w') as f:
                f.write(self.server_public_key)
            
            # Set secure permissions
            os.chmod(f'{self.config_path}/server_private.key', 0o600)
            
        except Exception as e:
            logger.error(f"Key generation failed: {str(e)}")
            raise
    
    def _load_server_keys(self):
        """Load existing server keys"""
        try:
            with open(f'{self.config_path}/server_private.key', 'r') as f:
                self.server_private_key = f.read().strip()
            with open(f'{self.config_path}/server_public.key', 'r') as f:
                self.server_public_key = f.read().strip()
        except Exception as e:
            logger.error(f"Failed to load server keys: {str(e)}")
            self._generate_server_keys()
    
    def _create_server_config(self):
        """Create WireGuard server configuration"""
        config_content = f"""[Interface]
PrivateKey = {self.server_private_key}
Address = {list(self.network_range.hosts())[0]}/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i {self.interface_name} -j ACCEPT; iptables -A FORWARD -o {self.interface_name} -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i {self.interface_name} -j ACCEPT; iptables -D FORWARD -o {self.interface_name} -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

"""
        
        with open(f'{self.config_path}/{self.interface_name}.conf', 'w') as f:
            f.write(config_content)
    
    def _start_wireguard(self):
        """Start WireGuard interface"""
        try:
            # Stop existing interface if running
            subprocess.run(['wg-quick', 'down', self.interface_name], 
                         capture_output=True, text=True)
            
            # Start interface
            result = subprocess.run(['wg-quick', 'up', self.interface_name], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to start WireGuard: {result.stderr}")
                return False
            
            logger.info(f"WireGuard interface {self.interface_name} started")
            return True
            
        except Exception as e:
            logger.error(f"Error starting WireGuard: {str(e)}")
            return False
    
    def create_client_config(self, client_id, allowed_ips=None):
        """Create client configuration and add peer"""
        try:
            # Generate client keys
            result = subprocess.run(['wg', 'genkey'], capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception("Failed to generate client private key")
            
            client_private_key = result.stdout.strip()
            
            result = subprocess.run(
                ['wg', 'pubkey'], 
                input=client_private_key, 
                capture_output=True, 
                text=True
            )
            if result.returncode != 0:
                raise Exception("Failed to generate client public key")
            
            client_public_key = result.stdout.strip()
            
            # Assign IP address
            client_ip = self._get_next_available_ip()
            if not client_ip:
                raise Exception("No available IP addresses")
            
            # Add peer to server
            if allowed_ips is None:
                allowed_ips = "0.0.0.0/0"
            
            subprocess.run([
                'wg', 'set', self.interface_name,
                'peer', client_public_key,
                'allowed-ips', str(client_ip) + '/32'
            ])
            
            # Save configuration
            subprocess.run(['wg-quick', 'save', self.interface_name])
            
            # Create client configuration
            client_config = f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_ip}/24
DNS = 8.8.8.8

[Peer]
PublicKey = {self.server_public_key}
Endpoint = sdp-gateway:51820
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
            
            logger.info(f"Created client configuration for {client_id}")
            
            return {
                'client_config': client_config,
                'client_ip': str(client_ip),
                'client_public_key': client_public_key,
                'server_public_key': self.server_public_key
            }
            
        except Exception as e:
            logger.error(f"Failed to create client config: {str(e)}")
            raise
    
    def remove_client(self, client_public_key):
        """Remove client peer from server"""
        try:
            subprocess.run([
                'wg', 'set', self.interface_name,
                'peer', client_public_key,
                'remove'
            ])
            
            subprocess.run(['wg-quick', 'save', self.interface_name])
            logger.info(f"Removed client peer: {client_public_key}")
            
        except Exception as e:
            logger.error(f"Failed to remove client: {str(e)}")
    
    def _get_next_available_ip(self):
        """Get next available IP address from the network range"""
        for ip in self.network_range.hosts():
            if ip not in self.assigned_ips:
                self.assigned_ips.add(ip)
                return ip
        return None
    
    def get_status(self):
        """Get WireGuard interface status"""
        try:
            result = subprocess.run(['wg', 'show', self.interface_name], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                return {'status': 'down', 'error': result.stderr}
            
            return {
                'status': 'up',
                'interface': self.interface_name,
                'public_key': self.server_public_key,
                'output': result.stdout
            }
            
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

class GatewayDatabase:
    """Manages gateway-specific database operations"""
    
    def __init__(self):
        self.db_path = 'sdp_gateway.db'
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Active tunnels table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS active_tunnels (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    device_id TEXT,
                    client_public_key TEXT,
                    client_ip TEXT,
                    allowed_ips TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_activity TIMESTAMP,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # Gateway metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS gateway_metrics (
                    id TEXT PRIMARY KEY,
                    metric_type TEXT,
                    value REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()

# Initialize components
wireguard_manager = WireGuardManager()
gateway_db = GatewayDatabase()

class TunnelResource(Resource):
    """Manages VPN tunnel creation and management"""
    
    def post(self):
        """Create new VPN tunnel for authenticated client"""
        try:
            data = request.get_json()
            
            # Validate request
            required_fields = ['user_id', 'device_id', 'access_token']
            for field in required_fields:
                if field not in data:
                    return {'error': f'Missing required field: {field}'}, 400
            
            # Verify access token with controller
            if not self._verify_access_token(data['access_token']):
                return {'error': 'Invalid access token'}, 401
            
            # Create tunnel configuration
            tunnel_id = str(uuid.uuid4())
            allowed_ips = data.get('allowed_ips', '10.0.0.0/8')
            
            tunnel_config = wireguard_manager.create_client_config(
                tunnel_id, allowed_ips
            )
            
            # Store tunnel information
            with sqlite3.connect(gateway_db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO active_tunnels 
                    (id, user_id, device_id, client_public_key, client_ip, allowed_ips, last_activity)
                    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    tunnel_id,
                    data['user_id'],
                    data['device_id'],
                    tunnel_config['client_public_key'],
                    tunnel_config['client_ip'],
                    allowed_ips
                ))
                conn.commit()
            
            logger.info(f"Created tunnel {tunnel_id} for user {data['user_id']}")
            
            return {
                'tunnel_id': tunnel_id,
                'client_config': tunnel_config['client_config'],
                'server_endpoint': 'sdp-gateway:51820',
                'status': 'active'
            }, 201
            
        except Exception as e:
            logger.error(f"Error creating tunnel: {str(e)}")
            return {'error': 'Failed to create tunnel'}, 500
    
    def delete(self, tunnel_id):
        """Terminate VPN tunnel"""
        try:
            with sqlite3.connect(gateway_db.db_path) as conn:
                cursor = conn.cursor()
                
                # Get tunnel information
                cursor.execute('''
                    SELECT client_public_key FROM active_tunnels 
                    WHERE id = ? AND is_active = 1
                ''', (tunnel_id,))
                
                tunnel = cursor.fetchone()
                if not tunnel:
                    return {'error': 'Tunnel not found'}, 404
                
                client_public_key = tunnel[0]
                
                # Remove from WireGuard
                wireguard_manager.remove_client(client_public_key)
                
                # Mark as inactive in database
                cursor.execute('''
                    UPDATE active_tunnels SET is_active = 0 
                    WHERE id = ?
                ''', (tunnel_id,))
                conn.commit()
            
            logger.info(f"Terminated tunnel {tunnel_id}")
            return {'message': 'Tunnel terminated successfully'}, 200
            
        except Exception as e:
            logger.error(f"Error terminating tunnel: {str(e)}")
            return {'error': 'Failed to terminate tunnel'}, 500
    
    def _verify_access_token(self, access_token):
        """Verify access token with SDP controller"""
        try:
            controller_url = os.environ.get('CONTROLLER_URL', 'http://sdp-controller:8001')
            
            response = requests.get(
                f'{controller_url}/api/status',
                headers={'Authorization': f'Bearer {access_token}'},
                timeout=5
            )
            
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Token verification failed: {str(e)}")
            return False

class GatewayStatusResource(Resource):
    """Provides gateway status and metrics"""
    
    def get(self):
        """Get gateway status"""
        try:
            # Get WireGuard status
            wg_status = wireguard_manager.get_status()
            
            # Get active tunnels count
            with sqlite3.connect(gateway_db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM active_tunnels WHERE is_active = 1')
                active_tunnels = cursor.fetchone()[0]
            
            return {
                'status': 'operational',
                'wireguard': wg_status,
                'active_tunnels': active_tunnels,
                'timestamp': datetime.utcnow().isoformat()
            }, 200
            
        except Exception as e:
            logger.error(f"Error getting status: {str(e)}")
            return {'error': 'Failed to get status'}, 500

# Register API endpoints
api.add_resource(TunnelResource, '/api/tunnel', '/api/tunnel/<tunnel_id>')
api.add_resource(GatewayStatusResource, '/api/status')

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return {
        'status': 'healthy', 
        'service': 'sdp-gateway', 
        'timestamp': datetime.utcnow().isoformat()
    }

def tunnel_monitor():
    """Background thread to monitor tunnel activity"""
    while True:
        try:
            # Update tunnel metrics
            wg_status = wireguard_manager.get_status()
            
            # Store metrics in database
            with sqlite3.connect(gateway_db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO gateway_metrics (id, metric_type, value)
                    VALUES (?, ?, ?)
                ''', (str(uuid.uuid4()), 'active_tunnels', len(wireguard_manager.assigned_ips)))
                conn.commit()
            
            time.sleep(60)  # Update every minute
            
        except Exception as e:
            logger.error(f"Tunnel monitor error: {str(e)}")
            time.sleep(60)

if __name__ == '__main__':
    # Start tunnel monitoring thread
    monitor_thread = threading.Thread(target=tunnel_monitor, daemon=True)
    monitor_thread.start()
    
    logger.info("Starting SDP Gateway...")
    app.run(host='0.0.0.0', port=8002, debug=True)
