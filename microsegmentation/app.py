#!/usr/bin/env python3
"""
Zero Trust Micro-segmentation Engine

This component implements network micro-segmentation by creating isolated security zones
with granular access controls between them. It manages dynamic policy enforcement
and traffic analysis for zero trust network architecture.
"""

import os
import logging
import json
import ipaddress
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_cors import CORS
import sqlite3
import uuid
import requests
import threading
import time
import subprocess

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/microsegmentation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
api = Api(app)
CORS(app)

class NetworkZoneManager:
    """Manages network security zones and their configurations"""
    
    def __init__(self):
        self.zones = {}
        self.zone_policies = {}
        self.load_default_zones()
    
    def load_default_zones(self):
        """Load default network zones"""
        default_zones = {
            'dmz': {
                'name': 'DMZ Zone',
                'description': 'Demilitarized zone for public services',
                'subnet': '10.1.0.0/24',
                'security_level': 'medium',
                'allowed_protocols': ['tcp', 'udp'],
                'default_action': 'deny'
            },
            'internal': {
                'name': 'Internal Zone',
                'description': 'Internal corporate network',
                'subnet': '10.2.0.0/24',
                'security_level': 'high',
                'allowed_protocols': ['tcp', 'udp', 'icmp'],
                'default_action': 'deny'
            },
            'user_devices': {
                'name': 'User Devices',
                'description': 'End user workstations and mobile devices',
                'subnet': '10.3.0.0/24',
                'security_level': 'medium',
                'allowed_protocols': ['tcp', 'udp'],
                'default_action': 'deny'
            },
            'servers': {
                'name': 'Server Zone',
                'description': 'Application and database servers',
                'subnet': '10.4.0.0/24',
                'security_level': 'high',
                'allowed_protocols': ['tcp'],
                'default_action': 'deny'
            },
            'management': {
                'name': 'Management Zone',
                'description': 'Network management and monitoring',
                'subnet': '10.5.0.0/24',
                'security_level': 'critical',
                'allowed_protocols': ['tcp', 'udp', 'icmp'],
                'default_action': 'deny'
            }
        }
        
        self.zones = default_zones
        logger.info(f"Loaded {len(default_zones)} default network zones")
    
    def create_zone(self, zone_id, zone_config):
        """Create a new network zone"""
        try:
            # Validate subnet
            ipaddress.IPv4Network(zone_config['subnet'])
            
            self.zones[zone_id] = zone_config
            logger.info(f"Created network zone: {zone_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create zone {zone_id}: {str(e)}")
            return False
    
    def get_zone_by_ip(self, ip_address):
        """Get zone containing the specified IP address"""
        try:
            ip = ipaddress.IPv4Address(ip_address)
            
            for zone_id, zone_config in self.zones.items():
                network = ipaddress.IPv4Network(zone_config['subnet'])
                if ip in network:
                    return zone_id
            
            return 'unknown'
            
        except Exception as e:
            logger.error(f"Error determining zone for IP {ip_address}: {str(e)}")
            return 'unknown'
    
    def get_all_zones(self):
        """Get all configured zones"""
        return self.zones

class PolicyEngine:
    """Manages and enforces micro-segmentation policies"""
    
    def __init__(self, zone_manager):
        self.zone_manager = zone_manager
        self.policies = []
        self.policy_cache = {}
        self.load_default_policies()
    
    def load_default_policies(self):
        """Load default micro-segmentation policies"""
        default_policies = [
            {
                'id': 'allow-user-to-dmz-web',
                'name': 'Allow User to DMZ Web Services',
                'source_zone': 'user_devices',
                'destination_zone': 'dmz',
                'protocol': 'tcp',
                'destination_ports': [80, 443],
                'action': 'allow',
                'conditions': {
                    'require_authentication': True,
                    'business_hours_only': False,
                    'max_connection_time': 3600
                },
                'priority': 100,
                'enabled': True
            },
            {
                'id': 'allow-dmz-to-servers',
                'name': 'Allow DMZ to Application Servers',
                'source_zone': 'dmz',
                'destination_zone': 'servers',
                'protocol': 'tcp',
                'destination_ports': [8080, 8443],
                'action': 'allow',
                'conditions': {
                    'require_authentication': True,
                    'max_connection_time': 1800
                },
                'priority': 110,
                'enabled': True
            },
            {
                'id': 'allow-management-all',
                'name': 'Allow Management Zone Full Access',
                'source_zone': 'management',
                'destination_zone': 'any',
                'protocol': 'any',
                'destination_ports': 'any',
                'action': 'allow',
                'conditions': {
                    'require_mfa': True,
                    'require_privileged_access': True
                },
                'priority': 50,
                'enabled': True
            },
            {
                'id': 'deny-all-default',
                'name': 'Default Deny All Traffic',
                'source_zone': 'any',
                'destination_zone': 'any',
                'protocol': 'any',
                'destination_ports': 'any',
                'action': 'deny',
                'conditions': {},
                'priority': 1000,
                'enabled': True
            }
        ]
        
        self.policies = default_policies
        self._rebuild_policy_cache()
        logger.info(f"Loaded {len(default_policies)} default policies")
    
    def add_policy(self, policy):
        """Add a new policy"""
        try:
            # Validate policy
            required_fields = ['id', 'name', 'source_zone', 'destination_zone', 'action']
            for field in required_fields:
                if field not in policy:
                    raise ValueError(f"Missing required field: {field}")
            
            # Set defaults
            policy.setdefault('protocol', 'any')
            policy.setdefault('destination_ports', 'any')
            policy.setdefault('priority', 500)
            policy.setdefault('enabled', True)
            policy.setdefault('conditions', {})
            
            self.policies.append(policy)
            self._rebuild_policy_cache()
            
            logger.info(f"Added policy: {policy['id']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add policy: {str(e)}")
            return False
    
    def remove_policy(self, policy_id):
        """Remove a policy"""
        try:
            self.policies = [p for p in self.policies if p['id'] != policy_id]
            self._rebuild_policy_cache()
            
            logger.info(f"Removed policy: {policy_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove policy {policy_id}: {str(e)}")
            return False
    
    def _rebuild_policy_cache(self):
        """Rebuild policy cache for faster lookups"""
        self.policy_cache = {}
        
        # Sort policies by priority
        sorted_policies = sorted(self.policies, key=lambda p: p['priority'])
        
        for policy in sorted_policies:
            if not policy.get('enabled', True):
                continue
            
            source_zone = policy['source_zone']
            dest_zone = policy['destination_zone']
            
            cache_key = f"{source_zone}:{dest_zone}"
            
            if cache_key not in self.policy_cache:
                self.policy_cache[cache_key] = []
            
            self.policy_cache[cache_key].append(policy)
    
    def evaluate_traffic(self, source_ip, destination_ip, protocol, destination_port):
        """Evaluate traffic against policies"""
        try:
            # Determine zones
            source_zone = self.zone_manager.get_zone_by_ip(source_ip)
            dest_zone = self.zone_manager.get_zone_by_ip(destination_ip)
            
            # Check cache for applicable policies
            cache_keys = [
                f"{source_zone}:{dest_zone}",
                f"{source_zone}:any",
                f"any:{dest_zone}",
                "any:any"
            ]
            
            for cache_key in cache_keys:
                if cache_key in self.policy_cache:
                    for policy in self.policy_cache[cache_key]:
                        if self._policy_matches_traffic(policy, protocol, destination_port):
                            return {
                                'decision': policy['action'],
                                'policy_id': policy['id'],
                                'policy_name': policy['name'],
                                'source_zone': source_zone,
                                'destination_zone': dest_zone,
                                'conditions': policy.get('conditions', {}),
                                'priority': policy['priority']
                            }
            
            # Default deny
            return {
                'decision': 'deny',
                'policy_id': 'default-deny',
                'policy_name': 'Default Deny',
                'source_zone': source_zone,
                'destination_zone': dest_zone,
                'reason': 'No matching allow policy'
            }
            
        except Exception as e:
            logger.error(f"Policy evaluation error: {str(e)}")
            return {
                'decision': 'deny',
                'policy_id': 'error',
                'policy_name': 'Error Policy',
                'reason': 'Policy evaluation failed'
            }
    
    def _policy_matches_traffic(self, policy, protocol, destination_port):
        """Check if policy matches the traffic"""
        # Protocol check
        if policy['protocol'] != 'any' and policy['protocol'] != protocol:
            return False
        
        # Port check
        policy_ports = policy['destination_ports']
        if policy_ports != 'any':
            if isinstance(policy_ports, list):
                if int(destination_port) not in policy_ports:
                    return False
            elif isinstance(policy_ports, str) and policy_ports.isdigit():
                if int(destination_port) != int(policy_ports):
                    return False
        
        return True

class TrafficMonitor:
    """Monitors network traffic and enforces policies"""
    
    def __init__(self, policy_engine):
        self.policy_engine = policy_engine
        self.traffic_log = []
        self.active_connections = {}
        self.monitoring_active = False
    
    def start_monitoring(self):
        """Start traffic monitoring"""
        self.monitoring_active = True
        monitor_thread = threading.Thread(target=self._monitor_traffic, daemon=True)
        monitor_thread.start()
        logger.info("Traffic monitoring started")
    
    def stop_monitoring(self):
        """Stop traffic monitoring"""
        self.monitoring_active = False
        logger.info("Traffic monitoring stopped")
    
    def _monitor_traffic(self):
        """Monitor network traffic (simulated)"""
        while self.monitoring_active:
            try:
                # In a real implementation, this would capture actual network traffic
                # For demo purposes, we'll simulate some traffic patterns
                self._simulate_traffic()
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Traffic monitoring error: {str(e)}")
                time.sleep(5)
    
    def _simulate_traffic(self):
        """Simulate network traffic for demonstration"""
        import random
        
        # Simulate some traffic patterns
        traffic_patterns = [
            ('10.3.0.101', '10.1.0.10', 'tcp', 80),    # User to DMZ web
            ('10.3.0.102', '10.1.0.10', 'tcp', 443),   # User to DMZ HTTPS
            ('10.1.0.10', '10.4.0.20', 'tcp', 8080),   # DMZ to app server
            ('10.5.0.5', '10.4.0.20', 'tcp', 22),      # Management SSH
            ('10.3.0.103', '10.4.0.20', 'tcp', 3306),  # Blocked: User to DB
        ]
        
        for source_ip, dest_ip, protocol, port in traffic_patterns:
            if random.random() < 0.3:  # 30% chance to generate each pattern
                self.log_traffic(source_ip, dest_ip, protocol, port)
    
    def log_traffic(self, source_ip, destination_ip, protocol, destination_port):
        """Log and evaluate traffic"""
        try:
            # Evaluate against policies
            decision = self.policy_engine.evaluate_traffic(
                source_ip, destination_ip, protocol, destination_port
            )
            
            # Create traffic log entry
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'protocol': protocol,
                'destination_port': destination_port,
                'decision': decision['decision'],
                'policy_id': decision['policy_id'],
                'policy_name': decision['policy_name'],
                'source_zone': decision.get('source_zone'),
                'destination_zone': decision.get('destination_zone')
            }
            
            # Add to traffic log
            self.traffic_log.append(log_entry)
            
            # Keep only recent entries (last 1000)
            if len(self.traffic_log) > 1000:
                self.traffic_log = self.traffic_log[-1000:]
            
            # Log significant events
            if decision['decision'] == 'deny':
                logger.warning(f"Traffic denied: {source_ip} -> {destination_ip}:{destination_port} ({decision['policy_name']})")
            
        except Exception as e:
            logger.error(f"Traffic logging error: {str(e)}")
    
    def get_traffic_summary(self, hours=1):
        """Get traffic summary for the specified time period"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            recent_traffic = [
                entry for entry in self.traffic_log
                if datetime.fromisoformat(entry['timestamp']) > cutoff_time
            ]
            
            # Calculate statistics
            total_requests = len(recent_traffic)
            allowed_requests = len([e for e in recent_traffic if e['decision'] == 'allow'])
            denied_requests = len([e for e in recent_traffic if e['decision'] == 'deny'])
            
            # Top source zones
            source_zones = {}
            for entry in recent_traffic:
                zone = entry.get('source_zone', 'unknown')
                source_zones[zone] = source_zones.get(zone, 0) + 1
            
            # Top destination zones
            dest_zones = {}
            for entry in recent_traffic:
                zone = entry.get('destination_zone', 'unknown')
                dest_zones[zone] = dest_zones.get(zone, 0) + 1
            
            return {
                'time_period_hours': hours,
                'total_requests': total_requests,
                'allowed_requests': allowed_requests,
                'denied_requests': denied_requests,
                'allow_rate': (allowed_requests / total_requests * 100) if total_requests > 0 else 0,
                'top_source_zones': dict(sorted(source_zones.items(), key=lambda x: x[1], reverse=True)[:5]),
                'top_destination_zones': dict(sorted(dest_zones.items(), key=lambda x: x[1], reverse=True)[:5])
            }
            
        except Exception as e:
            logger.error(f"Traffic summary error: {str(e)}")
            return {}

# Initialize components
zone_manager = NetworkZoneManager()
policy_engine = PolicyEngine(zone_manager)
traffic_monitor = TrafficMonitor(policy_engine)

# Start traffic monitoring
traffic_monitor.start_monitoring()

class ZoneResource(Resource):
    """Manages network zones"""
    
    def get(self, zone_id=None):
        """Get zone information"""
        try:
            if zone_id:
                zones = zone_manager.get_all_zones()
                if zone_id in zones:
                    return {zone_id: zones[zone_id]}, 200
                else:
                    return {'error': 'Zone not found'}, 404
            else:
                return zone_manager.get_all_zones(), 200
                
        except Exception as e:
            logger.error(f"Zone retrieval error: {str(e)}")
            return {'error': 'Zone retrieval failed'}, 500
    
    def post(self):
        """Create new zone"""
        try:
            data = request.get_json()
            
            required_fields = ['id', 'name', 'subnet']
            for field in required_fields:
                if field not in data:
                    return {'error': f'Missing required field: {field}'}, 400
            
            zone_id = data.pop('id')
            
            if zone_manager.create_zone(zone_id, data):
                return {'message': f'Zone {zone_id} created successfully'}, 201
            else:
                return {'error': 'Zone creation failed'}, 500
                
        except Exception as e:
            logger.error(f"Zone creation error: {str(e)}")
            return {'error': 'Zone creation failed'}, 500

class PolicyResource(Resource):
    """Manages micro-segmentation policies"""
    
    def get(self):
        """Get all policies"""
        try:
            return {'policies': policy_engine.policies}, 200
        except Exception as e:
            logger.error(f"Policy retrieval error: {str(e)}")
            return {'error': 'Policy retrieval failed'}, 500
    
    def post(self):
        """Create new policy"""
        try:
            data = request.get_json()
            
            if policy_engine.add_policy(data):
                return {'message': f'Policy {data["id"]} created successfully'}, 201
            else:
                return {'error': 'Policy creation failed'}, 500
                
        except Exception as e:
            logger.error(f"Policy creation error: {str(e)}")
            return {'error': 'Policy creation failed'}, 500
    
    def delete(self, policy_id):
        """Delete policy"""
        try:
            if policy_engine.remove_policy(policy_id):
                return {'message': f'Policy {policy_id} deleted successfully'}, 200
            else:
                return {'error': 'Policy deletion failed'}, 500
                
        except Exception as e:
            logger.error(f"Policy deletion error: {str(e)}")
            return {'error': 'Policy deletion failed'}, 500

class TrafficEvaluationResource(Resource):
    """Evaluates traffic against policies"""
    
    def post(self):
        """Evaluate traffic"""
        try:
            data = request.get_json()
            
            required_fields = ['source_ip', 'destination_ip', 'protocol', 'destination_port']
            for field in required_fields:
                if field not in data:
                    return {'error': f'Missing required field: {field}'}, 400
            
            decision = policy_engine.evaluate_traffic(
                data['source_ip'],
                data['destination_ip'],
                data['protocol'],
                data['destination_port']
            )
            
            # Log the traffic
            traffic_monitor.log_traffic(
                data['source_ip'],
                data['destination_ip'],
                data['protocol'],
                data['destination_port']
            )
            
            return decision, 200
            
        except Exception as e:
            logger.error(f"Traffic evaluation error: {str(e)}")
            return {'error': 'Traffic evaluation failed'}, 500

class TrafficSummaryResource(Resource):
    """Provides traffic analytics and summaries"""
    
    def get(self):
        """Get traffic summary"""
        try:
            hours = request.args.get('hours', 1, type=int)
            summary = traffic_monitor.get_traffic_summary(hours)
            return summary, 200
            
        except Exception as e:
            logger.error(f"Traffic summary error: {str(e)}")
            return {'error': 'Traffic summary failed'}, 500

# Register API endpoints
api.add_resource(ZoneResource, '/api/zones', '/api/zones/<zone_id>')
api.add_resource(PolicyResource, '/api/policies', '/api/policies/<policy_id>')
api.add_resource(TrafficEvaluationResource, '/api/traffic/evaluate')
api.add_resource(TrafficSummaryResource, '/api/traffic/summary')

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return {
        'status': 'healthy',
        'service': 'microsegmentation',
        'zones_configured': len(zone_manager.zones),
        'policies_active': len([p for p in policy_engine.policies if p.get('enabled', True)]),
        'timestamp': datetime.utcnow().isoformat()
    }

@app.route('/api/status')
def get_status():
    """Get service status and statistics"""
    try:
        traffic_summary = traffic_monitor.get_traffic_summary(24)  # Last 24 hours
        
        return {
            'status': 'operational',
            'zones': {
                'total': len(zone_manager.zones),
                'configured': list(zone_manager.zones.keys())
            },
            'policies': {
                'total': len(policy_engine.policies),
                'active': len([p for p in policy_engine.policies if p.get('enabled', True)])
            },
            'traffic_summary': traffic_summary,
            'monitoring_active': traffic_monitor.monitoring_active,
            'timestamp': datetime.utcnow().isoformat()
        }, 200
        
    except Exception as e:
        logger.error(f"Status retrieval error: {str(e)}")
        return {'error': 'Status retrieval failed'}, 500

if __name__ == '__main__':
    logger.info("Starting Micro-segmentation Engine...")
    app.run(host='0.0.0.0', port=8005, debug=True)
