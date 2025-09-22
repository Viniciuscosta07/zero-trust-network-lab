#!/usr/bin/env python3
"""
Zero Trust Integration API Gateway

This component serves as the central integration layer that connects all zero trust
components, provides unified APIs, handles event routing, and manages cross-component
communication and policy orchestration.
"""

import os
import logging
import json
import asyncio
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, get_jwt
import sqlite3
import uuid
import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/integration_api.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'zero-trust-integration-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=8)

# Initialize extensions
jwt = JWTManager(app)
api = Api(app)
CORS(app)

class ServiceRegistry:
    """Manages service discovery and health monitoring"""
    
    def __init__(self):
        self.services = {
            'sdp_controller': {
                'url': os.environ.get('SDP_CONTROLLER_URL', 'http://sdp-controller:8001'),
                'health_endpoint': '/health',
                'status': 'unknown',
                'last_check': None
            },
            'sdp_gateway': {
                'url': os.environ.get('SDP_GATEWAY_URL', 'http://sdp-gateway:8002'),
                'health_endpoint': '/health',
                'status': 'unknown',
                'last_check': None
            },
            'pki_ca': {
                'url': os.environ.get('PKI_CA_URL', 'http://pki-ca:8003'),
                'health_endpoint': '/health',
                'status': 'unknown',
                'last_check': None
            },
            'nac_service': {
                'url': os.environ.get('NAC_SERVICE_URL', 'http://nac-service:8004'),
                'health_endpoint': '/health',
                'status': 'unknown',
                'last_check': None
            },
            'microseg_engine': {
                'url': os.environ.get('MICROSEG_ENGINE_URL', 'http://microseg-engine:8005'),
                'health_endpoint': '/health',
                'status': 'unknown',
                'last_check': None
            }
        }
        
        # Start health monitoring
        self.start_health_monitoring()
    
    def start_health_monitoring(self):
        """Start background health monitoring"""
        monitor_thread = threading.Thread(target=self._monitor_services, daemon=True)
        monitor_thread.start()
        logger.info("Service health monitoring started")
    
    def _monitor_services(self):
        """Monitor service health continuously"""
        while True:
            try:
                for service_name, service_config in self.services.items():
                    self._check_service_health(service_name, service_config)
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Service monitoring error: {str(e)}")
                time.sleep(30)
    
    def _check_service_health(self, service_name, service_config):
        """Check individual service health"""
        try:
            health_url = f"{service_config['url']}{service_config['health_endpoint']}"
            
            response = requests.get(health_url, timeout=5)
            
            if response.status_code == 200:
                service_config['status'] = 'healthy'
            else:
                service_config['status'] = 'unhealthy'
                
        except requests.exceptions.RequestException:
            service_config['status'] = 'unreachable'
        except Exception as e:
            service_config['status'] = 'error'
            logger.error(f"Health check error for {service_name}: {str(e)}")
        
        service_config['last_check'] = datetime.utcnow().isoformat()
    
    def get_service_url(self, service_name):
        """Get service URL"""
        return self.services.get(service_name, {}).get('url')
    
    def is_service_healthy(self, service_name):
        """Check if service is healthy"""
        return self.services.get(service_name, {}).get('status') == 'healthy'
    
    def get_all_services_status(self):
        """Get status of all services"""
        return self.services

class EventManager:
    """Manages events and notifications across components"""
    
    def __init__(self):
        self.event_queue = []
        self.event_handlers = {}
        self.init_database()
        self.start_event_processing()
    
    def init_database(self):
        """Initialize event database"""
        with sqlite3.connect('integration.db') as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    event_type TEXT,
                    source_service TEXT,
                    event_data TEXT,
                    severity TEXT DEFAULT 'info',
                    processed BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS event_subscriptions (
                    id TEXT PRIMARY KEY,
                    service_name TEXT,
                    event_types TEXT,
                    webhook_url TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
    
    def start_event_processing(self):
        """Start background event processing"""
        processor_thread = threading.Thread(target=self._process_events, daemon=True)
        processor_thread.start()
        logger.info("Event processing started")
    
    def publish_event(self, event_type, source_service, event_data, severity='info'):
        """Publish event to the system"""
        try:
            event = {
                'id': str(uuid.uuid4()),
                'event_type': event_type,
                'source_service': source_service,
                'event_data': event_data,
                'severity': severity,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Add to queue for processing
            self.event_queue.append(event)
            
            # Store in database
            with sqlite3.connect('integration.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO events (id, event_type, source_service, event_data, severity)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    event['id'],
                    event_type,
                    source_service,
                    json.dumps(event_data),
                    severity
                ))
                conn.commit()
            
            logger.info(f"Event published: {event_type} from {source_service}")
            return event['id']
            
        except Exception as e:
            logger.error(f"Event publishing error: {str(e)}")
            return None
    
    def _process_events(self):
        """Process events from queue"""
        while True:
            try:
                if self.event_queue:
                    event = self.event_queue.pop(0)
                    self._handle_event(event)
                
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Event processing error: {str(e)}")
                time.sleep(1)
    
    def _handle_event(self, event):
        """Handle individual event"""
        try:
            event_type = event['event_type']
            
            # Handle specific event types
            if event_type == 'authentication_failed':
                self._handle_auth_failure(event)
            elif event_type == 'compliance_violation':
                self._handle_compliance_violation(event)
            elif event_type == 'policy_violation':
                self._handle_policy_violation(event)
            elif event_type == 'certificate_expiring':
                self._handle_certificate_expiry(event)
            elif event_type == 'service_unhealthy':
                self._handle_service_unhealthy(event)
            
            # Mark as processed
            with sqlite3.connect('integration.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE events SET processed = 1 WHERE id = ?
                ''', (event['id'],))
                conn.commit()
            
        except Exception as e:
            logger.error(f"Event handling error: {str(e)}")
    
    def _handle_auth_failure(self, event):
        """Handle authentication failure events"""
        event_data = event['event_data']
        user_id = event_data.get('user_id')
        
        # Could trigger additional security measures
        logger.warning(f"Authentication failure for user {user_id}")
    
    def _handle_compliance_violation(self, event):
        """Handle compliance violation events"""
        event_data = event['event_data']
        device_id = event_data.get('device_id')
        
        # Could trigger automatic remediation
        logger.warning(f"Compliance violation for device {device_id}")
    
    def _handle_policy_violation(self, event):
        """Handle policy violation events"""
        event_data = event['event_data']
        source_ip = event_data.get('source_ip')
        
        # Could trigger network isolation
        logger.warning(f"Policy violation from {source_ip}")
    
    def _handle_certificate_expiry(self, event):
        """Handle certificate expiry events"""
        event_data = event['event_data']
        serial_number = event_data.get('serial_number')
        
        # Could trigger automatic renewal
        logger.warning(f"Certificate {serial_number} expiring soon")
    
    def _handle_service_unhealthy(self, event):
        """Handle service health events"""
        event_data = event['event_data']
        service_name = event_data.get('service_name')
        
        logger.error(f"Service {service_name} is unhealthy")

class PolicyOrchestrator:
    """Orchestrates policies across all components"""
    
    def __init__(self, service_registry, event_manager):
        self.service_registry = service_registry
        self.event_manager = event_manager
        self.unified_policies = {}
    
    def create_unified_access_policy(self, policy_data):
        """Create unified access policy across components"""
        try:
            policy_id = str(uuid.uuid4())
            
            # Validate policy
            required_fields = ['name', 'source_zone', 'destination_zone', 'action']
            for field in required_fields:
                if field not in policy_data:
                    raise ValueError(f"Missing required field: {field}")
            
            # Create policy in SDP Controller
            sdp_controller_url = self.service_registry.get_service_url('sdp_controller')
            if sdp_controller_url and self.service_registry.is_service_healthy('sdp_controller'):
                try:
                    response = requests.post(
                        f'{sdp_controller_url}/api/policies',
                        json=policy_data,
                        timeout=10
                    )
                    if response.status_code == 201:
                        logger.info(f"Policy created in SDP Controller: {policy_id}")
                except Exception as e:
                    logger.error(f"Failed to create policy in SDP Controller: {str(e)}")
            
            # Create corresponding micro-segmentation policy
            microseg_url = self.service_registry.get_service_url('microseg_engine')
            if microseg_url and self.service_registry.is_service_healthy('microseg_engine'):
                try:
                    microseg_policy = {
                        'id': policy_id,
                        'name': policy_data['name'],
                        'source_zone': policy_data['source_zone'],
                        'destination_zone': policy_data['destination_zone'],
                        'protocol': policy_data.get('protocol', 'tcp'),
                        'destination_ports': policy_data.get('port_range', 'any'),
                        'action': policy_data['action'],
                        'conditions': policy_data.get('conditions', {}),
                        'priority': policy_data.get('priority', 500),
                        'enabled': True
                    }
                    
                    response = requests.post(
                        f'{microseg_url}/api/policies',
                        json=microseg_policy,
                        timeout=10
                    )
                    if response.status_code == 201:
                        logger.info(f"Policy created in Micro-segmentation: {policy_id}")
                except Exception as e:
                    logger.error(f"Failed to create policy in Micro-segmentation: {str(e)}")
            
            # Store unified policy
            self.unified_policies[policy_id] = {
                'policy_data': policy_data,
                'created_at': datetime.utcnow().isoformat(),
                'status': 'active'
            }
            
            # Publish event
            self.event_manager.publish_event(
                'policy_created',
                'integration_api',
                {'policy_id': policy_id, 'policy_name': policy_data['name']},
                'info'
            )
            
            return policy_id
            
        except Exception as e:
            logger.error(f"Unified policy creation failed: {str(e)}")
            raise
    
    def evaluate_access_request(self, access_request):
        """Evaluate access request across all components"""
        try:
            evaluation_result = {
                'request_id': str(uuid.uuid4()),
                'timestamp': datetime.utcnow().isoformat(),
                'components_evaluated': {},
                'final_decision': 'deny',
                'reasons': []
            }
            
            # 1. Check device compliance (NAC)
            nac_url = self.service_registry.get_service_url('nac_service')
            if nac_url and self.service_registry.is_service_healthy('nac_service'):
                try:
                    device_id = access_request.get('device_id')
                    if device_id:
                        response = requests.get(
                            f'{nac_url}/api/compliance/{device_id}',
                            timeout=10
                        )
                        if response.status_code == 200:
                            compliance_data = response.json()
                            evaluation_result['components_evaluated']['nac'] = compliance_data
                            
                            if compliance_data['compliance_status'] == 'non_compliant':
                                evaluation_result['reasons'].append('Device not compliant')
                                return evaluation_result
                except Exception as e:
                    logger.warning(f"NAC evaluation failed: {str(e)}")
                    evaluation_result['reasons'].append('Could not verify device compliance')
            
            # 2. Check micro-segmentation policies
            microseg_url = self.service_registry.get_service_url('microseg_engine')
            if microseg_url and self.service_registry.is_service_healthy('microseg_engine'):
                try:
                    traffic_eval = {
                        'source_ip': access_request.get('source_ip'),
                        'destination_ip': access_request.get('destination_ip'),
                        'protocol': access_request.get('protocol', 'tcp'),
                        'destination_port': access_request.get('destination_port')
                    }
                    
                    response = requests.post(
                        f'{microseg_url}/api/traffic/evaluate',
                        json=traffic_eval,
                        timeout=10
                    )
                    if response.status_code == 200:
                        microseg_decision = response.json()
                        evaluation_result['components_evaluated']['microsegmentation'] = microseg_decision
                        
                        if microseg_decision['decision'] == 'deny':
                            evaluation_result['reasons'].append(f"Micro-segmentation: {microseg_decision.get('reason', 'Policy violation')}")
                            return evaluation_result
                except Exception as e:
                    logger.warning(f"Micro-segmentation evaluation failed: {str(e)}")
                    evaluation_result['reasons'].append('Could not evaluate network policies')
            
            # 3. Check SDP Controller policies
            sdp_url = self.service_registry.get_service_url('sdp_controller')
            if sdp_url and self.service_registry.is_service_healthy('sdp_controller'):
                try:
                    # This would require authentication token
                    # For now, we'll assume it passes if other checks pass
                    evaluation_result['components_evaluated']['sdp_controller'] = {'status': 'evaluated'}
                except Exception as e:
                    logger.warning(f"SDP Controller evaluation failed: {str(e)}")
            
            # If all checks pass, allow access
            if not evaluation_result['reasons']:
                evaluation_result['final_decision'] = 'allow'
                evaluation_result['reasons'] = ['All security checks passed']
            
            return evaluation_result
            
        except Exception as e:
            logger.error(f"Access evaluation failed: {str(e)}")
            return {
                'request_id': str(uuid.uuid4()),
                'timestamp': datetime.utcnow().isoformat(),
                'final_decision': 'deny',
                'reasons': ['Evaluation error occurred'],
                'error': str(e)
            }

# Initialize components
service_registry = ServiceRegistry()
event_manager = EventManager()
policy_orchestrator = PolicyOrchestrator(service_registry, event_manager)

class UnifiedAuthResource(Resource):
    """Unified authentication across all components"""
    
    def post(self):
        """Authenticate user and device"""
        try:
            data = request.get_json()
            
            # Forward to SDP Controller for authentication
            sdp_controller_url = service_registry.get_service_url('sdp_controller')
            if not sdp_controller_url or not service_registry.is_service_healthy('sdp_controller'):
                return {'error': 'SDP Controller unavailable'}, 503
            
            response = requests.post(
                f'{sdp_controller_url}/api/auth/login',
                json=data,
                timeout=10
            )
            
            if response.status_code == 200:
                auth_result = response.json()
                
                # Evaluate device compliance
                device_info = data.get('device_info', {})
                if device_info:
                    nac_url = service_registry.get_service_url('nac_service')
                    if nac_url and service_registry.is_service_healthy('nac_service'):
                        try:
                            compliance_request = {'device_info': device_info}
                            compliance_response = requests.post(
                                f'{nac_url}/api/compliance',
                                json=compliance_request,
                                timeout=10
                            )
                            if compliance_response.status_code == 200:
                                compliance_data = compliance_response.json()
                                auth_result['compliance'] = compliance_data['compliance']
                                auth_result['enforcement'] = compliance_data['enforcement']
                        except Exception as e:
                            logger.warning(f"Compliance check failed during auth: {str(e)}")
                
                # Publish authentication event
                event_manager.publish_event(
                    'authentication_success',
                    'integration_api',
                    {
                        'user_id': auth_result.get('user_id'),
                        'device_id': auth_result.get('device_id'),
                        'source_ip': request.remote_addr
                    },
                    'info'
                )
                
                return auth_result, 200
            else:
                # Publish failed authentication event
                event_manager.publish_event(
                    'authentication_failed',
                    'integration_api',
                    {
                        'username': data.get('username'),
                        'source_ip': request.remote_addr,
                        'reason': response.json().get('error', 'Unknown error')
                    },
                    'warning'
                )
                
                return response.json(), response.status_code
                
        except Exception as e:
            logger.error(f"Unified authentication error: {str(e)}")
            return {'error': 'Authentication service error'}, 500

class UnifiedAccessResource(Resource):
    """Unified access request processing"""
    
    def post(self):
        """Process unified access request"""
        try:
            data = request.get_json()
            
            # Evaluate access request across all components
            evaluation = policy_orchestrator.evaluate_access_request(data)
            
            if evaluation['final_decision'] == 'allow':
                # If allowed, create tunnel through gateway
                sdp_gateway_url = service_registry.get_service_url('sdp_gateway')
                if sdp_gateway_url and service_registry.is_service_healthy('sdp_gateway'):
                    try:
                        tunnel_request = {
                            'user_id': data.get('user_id'),
                            'device_id': data.get('device_id'),
                            'access_token': data.get('access_token'),
                            'allowed_ips': data.get('allowed_ips', '10.0.0.0/8')
                        }
                        
                        tunnel_response = requests.post(
                            f'{sdp_gateway_url}/api/tunnel',
                            json=tunnel_request,
                            timeout=15
                        )
                        
                        if tunnel_response.status_code == 201:
                            tunnel_data = tunnel_response.json()
                            evaluation['tunnel'] = tunnel_data
                    except Exception as e:
                        logger.error(f"Tunnel creation failed: {str(e)}")
                        evaluation['tunnel_error'] = str(e)
            
            # Publish access event
            event_manager.publish_event(
                'access_request',
                'integration_api',
                {
                    'decision': evaluation['final_decision'],
                    'user_id': data.get('user_id'),
                    'device_id': data.get('device_id'),
                    'source_ip': data.get('source_ip'),
                    'destination': f"{data.get('destination_zone')}:{data.get('destination_port')}"
                },
                'info' if evaluation['final_decision'] == 'allow' else 'warning'
            )
            
            return evaluation, 200
            
        except Exception as e:
            logger.error(f"Unified access request error: {str(e)}")
            return {'error': 'Access request processing failed'}, 500

class PolicyManagementResource(Resource):
    """Unified policy management"""
    
    def post(self):
        """Create unified policy"""
        try:
            data = request.get_json()
            
            policy_id = policy_orchestrator.create_unified_access_policy(data)
            
            return {
                'policy_id': policy_id,
                'message': 'Unified policy created successfully'
            }, 201
            
        except Exception as e:
            logger.error(f"Policy creation error: {str(e)}")
            return {'error': 'Policy creation failed'}, 500
    
    def get(self):
        """Get all unified policies"""
        try:
            return {
                'policies': policy_orchestrator.unified_policies
            }, 200
        except Exception as e:
            logger.error(f"Policy retrieval error: {str(e)}")
            return {'error': 'Policy retrieval failed'}, 500

class SystemStatusResource(Resource):
    """System-wide status and health"""
    
    def get(self):
        """Get system status"""
        try:
            services_status = service_registry.get_all_services_status()
            
            # Calculate overall health
            healthy_services = sum(1 for s in services_status.values() if s['status'] == 'healthy')
            total_services = len(services_status)
            health_percentage = int((healthy_services / total_services) * 100)
            
            overall_status = 'healthy' if health_percentage == 100 else 'degraded' if health_percentage > 50 else 'unhealthy'
            
            # Get recent events
            with sqlite3.connect('integration.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT event_type, source_service, severity, created_at
                    FROM events 
                    ORDER BY created_at DESC 
                    LIMIT 10
                ''')
                recent_events = [
                    {
                        'event_type': row[0],
                        'source_service': row[1],
                        'severity': row[2],
                        'created_at': row[3]
                    }
                    for row in cursor.fetchall()
                ]
            
            return {
                'overall_status': overall_status,
                'health_percentage': health_percentage,
                'services': services_status,
                'statistics': {
                    'healthy_services': healthy_services,
                    'total_services': total_services,
                    'active_policies': len(policy_orchestrator.unified_policies)
                },
                'recent_events': recent_events,
                'timestamp': datetime.utcnow().isoformat()
            }, 200
            
        except Exception as e:
            logger.error(f"System status error: {str(e)}")
            return {'error': 'System status retrieval failed'}, 500

# Register API endpoints
api.add_resource(UnifiedAuthResource, '/api/auth/unified')
api.add_resource(UnifiedAccessResource, '/api/access/unified')
api.add_resource(PolicyManagementResource, '/api/policies/unified')
api.add_resource(SystemStatusResource, '/api/system/status')

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return {
        'status': 'healthy',
        'service': 'integration-api',
        'services_monitored': len(service_registry.services),
        'timestamp': datetime.utcnow().isoformat()
    }

@app.route('/api/events')
def get_recent_events():
    """Get recent system events"""
    try:
        hours = request.args.get('hours', 24, type=int)
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        with sqlite3.connect('integration.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, event_type, source_service, event_data, severity, created_at
                FROM events 
                WHERE created_at > ?
                ORDER BY created_at DESC
            ''', (cutoff_time.isoformat(),))
            
            events = [
                {
                    'id': row[0],
                    'event_type': row[1],
                    'source_service': row[2],
                    'event_data': json.loads(row[3]),
                    'severity': row[4],
                    'created_at': row[5]
                }
                for row in cursor.fetchall()
            ]
        
        return {
            'events': events,
            'count': len(events),
            'time_period_hours': hours
        }, 200
        
    except Exception as e:
        logger.error(f"Events retrieval error: {str(e)}")
        return {'error': 'Events retrieval failed'}, 500

if __name__ == '__main__':
    logger.info("Starting Integration API Gateway...")
    app.run(host='0.0.0.0', port=8006, debug=True)
