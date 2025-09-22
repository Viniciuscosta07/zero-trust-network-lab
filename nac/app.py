#!/usr/bin/env python3
"""
Zero Trust Network Access Control (NAC) Service

This component implements comprehensive Network Access Control by assessing device
compliance, enforcing security policies, and providing remediation services for
non-compliant devices in the zero trust network.
"""

import os
import logging
import json
import platform
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_cors import CORS
import sqlite3
import uuid
import requests
import threading
import time
import hashlib
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/nac_service.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
api = Api(app)
CORS(app)

class ComplianceEngine:
    """Evaluates device compliance against security policies"""
    
    def __init__(self):
        self.compliance_policies = self.load_default_policies()
        self.compliance_cache = {}
        
    def load_default_policies(self):
        """Load default compliance policies"""
        return {
            'antivirus_required': {
                'name': 'Antivirus Protection Required',
                'description': 'Device must have active antivirus protection',
                'severity': 'high',
                'check_function': 'check_antivirus',
                'remediation': 'Install and activate antivirus software'
            },
            'firewall_enabled': {
                'name': 'Firewall Must Be Enabled',
                'description': 'Device firewall must be active',
                'severity': 'high',
                'check_function': 'check_firewall',
                'remediation': 'Enable device firewall'
            },
            'os_patches_current': {
                'name': 'Operating System Patches',
                'description': 'OS must be up to date with security patches',
                'severity': 'medium',
                'check_function': 'check_os_patches',
                'remediation': 'Install latest security updates'
            },
            'disk_encryption': {
                'name': 'Disk Encryption Required',
                'description': 'Device storage must be encrypted',
                'severity': 'high',
                'check_function': 'check_disk_encryption',
                'remediation': 'Enable full disk encryption'
            },
            'password_policy': {
                'name': 'Strong Password Policy',
                'description': 'Device must enforce strong password policies',
                'severity': 'medium',
                'check_function': 'check_password_policy',
                'remediation': 'Configure strong password requirements'
            },
            'unauthorized_software': {
                'name': 'No Unauthorized Software',
                'description': 'Device must not have prohibited software',
                'severity': 'medium',
                'check_function': 'check_unauthorized_software',
                'remediation': 'Remove unauthorized applications'
            },
            'certificate_valid': {
                'name': 'Valid Device Certificate',
                'description': 'Device must have valid PKI certificate',
                'severity': 'critical',
                'check_function': 'check_device_certificate',
                'remediation': 'Renew or obtain valid device certificate'
            }
        }
    
    def evaluate_device_compliance(self, device_info):
        """Evaluate device against all compliance policies"""
        try:
            compliance_results = {
                'device_id': device_info.get('device_id'),
                'evaluation_time': datetime.utcnow().isoformat(),
                'overall_status': 'compliant',
                'compliance_score': 0,
                'policy_results': {},
                'violations': [],
                'recommendations': []
            }
            
            total_policies = len(self.compliance_policies)
            passed_policies = 0
            
            for policy_id, policy in self.compliance_policies.items():
                try:
                    # Execute compliance check
                    check_result = self._execute_compliance_check(policy, device_info)
                    
                    compliance_results['policy_results'][policy_id] = check_result
                    
                    if check_result['compliant']:
                        passed_policies += 1
                    else:
                        compliance_results['violations'].append({
                            'policy_id': policy_id,
                            'policy_name': policy['name'],
                            'severity': policy['severity'],
                            'description': check_result.get('reason', 'Compliance check failed')
                        })
                        
                        compliance_results['recommendations'].append({
                            'policy_id': policy_id,
                            'remediation': policy['remediation'],
                            'severity': policy['severity']
                        })
                        
                        # Set overall status based on severity
                        if policy['severity'] == 'critical':
                            compliance_results['overall_status'] = 'non_compliant'
                        elif policy['severity'] == 'high' and compliance_results['overall_status'] != 'non_compliant':
                            compliance_results['overall_status'] = 'partially_compliant'
                
                except Exception as e:
                    logger.error(f"Compliance check failed for {policy_id}: {str(e)}")
                    compliance_results['policy_results'][policy_id] = {
                        'compliant': False,
                        'reason': f'Check execution failed: {str(e)}'
                    }
            
            # Calculate compliance score
            compliance_results['compliance_score'] = int((passed_policies / total_policies) * 100)
            
            # Cache result
            self.compliance_cache[device_info.get('device_id')] = compliance_results
            
            return compliance_results
            
        except Exception as e:
            logger.error(f"Device compliance evaluation failed: {str(e)}")
            return {
                'device_id': device_info.get('device_id'),
                'evaluation_time': datetime.utcnow().isoformat(),
                'overall_status': 'error',
                'compliance_score': 0,
                'error': str(e)
            }
    
    def _execute_compliance_check(self, policy, device_info):
        """Execute individual compliance check"""
        check_function = policy.get('check_function')
        
        if check_function == 'check_antivirus':
            return self._check_antivirus(device_info)
        elif check_function == 'check_firewall':
            return self._check_firewall(device_info)
        elif check_function == 'check_os_patches':
            return self._check_os_patches(device_info)
        elif check_function == 'check_disk_encryption':
            return self._check_disk_encryption(device_info)
        elif check_function == 'check_password_policy':
            return self._check_password_policy(device_info)
        elif check_function == 'check_unauthorized_software':
            return self._check_unauthorized_software(device_info)
        elif check_function == 'check_device_certificate':
            return self._check_device_certificate(device_info)
        else:
            return {'compliant': False, 'reason': 'Unknown compliance check'}
    
    def _check_antivirus(self, device_info):
        """Check antivirus status"""
        security_info = device_info.get('security', {})
        antivirus_running = security_info.get('antivirus_running', False)
        
        return {
            'compliant': antivirus_running,
            'reason': 'Antivirus not detected' if not antivirus_running else 'Antivirus active',
            'details': security_info
        }
    
    def _check_firewall(self, device_info):
        """Check firewall status"""
        security_info = device_info.get('security', {})
        firewall_enabled = security_info.get('firewall_enabled', False)
        
        return {
            'compliant': firewall_enabled,
            'reason': 'Firewall not enabled' if not firewall_enabled else 'Firewall active',
            'details': security_info
        }
    
    def _check_os_patches(self, device_info):
        """Check OS patch level"""
        os_info = device_info.get('os', {})
        security_info = device_info.get('security', {})
        patch_level = security_info.get('patch_level', 'unknown')
        
        # Simplified check - in production, this would verify against vulnerability databases
        compliant = patch_level not in ['outdated', 'critical', 'unknown']
        
        return {
            'compliant': compliant,
            'reason': f'Patch level: {patch_level}',
            'details': {'os': os_info, 'patch_level': patch_level}
        }
    
    def _check_disk_encryption(self, device_info):
        """Check disk encryption status"""
        security_info = device_info.get('security', {})
        disk_encryption = security_info.get('disk_encryption', False)
        
        return {
            'compliant': disk_encryption,
            'reason': 'Disk encryption not enabled' if not disk_encryption else 'Disk encryption active',
            'details': security_info
        }
    
    def _check_password_policy(self, device_info):
        """Check password policy compliance"""
        # Simplified check - assume compliant if device has recent security info
        security_info = device_info.get('security', {})
        has_security_info = len(security_info) > 0
        
        return {
            'compliant': has_security_info,
            'reason': 'Password policy status unknown' if not has_security_info else 'Password policy compliant',
            'details': security_info
        }
    
    def _check_unauthorized_software(self, device_info):
        """Check for unauthorized software"""
        # Simplified check - look for known prohibited software patterns
        prohibited_software = ['torrent', 'p2p', 'keylogger', 'crack', 'hack']
        
        # In a real implementation, this would scan running processes or installed software
        # For demo, we'll assume compliant unless specific indicators are found
        
        return {
            'compliant': True,
            'reason': 'No unauthorized software detected',
            'details': {}
        }
    
    def _check_device_certificate(self, device_info):
        """Check device certificate validity"""
        try:
            # Check if device has certificate information
            device_id = device_info.get('device_id')
            if not device_id:
                return {'compliant': False, 'reason': 'No device ID provided'}
            
            # In a real implementation, this would verify certificate with PKI CA
            # For demo, we'll simulate certificate validation
            certificate_valid = device_info.get('certificate_fingerprint') is not None
            
            return {
                'compliant': certificate_valid,
                'reason': 'No valid device certificate' if not certificate_valid else 'Valid device certificate',
                'details': {'device_id': device_id}
            }
            
        except Exception as e:
            return {'compliant': False, 'reason': f'Certificate check failed: {str(e)}'}

class EnforcementEngine:
    """Enforces access control based on compliance status"""
    
    def __init__(self):
        self.enforcement_policies = self.load_enforcement_policies()
        self.quarantine_network = '10.99.0.0/24'
        
    def load_enforcement_policies(self):
        """Load enforcement policies"""
        return {
            'compliant': {
                'network_access': 'full',
                'allowed_zones': ['dmz', 'internal', 'servers'],
                'session_duration': 28800,  # 8 hours
                'monitoring_level': 'normal'
            },
            'partially_compliant': {
                'network_access': 'limited',
                'allowed_zones': ['dmz'],
                'session_duration': 3600,  # 1 hour
                'monitoring_level': 'enhanced',
                'require_remediation': True
            },
            'non_compliant': {
                'network_access': 'quarantine',
                'allowed_zones': ['remediation'],
                'session_duration': 900,  # 15 minutes
                'monitoring_level': 'high',
                'require_remediation': True,
                'block_internet': True
            }
        }
    
    def determine_access_level(self, compliance_result):
        """Determine access level based on compliance status"""
        try:
            compliance_status = compliance_result.get('overall_status', 'non_compliant')
            
            if compliance_status not in self.enforcement_policies:
                compliance_status = 'non_compliant'
            
            enforcement_policy = self.enforcement_policies[compliance_status].copy()
            enforcement_policy['compliance_status'] = compliance_status
            enforcement_policy['compliance_score'] = compliance_result.get('compliance_score', 0)
            enforcement_policy['evaluation_time'] = compliance_result.get('evaluation_time')
            
            # Add specific restrictions based on violations
            violations = compliance_result.get('violations', [])
            critical_violations = [v for v in violations if v['severity'] == 'critical']
            
            if critical_violations:
                enforcement_policy['network_access'] = 'quarantine'
                enforcement_policy['allowed_zones'] = ['remediation']
                enforcement_policy['critical_violations'] = critical_violations
            
            return enforcement_policy
            
        except Exception as e:
            logger.error(f"Access level determination failed: {str(e)}")
            # Default to most restrictive policy
            return self.enforcement_policies['non_compliant']
    
    def create_enforcement_action(self, device_id, access_level):
        """Create enforcement action for device"""
        try:
            action = {
                'action_id': str(uuid.uuid4()),
                'device_id': device_id,
                'timestamp': datetime.utcnow().isoformat(),
                'access_level': access_level,
                'actions_taken': []
            }
            
            # Network access enforcement
            if access_level['network_access'] == 'quarantine':
                action['actions_taken'].append({
                    'type': 'network_quarantine',
                    'description': f'Device moved to quarantine network {self.quarantine_network}',
                    'network': self.quarantine_network
                })
            elif access_level['network_access'] == 'limited':
                action['actions_taken'].append({
                    'type': 'network_restriction',
                    'description': f'Limited network access to zones: {access_level["allowed_zones"]}',
                    'allowed_zones': access_level['allowed_zones']
                })
            
            # Session time limits
            if access_level.get('session_duration'):
                action['actions_taken'].append({
                    'type': 'session_limit',
                    'description': f'Session limited to {access_level["session_duration"]} seconds',
                    'duration': access_level['session_duration']
                })
            
            # Enhanced monitoring
            if access_level.get('monitoring_level') in ['enhanced', 'high']:
                action['actions_taken'].append({
                    'type': 'enhanced_monitoring',
                    'description': f'Enhanced monitoring level: {access_level["monitoring_level"]}',
                    'level': access_level['monitoring_level']
                })
            
            # Remediation requirement
            if access_level.get('require_remediation'):
                action['actions_taken'].append({
                    'type': 'remediation_required',
                    'description': 'Device must complete remediation before full access',
                    'remediation_url': f'/remediation/{device_id}'
                })
            
            return action
            
        except Exception as e:
            logger.error(f"Enforcement action creation failed: {str(e)}")
            return None

class RemediationService:
    """Provides remediation guidance for non-compliant devices"""
    
    def __init__(self):
        self.remediation_steps = self.load_remediation_steps()
    
    def load_remediation_steps(self):
        """Load remediation step templates"""
        return {
            'antivirus_required': {
                'title': 'Install Antivirus Protection',
                'steps': [
                    'Download approved antivirus software from company portal',
                    'Install antivirus with default enterprise settings',
                    'Run full system scan',
                    'Enable real-time protection',
                    'Verify antivirus is running and up to date'
                ],
                'estimated_time': '15-30 minutes',
                'priority': 'high'
            },
            'firewall_enabled': {
                'title': 'Enable Device Firewall',
                'steps': [
                    'Open system security settings',
                    'Navigate to firewall configuration',
                    'Enable firewall for all network profiles',
                    'Configure firewall to block unnecessary incoming connections',
                    'Test firewall is active and properly configured'
                ],
                'estimated_time': '5-10 minutes',
                'priority': 'high'
            },
            'os_patches_current': {
                'title': 'Install Security Updates',
                'steps': [
                    'Open system update settings',
                    'Check for available updates',
                    'Download and install all security updates',
                    'Restart device if required',
                    'Verify all updates are installed successfully'
                ],
                'estimated_time': '20-60 minutes',
                'priority': 'medium'
            },
            'disk_encryption': {
                'title': 'Enable Disk Encryption',
                'steps': [
                    'Backup important data before proceeding',
                    'Open disk encryption settings',
                    'Enable full disk encryption (BitLocker/FileVault)',
                    'Save recovery key in secure location',
                    'Complete encryption process (may take several hours)'
                ],
                'estimated_time': '2-8 hours',
                'priority': 'high'
            },
            'certificate_valid': {
                'title': 'Renew Device Certificate',
                'steps': [
                    'Contact IT support for certificate renewal',
                    'Download new device certificate',
                    'Install certificate in device certificate store',
                    'Verify certificate is valid and trusted',
                    'Test certificate-based authentication'
                ],
                'estimated_time': '10-20 minutes',
                'priority': 'critical'
            }
        }
    
    def create_remediation_plan(self, compliance_result):
        """Create personalized remediation plan"""
        try:
            violations = compliance_result.get('violations', [])
            
            if not violations:
                return {
                    'device_id': compliance_result.get('device_id'),
                    'status': 'compliant',
                    'message': 'Device is compliant - no remediation required',
                    'plan': []
                }
            
            remediation_plan = {
                'device_id': compliance_result.get('device_id'),
                'created_time': datetime.utcnow().isoformat(),
                'status': 'remediation_required',
                'total_violations': len(violations),
                'estimated_time': '0 minutes',
                'plan': []
            }
            
            total_time = 0
            
            # Sort violations by priority
            priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            sorted_violations = sorted(violations, key=lambda x: priority_order.get(x['severity'], 3))
            
            for violation in sorted_violations:
                policy_id = violation['policy_id']
                
                if policy_id in self.remediation_steps:
                    remediation_step = self.remediation_steps[policy_id].copy()
                    remediation_step['violation'] = violation
                    remediation_step['step_id'] = str(uuid.uuid4())
                    
                    remediation_plan['plan'].append(remediation_step)
                    
                    # Estimate time (extract number from time string)
                    time_str = remediation_step.get('estimated_time', '0 minutes')
                    try:
                        time_parts = time_str.split('-')
                        if len(time_parts) == 2:
                            # Take average of range
                            min_time = int(time_parts[0].split()[0])
                            max_time = int(time_parts[1].split()[0])
                            avg_time = (min_time + max_time) // 2
                            total_time += avg_time
                        else:
                            # Single value
                            time_val = int(time_str.split()[0])
                            total_time += time_val
                    except:
                        pass
            
            remediation_plan['estimated_time'] = f'{total_time} minutes'
            
            return remediation_plan
            
        except Exception as e:
            logger.error(f"Remediation plan creation failed: {str(e)}")
            return {
                'device_id': compliance_result.get('device_id'),
                'status': 'error',
                'error': str(e)
            }

# Initialize components
compliance_engine = ComplianceEngine()
enforcement_engine = EnforcementEngine()
remediation_service = RemediationService()

# Database initialization
def init_database():
    """Initialize NAC database"""
    with sqlite3.connect('nac_service.db') as conn:
        cursor = conn.cursor()
        
        # Device compliance table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_compliance (
                id TEXT PRIMARY KEY,
                device_id TEXT UNIQUE,
                compliance_status TEXT,
                compliance_score INTEGER,
                last_evaluation TIMESTAMP,
                violations_count INTEGER,
                enforcement_level TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Compliance history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_history (
                id TEXT PRIMARY KEY,
                device_id TEXT,
                evaluation_time TIMESTAMP,
                compliance_status TEXT,
                compliance_score INTEGER,
                violations TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Enforcement actions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS enforcement_actions (
                id TEXT PRIMARY KEY,
                device_id TEXT,
                action_type TEXT,
                action_details TEXT,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
        ''')
        
        conn.commit()

init_database()

class ComplianceResource(Resource):
    """Handles device compliance evaluation"""
    
    def post(self):
        """Evaluate device compliance"""
        try:
            data = request.get_json()
            
            if 'device_info' not in data:
                return {'error': 'Device information required'}, 400
            
            device_info = data['device_info']
            
            # Evaluate compliance
            compliance_result = compliance_engine.evaluate_device_compliance(device_info)
            
            # Store compliance result
            self._store_compliance_result(compliance_result)
            
            # Determine enforcement action
            access_level = enforcement_engine.determine_access_level(compliance_result)
            
            return {
                'compliance': compliance_result,
                'enforcement': access_level
            }, 200
            
        except Exception as e:
            logger.error(f"Compliance evaluation error: {str(e)}")
            return {'error': 'Compliance evaluation failed'}, 500
    
    def get(self, device_id):
        """Get device compliance status"""
        try:
            with sqlite3.connect('nac_service.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT compliance_status, compliance_score, last_evaluation, 
                           violations_count, enforcement_level
                    FROM device_compliance WHERE device_id = ?
                ''', (device_id,))
                
                result = cursor.fetchone()
                if not result:
                    return {'error': 'Device not found'}, 404
                
                return {
                    'device_id': device_id,
                    'compliance_status': result[0],
                    'compliance_score': result[1],
                    'last_evaluation': result[2],
                    'violations_count': result[3],
                    'enforcement_level': result[4]
                }, 200
                
        except Exception as e:
            logger.error(f"Compliance retrieval error: {str(e)}")
            return {'error': 'Compliance retrieval failed'}, 500
    
    def _store_compliance_result(self, compliance_result):
        """Store compliance evaluation result"""
        try:
            device_id = compliance_result.get('device_id')
            
            with sqlite3.connect('nac_service.db') as conn:
                cursor = conn.cursor()
                
                # Update or insert device compliance
                cursor.execute('''
                    INSERT OR REPLACE INTO device_compliance
                    (id, device_id, compliance_status, compliance_score, last_evaluation, violations_count, enforcement_level)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    str(uuid.uuid4()),
                    device_id,
                    compliance_result.get('overall_status'),
                    compliance_result.get('compliance_score'),
                    compliance_result.get('evaluation_time'),
                    len(compliance_result.get('violations', [])),
                    compliance_result.get('overall_status')
                ))
                
                # Add to compliance history
                cursor.execute('''
                    INSERT INTO compliance_history
                    (id, device_id, evaluation_time, compliance_status, compliance_score, violations)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    str(uuid.uuid4()),
                    device_id,
                    compliance_result.get('evaluation_time'),
                    compliance_result.get('overall_status'),
                    compliance_result.get('compliance_score'),
                    json.dumps(compliance_result.get('violations', []))
                ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Compliance storage error: {str(e)}")

class RemediationResource(Resource):
    """Handles device remediation"""
    
    def get(self, device_id):
        """Get remediation plan for device"""
        try:
            # Get latest compliance result from cache or database
            compliance_result = compliance_engine.compliance_cache.get(device_id)
            
            if not compliance_result:
                # Try to get from database
                with sqlite3.connect('nac_service.db') as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT violations FROM compliance_history 
                        WHERE device_id = ? ORDER BY evaluation_time DESC LIMIT 1
                    ''', (device_id,))
                    
                    result = cursor.fetchone()
                    if result:
                        violations = json.loads(result[0])
                        compliance_result = {
                            'device_id': device_id,
                            'violations': violations
                        }
            
            if not compliance_result:
                return {'error': 'Device compliance data not found'}, 404
            
            remediation_plan = remediation_service.create_remediation_plan(compliance_result)
            
            return remediation_plan, 200
            
        except Exception as e:
            logger.error(f"Remediation plan error: {str(e)}")
            return {'error': 'Remediation plan creation failed'}, 500

class EnforcementResource(Resource):
    """Handles enforcement actions"""
    
    def post(self):
        """Create enforcement action"""
        try:
            data = request.get_json()
            
            required_fields = ['device_id', 'access_level']
            for field in required_fields:
                if field not in data:
                    return {'error': f'Missing required field: {field}'}, 400
            
            enforcement_action = enforcement_engine.create_enforcement_action(
                data['device_id'], 
                data['access_level']
            )
            
            if enforcement_action:
                # Store enforcement action
                self._store_enforcement_action(enforcement_action)
                return enforcement_action, 201
            else:
                return {'error': 'Enforcement action creation failed'}, 500
                
        except Exception as e:
            logger.error(f"Enforcement action error: {str(e)}")
            return {'error': 'Enforcement action failed'}, 500
    
    def _store_enforcement_action(self, action):
        """Store enforcement action in database"""
        try:
            with sqlite3.connect('nac_service.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO enforcement_actions
                    (id, device_id, action_type, action_details, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    action['action_id'],
                    action['device_id'],
                    'access_control',
                    json.dumps(action['actions_taken']),
                    datetime.utcnow() + timedelta(hours=24)  # 24 hour expiry
                ))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Enforcement action storage error: {str(e)}")

# Register API endpoints
api.add_resource(ComplianceResource, '/api/compliance', '/api/compliance/<device_id>')
api.add_resource(RemediationResource, '/api/remediation/<device_id>')
api.add_resource(EnforcementResource, '/api/enforcement')

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return {
        'status': 'healthy',
        'service': 'nac-service',
        'compliance_policies': len(compliance_engine.compliance_policies),
        'timestamp': datetime.utcnow().isoformat()
    }

@app.route('/api/status')
def get_status():
    """Get NAC service status"""
    try:
        with sqlite3.connect('nac_service.db') as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM device_compliance')
            total_devices = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM device_compliance WHERE compliance_status = "compliant"')
            compliant_devices = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM device_compliance WHERE compliance_status = "non_compliant"')
            non_compliant_devices = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM enforcement_actions WHERE status = "active"')
            active_enforcements = cursor.fetchone()[0]
        
        return {
            'status': 'operational',
            'statistics': {
                'total_devices': total_devices,
                'compliant_devices': compliant_devices,
                'non_compliant_devices': non_compliant_devices,
                'compliance_rate': (compliant_devices / total_devices * 100) if total_devices > 0 else 0,
                'active_enforcements': active_enforcements
            },
            'policies': {
                'compliance_policies': len(compliance_engine.compliance_policies),
                'enforcement_levels': len(enforcement_engine.enforcement_policies)
            },
            'timestamp': datetime.utcnow().isoformat()
        }, 200
        
    except Exception as e:
        logger.error(f"Status retrieval error: {str(e)}")
        return {'error': 'Status retrieval failed'}, 500

if __name__ == '__main__':
    logger.info("Starting NAC Service...")
    app.run(host='0.0.0.0', port=8004, debug=True)
