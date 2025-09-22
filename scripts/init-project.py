#!/usr/bin/env python3
"""
Zero Trust Network Lab Initialization Script

This script initializes the zero trust network lab environment,
including PKI setup, network configuration, and default policies.
"""

import os
import sys
import json
import time
import requests
import subprocess
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are available"""
    print("Checking dependencies...")
    
    # Check Docker
    try:
        result = subprocess.run(['docker', '--version'], capture_output=True, text=True)
        if result.returncode != 0:
            print("❌ Docker not found. Please install Docker.")
            return False
        print(f"✅ {result.stdout.strip()}")
    except FileNotFoundError:
        print("❌ Docker not found. Please install Docker.")
        return False
    
    # Check Docker Compose
    try:
        result = subprocess.run(['docker-compose', '--version'], capture_output=True, text=True)
        if result.returncode != 0:
            print("❌ Docker Compose not found. Please install Docker Compose.")
            return False
        print(f"✅ {result.stdout.strip()}")
    except FileNotFoundError:
        print("❌ Docker Compose not found. Please install Docker Compose.")
        return False
    
    return True

def create_config_files():
    """Create default configuration files"""
    print("Creating configuration files...")
    
    # Network configuration
    network_config = {
        "zones": {
            "dmz": {
                "name": "DMZ Zone",
                "description": "Demilitarized zone for public services",
                "subnet": "10.1.0.0/24",
                "security_level": "medium"
            },
            "internal": {
                "name": "Internal Zone",
                "description": "Internal corporate network",
                "subnet": "10.2.0.0/24",
                "security_level": "high"
            },
            "user_devices": {
                "name": "User Devices",
                "description": "End user workstations and mobile devices",
                "subnet": "10.3.0.0/24",
                "security_level": "medium"
            },
            "servers": {
                "name": "Server Zone",
                "description": "Application and database servers",
                "subnet": "10.4.0.0/24",
                "security_level": "high"
            },
            "management": {
                "name": "Management Zone",
                "description": "Network management and monitoring",
                "subnet": "10.5.0.0/24",
                "security_level": "critical"
            }
        }
    }
    
    with open('config/network/zones.json', 'w') as f:
        json.dump(network_config, f, indent=2)
    
    # Security policies
    security_policies = {
        "default_policies": [
            {
                "name": "Allow User to DMZ Web",
                "source_zone": "user_devices",
                "destination_zone": "dmz",
                "protocol": "tcp",
                "port_range": "80,443",
                "action": "allow",
                "conditions": {
                    "require_authentication": True,
                    "require_device_compliance": True
                }
            },
            {
                "name": "Allow Internal to Servers",
                "source_zone": "internal",
                "destination_zone": "servers",
                "protocol": "tcp",
                "port_range": "1433,3306,5432",
                "action": "allow",
                "conditions": {
                    "require_authentication": True,
                    "business_hours_only": True
                }
            },
            {
                "name": "Allow Management Access",
                "source_zone": "management",
                "destination_zone": "any",
                "protocol": "any",
                "port_range": "any",
                "action": "allow",
                "conditions": {
                    "require_mfa": True,
                    "require_privileged_access": True
                }
            },
            {
                "name": "Default Deny All",
                "source_zone": "any",
                "destination_zone": "any",
                "protocol": "any",
                "port_range": "any",
                "action": "deny",
                "priority": 1000
            }
        ]
    }
    
    with open('config/security/policies.json', 'w') as f:
        json.dump(security_policies, f, indent=2)
    
    # Application configuration
    app_config = {
        "sdp_controller": {
            "jwt_secret_key": "zero-trust-lab-secret-key-change-in-production",
            "session_timeout": 28800,
            "max_concurrent_sessions": 5
        },
        "pki_ca": {
            "ca_name": "ZeroTrust-Lab-Root-CA",
            "default_validity_days": 365,
            "key_size": 2048,
            "renewal_threshold_days": 30
        },
        "monitoring": {
            "metrics_retention_days": 30,
            "log_level": "INFO",
            "alert_thresholds": {
                "failed_authentications": 5,
                "policy_violations": 10,
                "certificate_expiry_days": 30
            }
        }
    }
    
    with open('config/app_config.json', 'w') as f:
        json.dump(app_config, f, indent=2)
    
    print("✅ Configuration files created")

def build_docker_images():
    """Build Docker images for all components"""
    print("Building Docker images...")
    
    try:
        # Build all images using docker-compose
        result = subprocess.run(
            ['docker-compose', 'build'],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"❌ Docker build failed: {result.stderr}")
            return False
        
        print("✅ Docker images built successfully")
        return True
        
    except Exception as e:
        print(f"❌ Docker build error: {str(e)}")
        return False

def start_services():
    """Start all services"""
    print("Starting services...")
    
    try:
        # Start services in dependency order
        result = subprocess.run(
            ['docker-compose', 'up', '-d'],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"❌ Service startup failed: {result.stderr}")
            return False
        
        print("✅ Services started successfully")
        return True
        
    except Exception as e:
        print(f"❌ Service startup error: {str(e)}")
        return False

def wait_for_services():
    """Wait for services to be ready"""
    print("Waiting for services to be ready...")
    
    services = {
        'SDP Controller': 'http://localhost:8001/health',
        'SDP Gateway': 'http://localhost:8002/health',
        'PKI CA': 'http://localhost:8003/health',
        'NAC Service': 'http://localhost:8004/health',
        'Microsegmentation': 'http://localhost:8005/health',
        'Integration API': 'http://localhost:8006/health',
        'Monitoring Dashboard': 'http://localhost:8080/health'
    }
    
    max_attempts = 30
    
    for service_name, health_url in services.items():
        print(f"  Checking {service_name}...")
        
        for attempt in range(max_attempts):
            try:
                response = requests.get(health_url, timeout=5)
                if response.status_code == 200:
                    print(f"  ✅ {service_name} is ready")
                    break
            except requests.exceptions.RequestException:
                pass
            
            if attempt < max_attempts - 1:
                time.sleep(2)
        else:
            print(f"  ⚠️  {service_name} not responding (may still be starting)")
    
    print("Service startup complete")

def initialize_pki():
    """Initialize PKI infrastructure"""
    print("Initializing PKI infrastructure...")
    
    try:
        # Wait for PKI CA to be ready
        for _ in range(30):
            try:
                response = requests.get('http://localhost:8003/health', timeout=5)
                if response.status_code == 200:
                    break
            except:
                pass
            time.sleep(2)
        
        # Get CA certificate
        response = requests.get('http://localhost:8003/api/ca/certificate')
        if response.status_code == 200:
            ca_data = response.json()
            
            # Save CA certificate
            with open('ca_certificate.pem', 'w') as f:
                f.write(ca_data['ca_certificate'])
            
            print("✅ PKI infrastructure initialized")
            print(f"   CA Subject: {ca_data['subject']}")
            print(f"   Valid until: {ca_data['not_after']}")
            return True
        else:
            print("❌ Failed to retrieve CA certificate")
            return False
            
    except Exception as e:
        print(f"❌ PKI initialization error: {str(e)}")
        return False

def create_default_policies():
    """Create default access policies"""
    print("Creating default access policies...")
    
    try:
        # Login as admin
        auth_data = {
            'username': 'admin',
            'password': 'zero-trust-admin',
            'device_info': {
                'name': 'setup-script',
                'type': 'management'
            }
        }
        
        response = requests.post(
            'http://localhost:8001/api/auth/login',
            json=auth_data,
            timeout=10
        )
        
        if response.status_code != 200:
            print("❌ Failed to authenticate with SDP Controller")
            return False
        
        auth_result = response.json()
        access_token = auth_result['access_token']
        headers = {'Authorization': f'Bearer {access_token}'}
        
        # Load default policies
        with open('config/security/policies.json', 'r') as f:
            policies_config = json.load(f)
        
        # Create each policy
        for policy in policies_config['default_policies']:
            response = requests.post(
                'http://localhost:8001/api/policies',
                json=policy,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 201:
                print(f"  ✅ Created policy: {policy['name']}")
            else:
                print(f"  ❌ Failed to create policy: {policy['name']}")
        
        print("✅ Default policies created")
        return True
        
    except Exception as e:
        print(f"❌ Policy creation error: {str(e)}")
        return False

def print_summary():
    """Print setup summary"""
    print("\n" + "="*60)
    print("ZERO TRUST NETWORK LAB - SETUP COMPLETE")
    print("="*60)
    print("\n🌐 Service Endpoints:")
    print("   • Monitoring Dashboard: http://localhost:8080")
    print("   • SDP Controller API:   http://localhost:8001")
    print("   • SDP Gateway API:      http://localhost:8002")
    print("   • PKI CA API:           http://localhost:8003")
    print("   • NAC Service API:      http://localhost:8004")
    print("   • Microsegmentation:    http://localhost:8005")
    print("   • Integration API:      http://localhost:8006")
    
    print("\n🔐 Default Credentials:")
    print("   • Admin Username: admin")
    print("   • Admin Password: zero-trust-admin")
    
    print("\n📁 Generated Files:")
    print("   • ca_certificate.pem - Root CA certificate")
    print("   • config/ - Configuration files")
    
    print("\n🚀 Next Steps:")
    print("   1. Open the monitoring dashboard: http://localhost:8080")
    print("   2. Review the architecture documentation in docs/")
    print("   3. Try the SDP client: python sdp/client/client.py admin zero-trust-admin")
    print("   4. Explore the API endpoints and create custom policies")
    
    print("\n⚠️  Note: This is a lab environment - do not use in production!")
    print("="*60)

def main():
    """Main setup function"""
    print("🔒 Zero Trust Network Lab Setup")
    print("================================\n")
    
    # Check if we're in the right directory
    if not os.path.exists('docker-compose.yml'):
        print("❌ Please run this script from the project root directory")
        sys.exit(1)
    
    # Create required directories
    os.makedirs('config/network', exist_ok=True)
    os.makedirs('config/security', exist_ok=True)
    os.makedirs('config/docker', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # Run setup steps
    steps = [
        ("Checking dependencies", check_dependencies),
        ("Creating config files", create_config_files),
        ("Building Docker images", build_docker_images),
        ("Starting services", start_services),
        ("Waiting for services", wait_for_services),
        ("Initializing PKI", initialize_pki),
        ("Creating default policies", create_default_policies)
    ]
    
    for step_name, step_func in steps:
        print(f"\n📋 {step_name}...")
        if not step_func():
            print(f"❌ Setup failed at step: {step_name}")
            print("\nTo troubleshoot:")
            print("  • Check Docker logs: docker-compose logs")
            print("  • Verify all services: docker-compose ps")
            print("  • Restart services: docker-compose restart")
            sys.exit(1)
    
    print_summary()

if __name__ == '__main__':
    main()
