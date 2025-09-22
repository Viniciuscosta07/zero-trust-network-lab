#!/usr/bin/env python3
"""
Zero Trust PKI Enrollment Service

This service provides automated certificate enrollment capabilities,
including CSR generation, certificate request processing, and
automated renewal for devices and users.
"""

import os
import logging
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import requests
import json
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CertificateEnrollment:
    """Handles certificate enrollment operations"""
    
    def __init__(self, ca_url='http://pki-ca:8003'):
        self.ca_url = ca_url
        self.ca_certificate = None
        self.load_ca_certificate()
    
    def load_ca_certificate(self):
        """Load CA certificate for validation"""
        try:
            response = requests.get(f'{self.ca_url}/api/ca/certificate', timeout=10)
            if response.status_code == 200:
                ca_data = response.json()
                self.ca_certificate = x509.load_pem_x509_certificate(
                    ca_data['ca_certificate'].encode()
                )
                logger.info("Loaded CA certificate successfully")
            else:
                logger.error("Failed to load CA certificate")
        except Exception as e:
            logger.error(f"Error loading CA certificate: {str(e)}")
    
    def generate_key_pair(self, key_size=2048):
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        return private_key
    
    def create_csr(self, private_key, subject_info, cert_type='client'):
        """Create Certificate Signing Request"""
        try:
            # Build subject name
            subject_components = []
            
            if 'country' in subject_info:
                subject_components.append(x509.NameAttribute(NameOID.COUNTRY_NAME, subject_info['country']))
            if 'state' in subject_info:
                subject_components.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_info['state']))
            if 'city' in subject_info:
                subject_components.append(x509.NameAttribute(NameOID.LOCALITY_NAME, subject_info['city']))
            if 'organization' in subject_info:
                subject_components.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_info['organization']))
            if 'organizational_unit' in subject_info:
                subject_components.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject_info['organizational_unit']))
            if 'common_name' in subject_info:
                subject_components.append(x509.NameAttribute(NameOID.COMMON_NAME, subject_info['common_name']))
            if 'email' in subject_info:
                subject_components.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, subject_info['email']))
            
            subject = x509.Name(subject_components)
            
            # Build CSR
            csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
            
            # Add extensions based on certificate type
            if cert_type == 'client':
                # Add Subject Alternative Name for client certificates
                san_list = []
                if 'email' in subject_info:
                    san_list.append(x509.RFC822Name(subject_info['email']))
                if 'dns_names' in subject_info:
                    for dns_name in subject_info['dns_names']:
                        san_list.append(x509.DNSName(dns_name))
                
                if san_list:
                    csr_builder = csr_builder.add_extension(
                        x509.SubjectAlternativeName(san_list),
                        critical=False
                    )
            
            elif cert_type == 'server':
                # Add Subject Alternative Name for server certificates
                san_list = []
                if 'dns_names' in subject_info:
                    for dns_name in subject_info['dns_names']:
                        san_list.append(x509.DNSName(dns_name))
                if 'ip_addresses' in subject_info:
                    for ip_addr in subject_info['ip_addresses']:
                        san_list.append(x509.IPAddress(ip_addr))
                
                if san_list:
                    csr_builder = csr_builder.add_extension(
                        x509.SubjectAlternativeName(san_list),
                        critical=False
                    )
            
            # Sign CSR
            csr = csr_builder.sign(private_key, hashes.SHA256())
            
            return csr
            
        except Exception as e:
            logger.error(f"CSR creation failed: {str(e)}")
            raise
    
    def submit_certificate_request(self, csr, cert_type='client', validity_days=365):
        """Submit certificate request to CA"""
        try:
            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
            
            request_data = {
                'csr': csr_pem,
                'type': cert_type,
                'validity_days': validity_days
            }
            
            response = requests.post(
                f'{self.ca_url}/api/certificates',
                json=request_data,
                timeout=30
            )
            
            if response.status_code == 201:
                return response.json()
            else:
                error_msg = response.json().get('error', 'Unknown error')
                raise Exception(f"Certificate request failed: {error_msg}")
                
        except Exception as e:
            logger.error(f"Certificate request submission failed: {str(e)}")
            raise
    
    def enroll_device_certificate(self, device_info):
        """Enroll device certificate"""
        try:
            # Generate key pair for device
            private_key = self.generate_key_pair()
            
            # Prepare subject information
            subject_info = {
                'country': 'US',
                'state': 'CA',
                'city': 'San Francisco',
                'organization': 'Zero Trust Lab',
                'organizational_unit': 'Devices',
                'common_name': device_info.get('device_name', f"device-{uuid.uuid4().hex[:8]}"),
                'email': f"{device_info.get('device_id', 'unknown')}@zerotrust.lab"
            }
            
            # Add device-specific DNS names if provided
            if 'hostname' in device_info:
                subject_info['dns_names'] = [device_info['hostname']]
            
            # Create CSR
            csr = self.create_csr(private_key, subject_info, 'client')
            
            # Submit certificate request
            cert_result = self.submit_certificate_request(csr, 'client', 365)
            
            # Prepare enrollment result
            enrollment_result = {
                'device_id': device_info.get('device_id'),
                'certificate_id': cert_result['certificate_id'],
                'serial_number': cert_result['serial_number'],
                'private_key_pem': private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode(),
                'certificate_pem': cert_result['certificate_pem'],
                'not_before': cert_result['not_before'],
                'not_after': cert_result['not_after'],
                'ca_certificate_pem': self.ca_certificate.public_bytes(
                    serialization.Encoding.PEM
                ).decode() if self.ca_certificate else None
            }
            
            logger.info(f"Device certificate enrolled for {subject_info['common_name']}")
            return enrollment_result
            
        except Exception as e:
            logger.error(f"Device certificate enrollment failed: {str(e)}")
            raise
    
    def enroll_user_certificate(self, user_info):
        """Enroll user certificate"""
        try:
            # Generate key pair for user
            private_key = self.generate_key_pair()
            
            # Prepare subject information
            subject_info = {
                'country': 'US',
                'state': 'CA',
                'city': 'San Francisco',
                'organization': 'Zero Trust Lab',
                'organizational_unit': 'Users',
                'common_name': user_info.get('full_name', user_info.get('username', 'Unknown User')),
                'email': user_info.get('email', f"{user_info.get('username', 'unknown')}@zerotrust.lab")
            }
            
            # Create CSR
            csr = self.create_csr(private_key, subject_info, 'client')
            
            # Submit certificate request
            cert_result = self.submit_certificate_request(csr, 'client', 365)
            
            # Prepare enrollment result
            enrollment_result = {
                'user_id': user_info.get('user_id'),
                'username': user_info.get('username'),
                'certificate_id': cert_result['certificate_id'],
                'serial_number': cert_result['serial_number'],
                'private_key_pem': private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode(),
                'certificate_pem': cert_result['certificate_pem'],
                'not_before': cert_result['not_before'],
                'not_after': cert_result['not_after'],
                'ca_certificate_pem': self.ca_certificate.public_bytes(
                    serialization.Encoding.PEM
                ).decode() if self.ca_certificate else None
            }
            
            logger.info(f"User certificate enrolled for {subject_info['common_name']}")
            return enrollment_result
            
        except Exception as e:
            logger.error(f"User certificate enrollment failed: {str(e)}")
            raise
    
    def enroll_server_certificate(self, server_info):
        """Enroll server certificate"""
        try:
            # Generate key pair for server
            private_key = self.generate_key_pair(key_size=2048)
            
            # Prepare subject information
            subject_info = {
                'country': 'US',
                'state': 'CA',
                'city': 'San Francisco',
                'organization': 'Zero Trust Lab',
                'organizational_unit': 'Servers',
                'common_name': server_info.get('hostname', server_info.get('service_name', 'Unknown Server'))
            }
            
            # Add DNS names and IP addresses
            if 'dns_names' in server_info:
                subject_info['dns_names'] = server_info['dns_names']
            elif 'hostname' in server_info:
                subject_info['dns_names'] = [server_info['hostname']]
            
            if 'ip_addresses' in server_info:
                from ipaddress import ip_address
                subject_info['ip_addresses'] = [ip_address(ip) for ip in server_info['ip_addresses']]
            
            # Create CSR
            csr = self.create_csr(private_key, subject_info, 'server')
            
            # Submit certificate request
            cert_result = self.submit_certificate_request(csr, 'server', 730)  # 2 years for servers
            
            # Prepare enrollment result
            enrollment_result = {
                'server_id': server_info.get('server_id'),
                'hostname': server_info.get('hostname'),
                'certificate_id': cert_result['certificate_id'],
                'serial_number': cert_result['serial_number'],
                'private_key_pem': private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode(),
                'certificate_pem': cert_result['certificate_pem'],
                'not_before': cert_result['not_before'],
                'not_after': cert_result['not_after'],
                'ca_certificate_pem': self.ca_certificate.public_bytes(
                    serialization.Encoding.PEM
                ).decode() if self.ca_certificate else None
            }
            
            logger.info(f"Server certificate enrolled for {subject_info['common_name']}")
            return enrollment_result
            
        except Exception as e:
            logger.error(f"Server certificate enrollment failed: {str(e)}")
            raise
    
    def check_certificate_renewal(self, certificate_pem, renewal_threshold_days=30):
        """Check if certificate needs renewal"""
        try:
            certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
            
            # Calculate days until expiration
            days_until_expiry = (certificate.not_valid_after - datetime.utcnow()).days
            
            return {
                'needs_renewal': days_until_expiry <= renewal_threshold_days,
                'days_until_expiry': days_until_expiry,
                'not_after': certificate.not_valid_after.isoformat(),
                'serial_number': certificate.serial_number
            }
            
        except Exception as e:
            logger.error(f"Certificate renewal check failed: {str(e)}")
            raise
    
    def renew_certificate(self, old_certificate_pem, cert_type='client'):
        """Renew an existing certificate"""
        try:
            old_certificate = x509.load_pem_x509_certificate(old_certificate_pem.encode())
            
            # Generate new key pair
            private_key = self.generate_key_pair()
            
            # Extract subject information from old certificate
            subject_info = {}
            for attribute in old_certificate.subject:
                if attribute.oid == NameOID.COUNTRY_NAME:
                    subject_info['country'] = attribute.value
                elif attribute.oid == NameOID.STATE_OR_PROVINCE_NAME:
                    subject_info['state'] = attribute.value
                elif attribute.oid == NameOID.LOCALITY_NAME:
                    subject_info['city'] = attribute.value
                elif attribute.oid == NameOID.ORGANIZATION_NAME:
                    subject_info['organization'] = attribute.value
                elif attribute.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                    subject_info['organizational_unit'] = attribute.value
                elif attribute.oid == NameOID.COMMON_NAME:
                    subject_info['common_name'] = attribute.value
                elif attribute.oid == NameOID.EMAIL_ADDRESS:
                    subject_info['email'] = attribute.value
            
            # Extract SAN information if present
            try:
                san_ext = old_certificate.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                dns_names = []
                ip_addresses = []
                
                for name in san_ext.value:
                    if isinstance(name, x509.DNSName):
                        dns_names.append(name.value)
                    elif isinstance(name, x509.IPAddress):
                        ip_addresses.append(name.value)
                
                if dns_names:
                    subject_info['dns_names'] = dns_names
                if ip_addresses:
                    subject_info['ip_addresses'] = ip_addresses
                    
            except x509.ExtensionNotFound:
                pass
            
            # Create new CSR
            csr = self.create_csr(private_key, subject_info, cert_type)
            
            # Submit certificate request
            cert_result = self.submit_certificate_request(csr, cert_type, 365)
            
            # Revoke old certificate
            try:
                requests.delete(
                    f'{self.ca_url}/api/certificates/{old_certificate.serial_number}',
                    json={'reason': 'superseded'},
                    timeout=10
                )
            except:
                logger.warning(f"Failed to revoke old certificate {old_certificate.serial_number}")
            
            # Prepare renewal result
            renewal_result = {
                'old_serial_number': old_certificate.serial_number,
                'new_certificate_id': cert_result['certificate_id'],
                'new_serial_number': cert_result['serial_number'],
                'private_key_pem': private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode(),
                'certificate_pem': cert_result['certificate_pem'],
                'not_before': cert_result['not_before'],
                'not_after': cert_result['not_after']
            }
            
            logger.info(f"Certificate renewed: {old_certificate.serial_number} -> {cert_result['serial_number']}")
            return renewal_result
            
        except Exception as e:
            logger.error(f"Certificate renewal failed: {str(e)}")
            raise

# Example usage functions
def enroll_demo_certificates():
    """Enroll demo certificates for testing"""
    enrollment = CertificateEnrollment()
    
    # Enroll device certificate
    device_info = {
        'device_id': 'demo-device-001',
        'device_name': 'demo-workstation',
        'hostname': 'demo-ws.zerotrust.lab'
    }
    
    try:
        device_cert = enrollment.enroll_device_certificate(device_info)
        print(f"Device certificate enrolled: Serial {device_cert['serial_number']}")
        
        # Save device certificate and key
        with open('device_cert.pem', 'w') as f:
            f.write(device_cert['certificate_pem'])
        with open('device_key.pem', 'w') as f:
            f.write(device_cert['private_key_pem'])
        
    except Exception as e:
        print(f"Device enrollment failed: {e}")
    
    # Enroll user certificate
    user_info = {
        'user_id': 'demo-user-001',
        'username': 'demo.user',
        'full_name': 'Demo User',
        'email': 'demo.user@zerotrust.lab'
    }
    
    try:
        user_cert = enrollment.enroll_user_certificate(user_info)
        print(f"User certificate enrolled: Serial {user_cert['serial_number']}")
        
        # Save user certificate and key
        with open('user_cert.pem', 'w') as f:
            f.write(user_cert['certificate_pem'])
        with open('user_key.pem', 'w') as f:
            f.write(user_cert['private_key_pem'])
        
    except Exception as e:
        print(f"User enrollment failed: {e}")
    
    # Enroll server certificate
    server_info = {
        'server_id': 'demo-server-001',
        'hostname': 'api.zerotrust.lab',
        'service_name': 'API Server',
        'dns_names': ['api.zerotrust.lab', 'api-internal.zerotrust.lab'],
        'ip_addresses': ['10.0.1.100']
    }
    
    try:
        server_cert = enrollment.enroll_server_certificate(server_info)
        print(f"Server certificate enrolled: Serial {server_cert['serial_number']}")
        
        # Save server certificate and key
        with open('server_cert.pem', 'w') as f:
            f.write(server_cert['certificate_pem'])
        with open('server_key.pem', 'w') as f:
            f.write(server_cert['private_key_pem'])
        
    except Exception as e:
        print(f"Server enrollment failed: {e}")

if __name__ == '__main__':
    print("PKI Enrollment Service Demo")
    enroll_demo_certificates()
