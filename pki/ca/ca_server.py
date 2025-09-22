#!/usr/bin/env python3
"""
Zero Trust PKI Certificate Authority

This component implements a hierarchical PKI infrastructure for certificate-based
authentication throughout the zero trust network. It provides automated certificate
enrollment, lifecycle management, and revocation services.
"""

import os
import logging
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file
from flask_restful import Api, Resource
from flask_cors import CORS
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import sqlite3
import uuid
import base64
from io import BytesIO

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/pki_ca.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
api = Api(app)
CORS(app)

class CertificateAuthority:
    """Main Certificate Authority class managing the PKI hierarchy"""
    
    def __init__(self):
        self.ca_name = os.environ.get('CA_NAME', 'ZeroTrust-Root-CA')
        self.cert_dir = '/app/certificates'
        self.ca_private_key = None
        self.ca_certificate = None
        self.ca_serial_number = 1
        
        # Ensure certificate directory exists
        os.makedirs(self.cert_dir, exist_ok=True)
        
        # Initialize CA
        self.init_ca()
        self.init_database()
    
    def init_ca(self):
        """Initialize the Certificate Authority"""
        ca_key_path = os.path.join(self.cert_dir, 'ca_private_key.pem')
        ca_cert_path = os.path.join(self.cert_dir, 'ca_certificate.pem')
        
        if os.path.exists(ca_key_path) and os.path.exists(ca_cert_path):
            # Load existing CA
            self._load_ca()
            logger.info("Loaded existing Certificate Authority")
        else:
            # Create new CA
            self._create_ca()
            logger.info("Created new Certificate Authority")
    
    def _create_ca(self):
        """Create a new Certificate Authority"""
        # Generate CA private key
        self.ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        
        # Create CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Zero Trust Lab"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name),
        ])
        
        self.ca_certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ca_private_key.public_key()
        ).serial_number(
            1
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)  # 10 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                key_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.ca_private_key.public_key()),
            critical=False,
        ).sign(self.ca_private_key, hashes.SHA256())
        
        # Save CA private key
        ca_key_path = os.path.join(self.cert_dir, 'ca_private_key.pem')
        with open(ca_key_path, 'wb') as f:
            f.write(self.ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save CA certificate
        ca_cert_path = os.path.join(self.cert_dir, 'ca_certificate.pem')
        with open(ca_cert_path, 'wb') as f:
            f.write(self.ca_certificate.public_bytes(serialization.Encoding.PEM))
        
        # Set secure permissions
        os.chmod(ca_key_path, 0o600)
        os.chmod(ca_cert_path, 0o644)
    
    def _load_ca(self):
        """Load existing Certificate Authority"""
        # Load CA private key
        ca_key_path = os.path.join(self.cert_dir, 'ca_private_key.pem')
        with open(ca_key_path, 'rb') as f:
            self.ca_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        
        # Load CA certificate
        ca_cert_path = os.path.join(self.cert_dir, 'ca_certificate.pem')
        with open(ca_cert_path, 'rb') as f:
            self.ca_certificate = x509.load_pem_x509_certificate(f.read())
    
    def init_database(self):
        """Initialize certificate database"""
        with sqlite3.connect('pki_ca.db') as conn:
            cursor = conn.cursor()
            
            # Certificates table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS certificates (
                    id TEXT PRIMARY KEY,
                    serial_number INTEGER UNIQUE,
                    subject_dn TEXT,
                    issuer_dn TEXT,
                    certificate_type TEXT,
                    not_before TIMESTAMP,
                    not_after TIMESTAMP,
                    status TEXT DEFAULT 'active',
                    certificate_pem TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    revoked_at TIMESTAMP,
                    revocation_reason TEXT
                )
            ''')
            
            # Certificate requests table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS certificate_requests (
                    id TEXT PRIMARY KEY,
                    requester_id TEXT,
                    csr_pem TEXT,
                    certificate_type TEXT,
                    status TEXT DEFAULT 'pending',
                    approved_by TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    processed_at TIMESTAMP
                )
            ''')
            
            # CRL entries table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS crl_entries (
                    serial_number INTEGER PRIMARY KEY,
                    revocation_date TIMESTAMP,
                    revocation_reason INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
    
    def get_next_serial_number(self):
        """Get next serial number for certificate"""
        with sqlite3.connect('pki_ca.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT MAX(serial_number) FROM certificates')
            result = cursor.fetchone()[0]
            return (result + 1) if result else 2  # Start from 2 (CA is 1)
    
    def issue_certificate(self, csr_pem, certificate_type='client', validity_days=365):
        """Issue a certificate from CSR"""
        try:
            # Parse CSR
            csr = x509.load_pem_x509_csr(csr_pem.encode())
            
            # Verify CSR signature
            if not csr.is_signature_valid:
                raise ValueError("Invalid CSR signature")
            
            # Get next serial number
            serial_number = self.get_next_serial_number()
            
            # Build certificate
            cert_builder = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                self.ca_certificate.subject
            ).public_key(
                csr.public_key()
            ).serial_number(
                serial_number
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=validity_days)
            )
            
            # Add extensions based on certificate type
            if certificate_type == 'client':
                cert_builder = cert_builder.add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=True,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        content_commitment=True,
                        data_encipherment=False,
                        encipher_only=False,
                        decipher_only=False
                    ),
                    critical=True,
                ).add_extension(
                    x509.ExtendedKeyUsage([
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                        x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION
                    ]),
                    critical=True,
                )
            elif certificate_type == 'server':
                cert_builder = cert_builder.add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=True,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        content_commitment=False,
                        data_encipherment=False,
                        encipher_only=False,
                        decipher_only=False
                    ),
                    critical=True,
                ).add_extension(
                    x509.ExtendedKeyUsage([
                        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
                    ]),
                    critical=True,
                )
            
            # Add Subject Key Identifier
            cert_builder = cert_builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False,
            )
            
            # Add Authority Key Identifier
            cert_builder = cert_builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_private_key.public_key()),
                critical=False,
            )
            
            # Sign certificate
            certificate = cert_builder.sign(self.ca_private_key, hashes.SHA256())
            
            # Store in database
            cert_id = str(uuid.uuid4())
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
            
            with sqlite3.connect('pki_ca.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO certificates 
                    (id, serial_number, subject_dn, issuer_dn, certificate_type, 
                     not_before, not_after, certificate_pem)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cert_id,
                    serial_number,
                    certificate.subject.rfc4514_string(),
                    certificate.issuer.rfc4514_string(),
                    certificate_type,
                    certificate.not_valid_before,
                    certificate.not_valid_after,
                    cert_pem
                ))
                conn.commit()
            
            logger.info(f"Issued {certificate_type} certificate with serial {serial_number}")
            
            return {
                'certificate_id': cert_id,
                'serial_number': serial_number,
                'certificate_pem': cert_pem,
                'not_before': certificate.not_valid_before.isoformat(),
                'not_after': certificate.not_valid_after.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Certificate issuance failed: {str(e)}")
            raise
    
    def revoke_certificate(self, serial_number, reason='unspecified'):
        """Revoke a certificate"""
        try:
            reason_codes = {
                'unspecified': 0,
                'key_compromise': 1,
                'ca_compromise': 2,
                'affiliation_changed': 3,
                'superseded': 4,
                'cessation_of_operation': 5,
                'certificate_hold': 6,
                'privilege_withdrawn': 9,
                'aa_compromise': 10
            }
            
            reason_code = reason_codes.get(reason, 0)
            
            with sqlite3.connect('pki_ca.db') as conn:
                cursor = conn.cursor()
                
                # Update certificate status
                cursor.execute('''
                    UPDATE certificates 
                    SET status = 'revoked', revoked_at = CURRENT_TIMESTAMP, revocation_reason = ?
                    WHERE serial_number = ?
                ''', (reason, serial_number))
                
                # Add to CRL entries
                cursor.execute('''
                    INSERT OR REPLACE INTO crl_entries 
                    (serial_number, revocation_date, revocation_reason)
                    VALUES (?, CURRENT_TIMESTAMP, ?)
                ''', (serial_number, reason_code))
                
                conn.commit()
            
            logger.info(f"Revoked certificate with serial {serial_number}")
            return True
            
        except Exception as e:
            logger.error(f"Certificate revocation failed: {str(e)}")
            return False
    
    def generate_crl(self):
        """Generate Certificate Revocation List"""
        try:
            with sqlite3.connect('pki_ca.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT serial_number, revocation_date, revocation_reason 
                    FROM crl_entries
                ''')
                revoked_certs = cursor.fetchall()
            
            # Build CRL
            crl_builder = x509.CertificateRevocationListBuilder().issuer_name(
                self.ca_certificate.subject
            ).last_update(
                datetime.utcnow()
            ).next_update(
                datetime.utcnow() + timedelta(days=7)  # Weekly CRL updates
            )
            
            # Add revoked certificates
            for serial, revocation_date, reason_code in revoked_certs:
                revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                    serial
                ).revocation_date(
                    datetime.fromisoformat(revocation_date.replace('Z', '+00:00'))
                ).add_extension(
                    x509.CRLReason(x509.ReasonFlags(reason_code)),
                    critical=False
                ).build()
                
                crl_builder = crl_builder.add_revoked_certificate(revoked_cert)
            
            # Sign CRL
            crl = crl_builder.sign(self.ca_private_key, hashes.SHA256())
            
            return crl.public_bytes(serialization.Encoding.PEM)
            
        except Exception as e:
            logger.error(f"CRL generation failed: {str(e)}")
            raise

# Initialize CA
ca = CertificateAuthority()

class CertificateResource(Resource):
    """Handles certificate operations"""
    
    def post(self):
        """Issue new certificate from CSR"""
        try:
            data = request.get_json()
            
            if 'csr' not in data:
                return {'error': 'CSR required'}, 400
            
            cert_type = data.get('type', 'client')
            validity_days = data.get('validity_days', 365)
            
            # Issue certificate
            result = ca.issue_certificate(data['csr'], cert_type, validity_days)
            
            return result, 201
            
        except Exception as e:
            logger.error(f"Certificate issuance error: {str(e)}")
            return {'error': 'Certificate issuance failed'}, 500
    
    def get(self, serial_number=None):
        """Get certificate by serial number"""
        try:
            if not serial_number:
                return {'error': 'Serial number required'}, 400
            
            with sqlite3.connect('pki_ca.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT certificate_pem, status, not_before, not_after 
                    FROM certificates WHERE serial_number = ?
                ''', (serial_number,))
                
                result = cursor.fetchone()
                if not result:
                    return {'error': 'Certificate not found'}, 404
                
                cert_pem, status, not_before, not_after = result
                
                return {
                    'serial_number': serial_number,
                    'certificate_pem': cert_pem,
                    'status': status,
                    'not_before': not_before,
                    'not_after': not_after
                }, 200
                
        except Exception as e:
            logger.error(f"Certificate retrieval error: {str(e)}")
            return {'error': 'Certificate retrieval failed'}, 500
    
    def delete(self, serial_number):
        """Revoke certificate"""
        try:
            data = request.get_json() or {}
            reason = data.get('reason', 'unspecified')
            
            if ca.revoke_certificate(int(serial_number), reason):
                return {'message': 'Certificate revoked successfully'}, 200
            else:
                return {'error': 'Certificate revocation failed'}, 500
                
        except Exception as e:
            logger.error(f"Certificate revocation error: {str(e)}")
            return {'error': 'Certificate revocation failed'}, 500

class CACertificateResource(Resource):
    """Provides CA certificate"""
    
    def get(self):
        """Get CA certificate"""
        try:
            ca_cert_pem = ca.ca_certificate.public_bytes(serialization.Encoding.PEM).decode()
            
            return {
                'ca_certificate': ca_cert_pem,
                'subject': ca.ca_certificate.subject.rfc4514_string(),
                'not_before': ca.ca_certificate.not_valid_before.isoformat(),
                'not_after': ca.ca_certificate.not_valid_after.isoformat(),
                'serial_number': ca.ca_certificate.serial_number
            }, 200
            
        except Exception as e:
            logger.error(f"CA certificate retrieval error: {str(e)}")
            return {'error': 'CA certificate retrieval failed'}, 500

class CRLResource(Resource):
    """Provides Certificate Revocation List"""
    
    def get(self):
        """Get current CRL"""
        try:
            crl_pem = ca.generate_crl()
            
            # Return as downloadable file
            return send_file(
                BytesIO(crl_pem),
                as_attachment=True,
                download_name='ca.crl',
                mimetype='application/pkix-crl'
            )
            
        except Exception as e:
            logger.error(f"CRL generation error: {str(e)}")
            return {'error': 'CRL generation failed'}, 500

# Register API endpoints
api.add_resource(CertificateResource, '/api/certificates', '/api/certificates/<int:serial_number>')
api.add_resource(CACertificateResource, '/api/ca/certificate')
api.add_resource(CRLResource, '/api/ca/crl')

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return {
        'status': 'healthy', 
        'service': 'pki-ca', 
        'ca_name': ca.ca_name,
        'timestamp': datetime.utcnow().isoformat()
    }

@app.route('/api/ca/status')
def ca_status():
    """Get CA status and statistics"""
    try:
        with sqlite3.connect('pki_ca.db') as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM certificates WHERE status = "active"')
            active_certs = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM certificates WHERE status = "revoked"')
            revoked_certs = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM certificate_requests WHERE status = "pending"')
            pending_requests = cursor.fetchone()[0]
        
        return {
            'status': 'operational',
            'ca_name': ca.ca_name,
            'statistics': {
                'active_certificates': active_certs,
                'revoked_certificates': revoked_certs,
                'pending_requests': pending_requests
            },
            'ca_certificate': {
                'subject': ca.ca_certificate.subject.rfc4514_string(),
                'not_before': ca.ca_certificate.not_valid_before.isoformat(),
                'not_after': ca.ca_certificate.not_valid_after.isoformat()
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Status retrieval error: {str(e)}")
        return {'error': 'Status retrieval failed'}, 500

if __name__ == '__main__':
    logger.info("Starting PKI Certificate Authority...")
    app.run(host='0.0.0.0', port=8003, debug=True)
