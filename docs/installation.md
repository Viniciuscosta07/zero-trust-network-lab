# Zero Trust Network Installation Guide

## Prerequisites

### System Requirements
- **Operating System**: Linux, macOS, or Windows 10/11
- **RAM**: Minimum 8GB, Recommended 16GB
- **Storage**: 20GB free space
- **Network**: Internet connection for Docker image downloads

### Required Software

#### Docker and Docker Compose
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install docker.io docker-compose

# CentOS/RHEL
sudo yum install docker docker-compose

# macOS (using Homebrew)
brew install docker docker-compose

# Windows
# Download Docker Desktop from https://www.docker.com/products/docker-desktop
```

#### Python 3.8+ (for client tools)
```bash
# Ubuntu/Debian
sudo apt install python3 python3-pip

# CentOS/RHEL
sudo yum install python3 python3-pip

# macOS
brew install python3

# Windows
# Download from https://www.python.org/downloads/
```

#### Node.js 16+ (for dashboard development)
```bash
# Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# macOS
brew install node

# Windows
# Download from https://nodejs.org/
```

## Quick Start Installation

### 1. Clone the Repository
```bash
git clone https://github.com/your-org/zero-trust-network-lab.git
cd zero-trust-network-lab
```

### 2. Run the Setup Script
```bash
# Make the script executable
chmod +x scripts/init-project.py

# Run the automated setup
python3 scripts/init-project.py
```

The setup script will:
- Check dependencies
- Create configuration files
- Build Docker images
- Start all services
- Initialize PKI infrastructure
- Create default policies

### 3. Access the Dashboard
Open your web browser and navigate to:
```
http://localhost:8080
```

Default credentials:
- Username: `admin`
- Password: `zero-trust-admin`

## Manual Installation

If you prefer to install components manually or need to customize the setup:

### 1. Environment Preparation

#### Create Project Structure
```bash
mkdir zero-trust-lab
cd zero-trust-lab

# Create necessary directories
mkdir -p {config/{network,security,docker},logs,docs}
mkdir -p {sdp/{controller,gateway,client},pki/{ca,certificates,enrollment}}
mkdir -p {nac/{compliance,enforcement,remediation},microsegmentation/{zones,policies,firewall}}
mkdir -p {integration/{api,events,policies},monitoring/{dashboard,analytics,logging}}
```

#### Install Python Dependencies
```bash
pip3 install -r requirements.txt
```

#### Install Node.js Dependencies
```bash
npm install
```

### 2. Configuration Setup

#### Network Configuration
Create `config/network/zones.json`:
```json
{
  "zones": {
    "dmz": {
      "name": "DMZ Zone",
      "subnet": "10.1.0.0/24",
      "security_level": "medium"
    },
    "internal": {
      "name": "Internal Zone", 
      "subnet": "10.2.0.0/24",
      "security_level": "high"
    },
    "user_devices": {
      "name": "User Devices",
      "subnet": "10.3.0.0/24", 
      "security_level": "medium"
    },
    "servers": {
      "name": "Server Zone",
      "subnet": "10.4.0.0/24",
      "security_level": "high"
    },
    "management": {
      "name": "Management Zone",
      "subnet": "10.5.0.0/24",
      "security_level": "critical"
    }
  }
}
```

#### Security Policies
Create `config/security/policies.json`:
```json
{
  "default_policies": [
    {
      "name": "Allow User to DMZ Web",
      "source_zone": "user_devices",
      "destination_zone": "dmz",
      "protocol": "tcp",
      "port_range": "80,443",
      "action": "allow",
      "conditions": {
        "require_authentication": true,
        "require_device_compliance": true
      }
    }
  ]
}
```

### 3. Service Deployment

#### Using Docker Compose
```bash
# Build all images
docker-compose build

# Start core services
docker-compose up -d postgres redis

# Wait for databases to be ready
sleep 30

# Start application services
docker-compose up -d
```

#### Individual Service Startup
```bash
# Start PKI CA first
docker-compose up -d pki-ca

# Start SDP Controller
docker-compose up -d sdp-controller

# Start remaining services
docker-compose up -d sdp-gateway nac-service microseg-engine

# Start integration and monitoring
docker-compose up -d integration-api monitoring-dashboard
```

### 4. Service Verification

#### Check Service Health
```bash
# Check all services
docker-compose ps

# Check individual service logs
docker-compose logs sdp-controller
docker-compose logs pki-ca
docker-compose logs monitoring-dashboard
```

#### Health Check Endpoints
```bash
# SDP Controller
curl http://localhost:8001/health

# SDP Gateway  
curl http://localhost:8002/health

# PKI CA
curl http://localhost:8003/health

# NAC Service
curl http://localhost:8004/health

# Microsegmentation
curl http://localhost:8005/health

# Integration API
curl http://localhost:8006/health

# Monitoring Dashboard
curl http://localhost:8080/health
```

## Configuration

### Environment Variables

Create `.env` file in project root:
```bash
# JWT Secret Keys
JWT_SECRET_KEY=your-secret-key-change-in-production
SDP_JWT_SECRET=your-sdp-secret-key

# Database Configuration
POSTGRES_DB=zerotrust
POSTGRES_USER=ztuser  
POSTGRES_PASSWORD=secure-password-change-me

# Service URLs (for development)
SDP_CONTROLLER_URL=http://localhost:8001
SDP_GATEWAY_URL=http://localhost:8002
PKI_CA_URL=http://localhost:8003
NAC_SERVICE_URL=http://localhost:8004
MICROSEG_ENGINE_URL=http://localhost:8005
INTEGRATION_API_URL=http://localhost:8006

# Monitoring
LOG_LEVEL=INFO
METRICS_RETENTION_DAYS=30
```

### SSL/TLS Certificates

For production deployment, configure proper SSL certificates:

#### Generate Self-Signed Certificates (Development Only)
```bash
# Create certificate directory
mkdir -p config/ssl

# Generate CA private key
openssl genrsa -out config/ssl/ca-key.pem 4096

# Generate CA certificate
openssl req -new -x509 -days 3650 -key config/ssl/ca-key.pem -out config/ssl/ca-cert.pem -subj "/CN=Zero Trust Lab CA"

# Generate server private key
openssl genrsa -out config/ssl/server-key.pem 2048

# Generate server certificate request
openssl req -new -key config/ssl/server-key.pem -out config/ssl/server-csr.pem -subj "/CN=localhost"

# Sign server certificate
openssl x509 -req -days 365 -in config/ssl/server-csr.pem -CA config/ssl/ca-cert.pem -CAkey config/ssl/ca-key.pem -CAcreateserial -out config/ssl/server-cert.pem
```

#### Update Docker Compose for SSL
```yaml
# Add to docker-compose.yml
volumes:
  - ./config/ssl:/app/ssl:ro

environment:
  - SSL_CERT_PATH=/app/ssl/server-cert.pem
  - SSL_KEY_PATH=/app/ssl/server-key.pem
  - CA_CERT_PATH=/app/ssl/ca-cert.pem
```

## Network Configuration

### Firewall Rules

#### Ubuntu/Debian (ufw)
```bash
# Allow SSH
sudo ufw allow ssh

# Allow web traffic
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow Zero Trust services
sudo ufw allow 8080/tcp  # Dashboard
sudo ufw allow 8001/tcp  # SDP Controller
sudo ufw allow 8002/tcp  # SDP Gateway
sudo ufw allow 51820/udp # WireGuard

# Enable firewall
sudo ufw enable
```

#### CentOS/RHEL (firewalld)
```bash
# Add services to firewall
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --permanent --add-port=8001/tcp
sudo firewall-cmd --permanent --add-port=8002/tcp
sudo firewall-cmd --permanent --add-port=51820/udp

# Reload firewall
sudo firewall-cmd --reload
```

### Network Interfaces

#### WireGuard Configuration
The SDP Gateway automatically configures WireGuard, but you can customize:

```bash
# Edit WireGuard configuration
sudo nano /etc/wireguard/wg0.conf

# Restart WireGuard
sudo systemctl restart wg-quick@wg0
```

## Database Setup

### PostgreSQL Configuration

#### Production Database Setup
```bash
# Install PostgreSQL
sudo apt install postgresql postgresql-contrib

# Create database and user
sudo -u postgres psql
CREATE DATABASE zerotrust;
CREATE USER ztuser WITH ENCRYPTED PASSWORD 'secure-password';
GRANT ALL PRIVILEGES ON DATABASE zerotrust TO ztuser;
\q
```

#### Database Migration
```bash
# Run database migrations for each service
docker-compose exec sdp-controller python migrate.py
docker-compose exec pki-ca python migrate.py
docker-compose exec nac-service python migrate.py
```

### Redis Configuration

#### Redis Persistence
```bash
# Edit redis configuration
sudo nano /etc/redis/redis.conf

# Enable persistence
save 900 1
save 300 10
save 60 10000

# Restart Redis
sudo systemctl restart redis
```

## Troubleshooting

### Common Issues

#### Services Not Starting
```bash
# Check Docker daemon
sudo systemctl status docker

# Check logs
docker-compose logs service-name

# Restart services
docker-compose restart service-name
```

#### Port Conflicts
```bash
# Check port usage
netstat -tulpn | grep :8080

# Kill processes using ports
sudo kill -9 $(lsof -t -i:8080)
```

#### Permission Issues
```bash
# Fix Docker permissions
sudo usermod -aG docker $USER
newgrp docker

# Fix file permissions
sudo chown -R $USER:$USER .
```

#### Database Connection Issues
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Test database connection
docker-compose exec postgres psql -U ztuser -d zerotrust -c "SELECT 1;"
```

### Log Analysis

#### Service Logs Location
```bash
# Application logs
tail -f logs/sdp_controller.log
tail -f logs/pki_ca.log
tail -f logs/nac_service.log

# Docker logs
docker-compose logs -f service-name

# System logs
journalctl -u docker -f
```

#### Log Levels
- **DEBUG**: Detailed diagnostic information
- **INFO**: General operational messages
- **WARNING**: Warning messages for potential issues
- **ERROR**: Error messages for failed operations
- **CRITICAL**: Critical errors requiring immediate attention

## Performance Tuning

### Resource Allocation

#### Docker Resource Limits
```yaml
# Add to docker-compose.yml
services:
  sdp-controller:
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
```

#### Database Optimization
```bash
# PostgreSQL tuning
echo "shared_buffers = 256MB" >> /etc/postgresql/13/main/postgresql.conf
echo "effective_cache_size = 1GB" >> /etc/postgresql/13/main/postgresql.conf
echo "work_mem = 4MB" >> /etc/postgresql/13/main/postgresql.conf
```

### Monitoring Setup

#### Prometheus Integration
```yaml
# Add to docker-compose.yml
prometheus:
  image: prom/prometheus
  ports:
    - "9090:9090"
  volumes:
    - ./config/prometheus.yml:/etc/prometheus/prometheus.yml
```

#### Grafana Dashboard
```yaml
grafana:
  image: grafana/grafana
  ports:
    - "3000:3000"
  environment:
    - GF_SECURITY_ADMIN_PASSWORD=admin
```

## Security Hardening

### Production Security Checklist

- [ ] Change all default passwords
- [ ] Generate unique JWT secret keys
- [ ] Configure proper SSL/TLS certificates
- [ ] Enable firewall with minimal required ports
- [ ] Configure log rotation and retention
- [ ] Set up automated backups
- [ ] Enable audit logging
- [ ] Configure intrusion detection
- [ ] Implement network segmentation
- [ ] Regular security updates

### Backup Strategy

#### Database Backup
```bash
# Automated backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
docker-compose exec postgres pg_dump -U ztuser zerotrust > backup_${DATE}.sql
```

#### Configuration Backup
```bash
# Backup configuration
tar -czf config_backup_$(date +%Y%m%d).tar.gz config/ logs/
```

This completes the installation guide. For additional help, consult the troubleshooting section or check the project documentation.
