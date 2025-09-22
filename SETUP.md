# Zero Trust Network - Complete Setup Guide

## 🚀 Quick Start (Recommended)

### Prerequisites
- Docker and Docker Compose installed
- Python 3.8+ and Node.js 16+
- 8GB RAM minimum, 16GB recommended
- 20GB free disk space

### 1. Initialize the Project
```bash
# Run the automated setup script
python3 scripts/init-project.py
```

This script will:
- ✅ Check all dependencies
- ✅ Create configuration files
- ✅ Build Docker images
- ✅ Start all services
- ✅ Initialize PKI infrastructure
- ✅ Create default policies
- ✅ Set up monitoring dashboard

### 2. Access the System
Once setup completes, access the monitoring dashboard:
- **URL**: http://localhost:8080
- **Username**: `admin`
- **Password**: `zero-trust-admin`

## 🎯 What You Get

### Complete Zero Trust Architecture
- **Software-Defined Perimeter**: Encrypted WireGuard tunnels with "dark network" approach
- **Micro-segmentation**: Network zones with granular access controls
- **PKI Infrastructure**: Automated certificate management and validation
- **Network Access Control**: Device compliance checking and enforcement
- **Continuous Verification**: Real-time monitoring and policy enforcement

### Service Endpoints
| Service | Port | Description |
|---------|------|-------------|
| Monitoring Dashboard | 8080 | Web-based management interface |
| SDP Controller | 8001 | Authentication and policy orchestration |
| SDP Gateway | 8002 | VPN tunnel management |
| PKI Certificate Authority | 8003 | Certificate issuance and management |
| NAC Service | 8004 | Device compliance and enforcement |
| Microsegmentation Engine | 8005 | Network policy enforcement |
| Integration API | 8006 | Unified API gateway |

### Default Network Zones
- **DMZ Zone** (10.1.0.0/24): Public-facing services
- **Internal Zone** (10.2.0.0/24): Corporate network
- **User Devices** (10.3.0.0/24): End-user workstations
- **Server Zone** (10.4.0.0/24): Application servers
- **Management Zone** (10.5.0.0/24): Network management

## 🧪 Testing the Implementation

### 1. Test SDP Client Connection
```bash
# Navigate to client directory
cd sdp/client

# Run the SDP client
python client.py admin zero-trust-admin http://localhost:8001 http://localhost:8002

# Follow the interactive menu to:
# - Request access to different zones
# - View connection status
# - Test policy enforcement
```

### 2. Test API Endpoints
```bash
# Test authentication
curl -X POST http://localhost:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"zero-trust-admin","device_info":{"name":"test-device","type":"workstation"}}'

# Test system status
curl http://localhost:8006/api/system/status

# Test certificate issuance
curl -X GET http://localhost:8003/api/ca/certificate
```

### 3. Test Policy Enforcement
```bash
# Test traffic evaluation
curl -X POST http://localhost:8005/api/traffic/evaluate \
  -H "Content-Type: application/json" \
  -d '{"source_ip":"10.3.0.101","destination_ip":"10.1.0.10","protocol":"tcp","destination_port":"80"}'

# Test device compliance
curl -X POST http://localhost:8004/api/compliance \
  -H "Content-Type: application/json" \
  -d '{"device_info":{"device_id":"test-001","security":{"antivirus_running":true,"firewall_enabled":true}}}'
```

## 📊 Monitoring and Management

### Dashboard Features
- **Real-time System Status**: Service health and performance metrics
- **Security Analytics**: Traffic patterns and policy violations
- **Compliance Monitoring**: Device security posture tracking
- **Event Management**: Security incident correlation and alerting
- **Policy Management**: Unified policy creation and enforcement

### Key Metrics Monitored
- Active network connections
- Authentication success/failure rates
- Policy violation incidents
- Device compliance rates
- Certificate expiration tracking
- Service availability and performance

## 🔧 Configuration

### Environment Variables
Create `.env` file to customize configuration:
```bash
# Security
JWT_SECRET_KEY=your-secure-secret-key
SDP_JWT_SECRET=your-sdp-secret-key

# Database
POSTGRES_DB=zerotrust
POSTGRES_USER=ztuser
POSTGRES_PASSWORD=your-secure-password

# Service Configuration
LOG_LEVEL=INFO
METRICS_RETENTION_DAYS=30
SESSION_TIMEOUT=28800

# PKI Settings
CA_NAME=YourOrg-Root-CA
CERT_VALIDITY_DAYS=365
RENEWAL_THRESHOLD_DAYS=30
```

### Custom Policies
Add custom access policies via the API or dashboard:
```json
{
  "name": "Allow DevOps SSH Access",
  "source_zone": "management",
  "destination_zone": "servers",
  "protocol": "tcp",
  "port_range": "22",
  "action": "allow",
  "conditions": {
    "require_mfa": true,
    "business_hours_only": false,
    "max_session_duration": 7200
  }
}
```

### Network Zones
Customize network zones in `config/network/zones.json`:
```json
{
  "zones": {
    "custom_zone": {
      "name": "Custom Application Zone",
      "subnet": "10.7.0.0/24",
      "security_level": "high",
      "description": "Custom application servers"
    }
  }
}
```

## 🛠️ Advanced Configuration

### SSL/TLS Certificates
For production deployment:
```bash
# Generate proper certificates
openssl req -new -x509 -days 365 -nodes \
  -out config/ssl/server.crt \
  -keyout config/ssl/server.key \
  -subj "/CN=your-domain.com"

# Update docker-compose.yml with SSL configuration
```

### High Availability Setup
```yaml
# docker-compose.ha.yml
services:
  sdp-controller:
    deploy:
      replicas: 3
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
  
  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_REPLICATION_MODE=master
      - POSTGRES_REPLICATION_USER=replicator
```

### External Integrations
- **LDAP/Active Directory**: Configure user authentication
- **SIEM Integration**: Forward security events
- **Vulnerability Scanners**: Import compliance data
- **Endpoint Protection**: Integrate device security status

## 🔍 Troubleshooting

### Common Issues

#### Services Won't Start
```bash
# Check Docker status
docker-compose ps

# View service logs
docker-compose logs service-name

# Restart specific service
docker-compose restart service-name
```

#### Authentication Failures
```bash
# Reset admin user
docker-compose exec sdp-controller python reset_admin.py

# Check JWT configuration
docker-compose logs sdp-controller | grep JWT
```

#### Network Connectivity Issues
```bash
# Test inter-service communication
docker-compose exec integration-api curl http://sdp-controller:8001/health

# Check WireGuard status
docker-compose exec sdp-gateway wg show
```

### Log Analysis
```bash
# Collect all logs for analysis
docker-compose logs > system_logs.txt

# Search for specific issues
grep -i "error\|fail\|exception" system_logs.txt

# Monitor real-time logs
docker-compose logs -f
```

## 📚 Learning Exercises

### Exercise 1: Policy Creation
1. Create a new network zone for IoT devices
2. Define policies allowing IoT devices to communicate with specific servers
3. Test policy enforcement using traffic evaluation API

### Exercise 2: Certificate Management
1. Generate device certificates using the PKI CA
2. Configure certificate-based authentication
3. Test certificate validation and revocation

### Exercise 3: Compliance Monitoring
1. Simulate non-compliant devices
2. Observe automatic enforcement actions
3. Test remediation workflows

### Exercise 4: Incident Response
1. Simulate security events (failed authentication, policy violations)
2. Monitor event correlation in the dashboard
3. Practice incident response procedures

## 🚀 Production Deployment

### Pre-Production Checklist
- [ ] Change all default passwords
- [ ] Generate production SSL certificates
- [ ] Configure proper database with backups
- [ ] Set up log rotation and monitoring
- [ ] Configure firewall rules
- [ ] Test disaster recovery procedures
- [ ] Conduct security assessment
- [ ] Train operations team

### Scaling Considerations
- Use container orchestration (Kubernetes)
- Implement database clustering
- Configure load balancers
- Set up monitoring and alerting
- Plan capacity based on user count and traffic

### Security Hardening
- Enable audit logging for all components
- Implement network segmentation at infrastructure level
- Configure intrusion detection systems
- Regular security updates and patches
- Penetration testing and vulnerability assessments

## 📞 Support and Resources

### Documentation
- [Architecture Guide](docs/architecture.md) - Detailed system design
- [API Documentation](docs/api.md) - Complete API reference
- [Installation Guide](docs/installation.md) - Detailed setup instructions
- [Troubleshooting Guide](docs/troubleshooting.md) - Common issues and solutions

### Community
- GitHub Issues: Report bugs and feature requests
- Discussions: Ask questions and share experiences
- Wiki: Community-contributed guides and examples

### Professional Services
- Deployment consulting
- Custom integrations
- Training and certification
- Production support

---

## 🎉 Congratulations!

You now have a complete, functional zero trust network implementation that demonstrates:

- **Never Trust, Always Verify** principle
- **Software-Defined Perimeter** with encrypted tunnels
- **Micro-segmentation** with granular access controls
- **Continuous Verification** with real-time monitoring
- **Certificate-based Authentication** with PKI infrastructure
- **Device Compliance** monitoring and enforcement
- **Unified Policy Management** across all components
- **Real-time Analytics** and security monitoring

This implementation serves as both an educational tool and a foundation for production zero trust network deployments. The modular architecture allows you to adapt and extend the system to meet specific organizational requirements.

**⚠️ Important**: This is a laboratory implementation designed for learning and demonstration. For production use, ensure proper security hardening, testing, and compliance with your organization's security policies.

Enjoy exploring the future of network security with Zero Trust! 🔒
