# Zero Trust Network Troubleshooting Guide

## Common Issues and Solutions

### Service Startup Issues

#### Docker Services Won't Start

**Problem**: Services fail to start with Docker Compose.

**Symptoms**:
- `docker-compose up` fails
- Services show "Exited" status
- Port binding errors

**Solutions**:

1. **Check port conflicts**:
```bash
# Check if ports are in use
netstat -tulpn | grep :8001
netstat -tulpn | grep :8080

# Kill conflicting processes
sudo kill -9 $(lsof -t -i:8001)
```

2. **Check Docker daemon**:
```bash
# Ensure Docker is running
sudo systemctl status docker
sudo systemctl start docker

# Check Docker logs
journalctl -u docker -f
```

3. **Verify Docker Compose file**:
```bash
# Validate compose file syntax
docker-compose config

# Check for missing environment variables
docker-compose config --resolve-envs
```

4. **Clean and rebuild**:
```bash
# Stop all services
docker-compose down

# Remove containers and volumes
docker-compose down -v --remove-orphans

# Rebuild images
docker-compose build --no-cache

# Start services
docker-compose up -d
```

#### Database Connection Failures

**Problem**: Services can't connect to PostgreSQL or Redis.

**Symptoms**:
- "Connection refused" errors
- Services restart repeatedly
- Database-related error messages

**Solutions**:

1. **Check database containers**:
```bash
# Verify database containers are running
docker-compose ps postgres redis

# Check database logs
docker-compose logs postgres
docker-compose logs redis
```

2. **Test database connectivity**:
```bash
# Test PostgreSQL connection
docker-compose exec postgres psql -U ztuser -d zerotrust -c "SELECT 1;"

# Test Redis connection
docker-compose exec redis redis-cli ping
```

3. **Check database initialization**:
```bash
# Recreate databases
docker-compose down
docker volume rm zero_postgres-data zero_redis-data
docker-compose up -d postgres redis

# Wait for databases to initialize
sleep 30

# Start application services
docker-compose up -d
```

### Authentication Issues

#### Login Failures

**Problem**: Cannot authenticate with default credentials.

**Symptoms**:
- "Invalid credentials" error
- Authentication endpoint returns 401
- Admin user not found

**Solutions**:

1. **Verify default credentials**:
   - Username: `admin`
   - Password: `zero-trust-admin`

2. **Check SDP Controller logs**:
```bash
docker-compose logs sdp-controller | grep -i auth
```

3. **Reset admin user**:
```bash
# Connect to SDP Controller database
docker-compose exec sdp-controller python -c "
from app import db_manager
import hashlib
import uuid

with sqlite3.connect(db_manager.db_path) as conn:
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE username = \"admin\"')
    admin_id = str(uuid.uuid4())
    password_hash = hashlib.sha256('zero-trust-admin'.encode()).hexdigest()
    cursor.execute('''
        INSERT INTO users (id, username, password_hash, role)
        VALUES (?, ?, ?, ?)
    ''', (admin_id, 'admin', password_hash, 'admin'))
    conn.commit()
print('Admin user reset successfully')
"
```

#### JWT Token Issues

**Problem**: JWT tokens are invalid or expired.

**Symptoms**:
- "Invalid token" errors
- Frequent re-authentication required
- Token verification failures

**Solutions**:

1. **Check JWT configuration**:
```bash
# Verify JWT secret is set
docker-compose exec sdp-controller env | grep JWT_SECRET
```

2. **Update JWT secret**:
```bash
# Generate new secret
openssl rand -hex 32

# Update .env file
echo "JWT_SECRET_KEY=your-new-secret" >> .env

# Restart services
docker-compose restart
```

3. **Check system time**:
```bash
# Ensure system time is correct
date
sudo ntpdate -s time.nist.gov
```

### Network Connectivity Issues

#### VPN Tunnel Creation Failures

**Problem**: WireGuard tunnels fail to establish.

**Symptoms**:
- Tunnel creation returns errors
- Client can't connect to gateway
- WireGuard interface not found

**Solutions**:

1. **Check WireGuard installation**:
```bash
# Verify WireGuard is installed in gateway container
docker-compose exec sdp-gateway which wg
docker-compose exec sdp-gateway wg --version
```

2. **Check WireGuard interface**:
```bash
# Check if WireGuard interface exists
docker-compose exec sdp-gateway wg show

# Check interface configuration
docker-compose exec sdp-gateway ip addr show wg0
```

3. **Verify container capabilities**:
```bash
# Ensure gateway has NET_ADMIN capability
docker-compose exec sdp-gateway ip link add test type dummy
docker-compose exec sdp-gateway ip link delete test
```

4. **Check firewall rules**:
```bash
# Allow WireGuard port
sudo ufw allow 51820/udp

# Check iptables rules
docker-compose exec sdp-gateway iptables -L -n
```

#### Inter-Service Communication Failures

**Problem**: Services can't communicate with each other.

**Symptoms**:
- "Connection refused" between services
- Service discovery failures
- Health checks fail

**Solutions**:

1. **Check Docker network**:
```bash
# List Docker networks
docker network ls

# Inspect zero trust network
docker network inspect zero_zero-trust-net
```

2. **Test service connectivity**:
```bash
# Test from integration API to SDP Controller
docker-compose exec integration-api curl http://sdp-controller:8001/health

# Test DNS resolution
docker-compose exec integration-api nslookup sdp-controller
```

3. **Check service URLs**:
```bash
# Verify environment variables
docker-compose exec integration-api env | grep _URL
```

### Certificate Issues

#### PKI Certificate Authority Problems

**Problem**: CA fails to generate certificates.

**Symptoms**:
- Certificate issuance fails
- CA private key not found
- OpenSSL errors

**Solutions**:

1. **Check CA initialization**:
```bash
# Check CA logs
docker-compose logs pki-ca | grep -i certificate

# Verify CA files exist
docker-compose exec pki-ca ls -la /app/certificates/
```

2. **Regenerate CA certificates**:
```bash
# Remove existing CA files
docker-compose exec pki-ca rm -f /app/certificates/ca_*

# Restart CA service to regenerate
docker-compose restart pki-ca

# Check CA status
curl http://localhost:8003/api/ca/certificate
```

3. **Check file permissions**:
```bash
# Fix certificate directory permissions
docker-compose exec pki-ca chmod 700 /app/certificates
docker-compose exec pki-ca chown -R app:app /app/certificates
```

#### Certificate Validation Failures

**Problem**: Certificate validation fails across services.

**Symptoms**:
- "Certificate not trusted" errors
- SSL/TLS handshake failures
- Certificate chain validation errors

**Solutions**:

1. **Verify CA certificate distribution**:
```bash
# Check if services have CA certificate
docker-compose exec sdp-controller ls -la /app/ca_certificate.pem
docker-compose exec nac-service ls -la /app/ca_certificate.pem
```

2. **Update certificate trust**:
```bash
# Copy CA certificate to all services
CA_CERT=$(curl -s http://localhost:8003/api/ca/certificate | jq -r '.ca_certificate')
echo "$CA_CERT" | docker-compose exec -T sdp-controller tee /app/ca_certificate.pem
```

### Performance Issues

#### High Memory Usage

**Problem**: Services consume excessive memory.

**Symptoms**:
- Out of memory errors
- Services killed by OOM killer
- System becomes unresponsive

**Solutions**:

1. **Monitor resource usage**:
```bash
# Check container resource usage
docker stats

# Check system memory
free -h
```

2. **Adjust memory limits**:
```yaml
# Add to docker-compose.yml
services:
  sdp-controller:
    deploy:
      resources:
        limits:
          memory: 512M
```

3. **Optimize database queries**:
```bash
# Check slow queries
docker-compose exec postgres psql -U ztuser -d zerotrust -c "
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;"
```

#### Slow Response Times

**Problem**: API responses are slow.

**Symptoms**:
- High response times
- Timeouts
- Dashboard loading slowly

**Solutions**:

1. **Check service health**:
```bash
# Test response times
time curl http://localhost:8001/health
time curl http://localhost:8006/api/system/status
```

2. **Optimize database connections**:
```bash
# Check database connection pooling
docker-compose logs sdp-controller | grep -i database
```

3. **Enable caching**:
```bash
# Check Redis usage
docker-compose exec redis redis-cli info memory
docker-compose exec redis redis-cli keys "*"
```

### Monitoring and Logging Issues

#### Dashboard Not Loading

**Problem**: Monitoring dashboard doesn't load or shows errors.

**Symptoms**:
- Blank dashboard page
- JavaScript errors in browser
- WebSocket connection failures

**Solutions**:

1. **Check dashboard service**:
```bash
# Verify dashboard is running
docker-compose ps monitoring-dashboard

# Check dashboard logs
docker-compose logs monitoring-dashboard
```

2. **Test API connectivity**:
```bash
# Test dashboard API
curl http://localhost:8080/health
curl http://localhost:8080/api/dashboard/status
```

3. **Check browser console**:
```javascript
// Open browser developer tools
// Check for JavaScript errors
// Verify WebSocket connection
```

4. **Clear browser cache**:
```bash
# Clear browser cache and cookies
# Try incognito/private mode
# Disable browser extensions
```

#### Missing Log Files

**Problem**: Log files are not created or empty.

**Symptoms**:
- Empty log directory
- No log entries in files
- Cannot find specific log messages

**Solutions**:

1. **Check log directory permissions**:
```bash
# Verify log directory exists and is writable
docker-compose exec sdp-controller ls -la /app/logs/
docker-compose exec sdp-controller touch /app/logs/test.log
```

2. **Check logging configuration**:
```bash
# Verify logging configuration in services
docker-compose exec sdp-controller python -c "
import logging
print(logging.getLogger().handlers)
print(logging.getLogger().level)
"
```

3. **Increase log verbosity**:
```bash
# Set debug logging
export LOG_LEVEL=DEBUG
docker-compose restart
```

### Data and Storage Issues

#### Database Corruption

**Problem**: Database files become corrupted.

**Symptoms**:
- Database connection errors
- Data inconsistencies
- SQLite database locked errors

**Solutions**:

1. **Check database integrity**:
```bash
# SQLite integrity check
docker-compose exec sdp-controller sqlite3 sdp_controller.db "PRAGMA integrity_check;"

# PostgreSQL check
docker-compose exec postgres psql -U ztuser -d zerotrust -c "SELECT pg_database_size('zerotrust');"
```

2. **Repair database**:
```bash
# SQLite repair
docker-compose exec sdp-controller sqlite3 sdp_controller.db ".recover" > recovered.db

# PostgreSQL reindex
docker-compose exec postgres psql -U ztuser -d zerotrust -c "REINDEX DATABASE zerotrust;"
```

3. **Restore from backup**:
```bash
# Restore PostgreSQL backup
docker-compose exec postgres psql -U ztuser -d zerotrust < backup.sql
```

#### Disk Space Issues

**Problem**: System runs out of disk space.

**Symptoms**:
- "No space left on device" errors
- Services fail to write files
- Docker operations fail

**Solutions**:

1. **Check disk usage**:
```bash
# Check overall disk usage
df -h

# Check Docker space usage
docker system df
```

2. **Clean Docker resources**:
```bash
# Remove unused containers, networks, images
docker system prune -a

# Remove unused volumes
docker volume prune
```

3. **Clean log files**:
```bash
# Rotate and compress logs
find logs/ -name "*.log" -size +100M -exec gzip {} \;

# Remove old log files
find logs/ -name "*.log.gz" -mtime +30 -delete
```

## Diagnostic Commands

### System Health Check
```bash
#!/bin/bash
echo "=== Zero Trust Network Health Check ==="

echo "1. Checking Docker services..."
docker-compose ps

echo "2. Checking service health endpoints..."
for port in 8001 8002 8003 8004 8005 8006 8080; do
    echo -n "Port $port: "
    curl -s --max-time 5 http://localhost:$port/health >/dev/null && echo "OK" || echo "FAIL"
done

echo "3. Checking database connectivity..."
docker-compose exec postgres psql -U ztuser -d zerotrust -c "SELECT 1;" >/dev/null 2>&1 && echo "PostgreSQL: OK" || echo "PostgreSQL: FAIL"
docker-compose exec redis redis-cli ping >/dev/null 2>&1 && echo "Redis: OK" || echo "Redis: FAIL"

echo "4. Checking disk space..."
df -h | grep -E "(/$|/var/lib/docker)"

echo "5. Checking memory usage..."
free -h

echo "6. Checking recent errors..."
docker-compose logs --tail=10 | grep -i error

echo "=== Health Check Complete ==="
```

### Log Analysis Script
```bash
#!/bin/bash
echo "=== Zero Trust Network Log Analysis ==="

echo "1. Recent authentication events..."
docker-compose logs sdp-controller | grep -i "authentication" | tail -5

echo "2. Recent policy violations..."
docker-compose logs microseg-engine | grep -i "violation" | tail -5

echo "3. Recent certificate operations..."
docker-compose logs pki-ca | grep -i "certificate" | tail -5

echo "4. Service errors in last hour..."
docker-compose logs --since=1h | grep -i error

echo "5. Database connection issues..."
docker-compose logs | grep -i "database\|connection" | grep -i error | tail -5

echo "=== Log Analysis Complete ==="
```

### Performance Monitoring
```bash
#!/bin/bash
echo "=== Zero Trust Network Performance Monitor ==="

echo "1. Container resource usage..."
docker stats --no-stream

echo "2. API response times..."
for endpoint in "/health" "/api/status"; do
    for port in 8001 8002 8003 8004 8005 8006; do
        echo -n "localhost:$port$endpoint: "
        time curl -s http://localhost:$port$endpoint >/dev/null
    done
done

echo "3. Database performance..."
docker-compose exec postgres psql -U ztuser -d zerotrust -c "
SELECT schemaname, tablename, n_tup_ins, n_tup_upd, n_tup_del 
FROM pg_stat_user_tables 
ORDER BY n_tup_ins DESC;"

echo "4. Network connectivity..."
docker-compose exec integration-api ping -c 3 sdp-controller

echo "=== Performance Monitor Complete ==="
```

## Getting Help

### Log Collection for Support
```bash
#!/bin/bash
# Collect logs for support analysis
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOGDIR="zerotrust_logs_$TIMESTAMP"

mkdir -p $LOGDIR

# Collect service logs
docker-compose logs > $LOGDIR/docker-compose.logs

# Collect individual service logs
for service in sdp-controller sdp-gateway pki-ca nac-service microseg-engine integration-api monitoring-dashboard; do
    docker-compose logs $service > $LOGDIR/$service.log
done

# Collect system information
docker-compose ps > $LOGDIR/services_status.txt
docker system df > $LOGDIR/docker_usage.txt
df -h > $LOGDIR/disk_usage.txt
free -h > $LOGDIR/memory_usage.txt

# Create archive
tar -czf $LOGDIR.tar.gz $LOGDIR
rm -rf $LOGDIR

echo "Log collection complete: $LOGDIR.tar.gz"
```

### Community Support
- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Check the docs/ directory for detailed guides
- **Examples**: Review example configurations and use cases

### Professional Support
For production deployments and enterprise support:
- Contact the development team
- Schedule a consultation for deployment planning
- Request custom integrations and features

This troubleshooting guide covers the most common issues encountered when deploying and operating the Zero Trust Network implementation. For issues not covered here, check the service-specific logs and consult the API documentation for detailed error codes and responses.
