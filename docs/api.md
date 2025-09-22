# Zero Trust Network API Documentation

## Overview

This document provides comprehensive API documentation for all components in the Zero Trust Network implementation. All APIs use RESTful principles with JSON payloads and standard HTTP status codes.

## Base URLs

- **SDP Controller**: `http://localhost:8001`
- **SDP Gateway**: `http://localhost:8002`
- **PKI CA**: `http://localhost:8003`
- **NAC Service**: `http://localhost:8004`
- **Microsegmentation**: `http://localhost:8005`
- **Integration API**: `http://localhost:8006`
- **Monitoring Dashboard**: `http://localhost:8080`

## Authentication

Most APIs require JWT token authentication. Include the token in the Authorization header:

```
Authorization: Bearer <jwt-token>
```

## SDP Controller API

### Authentication

#### POST /api/auth/login
Authenticate user and device.

**Request Body:**
```json
{
  "username": "string",
  "password": "string",
  "device_info": {
    "device_id": "string",
    "name": "string",
    "type": "string",
    "mac_address": "string"
  }
}
```

**Response (200):**
```json
{
  "access_token": "string",
  "user_id": "string",
  "device_id": "string",
  "role": "string",
  "expires_in": 28800
}
```

### Access Policies

#### GET /api/policies
Get all access policies.

**Response (200):**
```json
{
  "policies": [
    {
      "id": "string",
      "name": "string",
      "source_zone": "string",
      "destination_zone": "string",
      "protocol": "string",
      "port_range": "string",
      "action": "allow|deny",
      "conditions": {},
      "created_at": "string",
      "is_active": true
    }
  ]
}
```

#### POST /api/policies
Create new access policy.

**Request Body:**
```json
{
  "name": "string",
  "source_zone": "string",
  "destination_zone": "string",
  "protocol": "tcp|udp|any",
  "port_range": "string",
  "action": "allow|deny",
  "conditions": {}
}
```

**Response (201):**
```json
{
  "policy_id": "string",
  "message": "Policy created successfully"
}
```

#### GET /api/policies/{policy_id}
Get specific policy by ID.

**Response (200):**
```json
{
  "id": "string",
  "name": "string",
  "source_zone": "string",
  "destination_zone": "string",
  "protocol": "string",
  "port_range": "string",
  "action": "string",
  "conditions": {},
  "created_at": "string",
  "is_active": true
}
```

### Access Requests

#### POST /api/access/request
Request access to network resource.

**Request Body:**
```json
{
  "source_zone": "string",
  "destination_zone": "string",
  "protocol": "tcp|udp",
  "destination_port": "string"
}
```

**Response (200):**
```json
{
  "decision": "allow|deny",
  "policy_id": "string",
  "policy_name": "string",
  "session_duration": 3600,
  "tunnel_config": {
    "tunnel_type": "wireguard",
    "gateway_endpoint": "string",
    "encryption": "string",
    "key_exchange": "string"
  }
}
```

### System Status

#### GET /api/status
Get controller status and statistics.

**Response (200):**
```json
{
  "status": "operational",
  "statistics": {
    "active_users": 0,
    "registered_devices": 0,
    "active_policies": 0,
    "active_sessions": 0
  },
  "timestamp": "string"
}
```

## SDP Gateway API

### Tunnel Management

#### POST /api/tunnel
Create VPN tunnel for authenticated client.

**Request Body:**
```json
{
  "user_id": "string",
  "device_id": "string",
  "access_token": "string",
  "allowed_ips": "10.0.0.0/8"
}
```

**Response (201):**
```json
{
  "tunnel_id": "string",
  "client_config": "string",
  "server_endpoint": "string",
  "status": "active"
}
```

#### DELETE /api/tunnel/{tunnel_id}
Terminate VPN tunnel.

**Response (200):**
```json
{
  "message": "Tunnel terminated successfully"
}
```

### Gateway Status

#### GET /api/status
Get gateway status and metrics.

**Response (200):**
```json
{
  "status": "operational",
  "wireguard": {
    "status": "up",
    "interface": "wg0",
    "public_key": "string",
    "output": "string"
  },
  "active_tunnels": 0,
  "timestamp": "string"
}
```

## PKI Certificate Authority API

### Certificate Management

#### POST /api/certificates
Issue new certificate from CSR.

**Request Body:**
```json
{
  "csr": "string",
  "type": "client|server",
  "validity_days": 365
}
```

**Response (201):**
```json
{
  "certificate_id": "string",
  "serial_number": 12345,
  "certificate_pem": "string",
  "not_before": "string",
  "not_after": "string"
}
```

#### GET /api/certificates/{serial_number}
Get certificate by serial number.

**Response (200):**
```json
{
  "serial_number": 12345,
  "certificate_pem": "string",
  "status": "active|revoked",
  "not_before": "string",
  "not_after": "string"
}
```

#### DELETE /api/certificates/{serial_number}
Revoke certificate.

**Request Body:**
```json
{
  "reason": "key_compromise|superseded|cessation_of_operation"
}
```

**Response (200):**
```json
{
  "message": "Certificate revoked successfully"
}
```

### CA Operations

#### GET /api/ca/certificate
Get CA certificate.

**Response (200):**
```json
{
  "ca_certificate": "string",
  "subject": "string",
  "not_before": "string",
  "not_after": "string",
  "serial_number": 1
}
```

#### GET /api/ca/crl
Get Certificate Revocation List.

**Response (200):**
Returns CRL file as `application/pkix-crl`.

#### GET /api/ca/status
Get CA status and statistics.

**Response (200):**
```json
{
  "status": "operational",
  "ca_name": "string",
  "statistics": {
    "active_certificates": 0,
    "revoked_certificates": 0,
    "pending_requests": 0
  },
  "ca_certificate": {
    "subject": "string",
    "not_before": "string",
    "not_after": "string"
  },
  "timestamp": "string"
}
```

## NAC Service API

### Device Compliance

#### POST /api/compliance
Evaluate device compliance.

**Request Body:**
```json
{
  "device_info": {
    "device_id": "string",
    "os": {
      "system": "string",
      "version": "string"
    },
    "security": {
      "antivirus_running": true,
      "firewall_enabled": true,
      "disk_encryption": true
    },
    "network": {},
    "hardware": {}
  }
}
```

**Response (200):**
```json
{
  "compliance": {
    "device_id": "string",
    "evaluation_time": "string",
    "overall_status": "compliant|partially_compliant|non_compliant",
    "compliance_score": 85,
    "policy_results": {},
    "violations": [
      {
        "policy_id": "string",
        "policy_name": "string",
        "severity": "critical|high|medium|low",
        "description": "string"
      }
    ],
    "recommendations": [
      {
        "policy_id": "string",
        "remediation": "string",
        "severity": "string"
      }
    ]
  },
  "enforcement": {
    "network_access": "full|limited|quarantine",
    "allowed_zones": ["string"],
    "session_duration": 3600,
    "monitoring_level": "normal|enhanced|high"
  }
}
```

#### GET /api/compliance/{device_id}
Get device compliance status.

**Response (200):**
```json
{
  "device_id": "string",
  "compliance_status": "string",
  "compliance_score": 85,
  "last_evaluation": "string",
  "violations_count": 2,
  "enforcement_level": "string"
}
```

### Remediation

#### GET /api/remediation/{device_id}
Get remediation plan for device.

**Response (200):**
```json
{
  "device_id": "string",
  "created_time": "string",
  "status": "remediation_required",
  "total_violations": 2,
  "estimated_time": "30 minutes",
  "plan": [
    {
      "step_id": "string",
      "title": "string",
      "steps": ["string"],
      "estimated_time": "string",
      "priority": "critical|high|medium|low",
      "violation": {}
    }
  ]
}
```

### Enforcement Actions

#### POST /api/enforcement
Create enforcement action.

**Request Body:**
```json
{
  "device_id": "string",
  "access_level": {
    "network_access": "quarantine",
    "allowed_zones": ["remediation"],
    "session_duration": 900,
    "monitoring_level": "high"
  }
}
```

**Response (201):**
```json
{
  "action_id": "string",
  "device_id": "string",
  "timestamp": "string",
  "access_level": {},
  "actions_taken": [
    {
      "type": "network_quarantine",
      "description": "string",
      "network": "10.99.0.0/24"
    }
  ]
}
```

## Microsegmentation API

### Network Zones

#### GET /api/zones
Get all network zones.

**Response (200):**
```json
{
  "dmz": {
    "name": "DMZ Zone",
    "description": "string",
    "subnet": "10.1.0.0/24",
    "security_level": "medium",
    "allowed_protocols": ["tcp", "udp"],
    "default_action": "deny"
  }
}
```

#### GET /api/zones/{zone_id}
Get specific zone.

**Response (200):**
```json
{
  "zone_id": {
    "name": "string",
    "description": "string",
    "subnet": "string",
    "security_level": "string"
  }
}
```

#### POST /api/zones
Create new zone.

**Request Body:**
```json
{
  "id": "string",
  "name": "string",
  "subnet": "10.6.0.0/24",
  "security_level": "high",
  "description": "string"
}
```

**Response (201):**
```json
{
  "message": "Zone created successfully"
}
```

### Traffic Policies

#### GET /api/policies
Get all microsegmentation policies.

**Response (200):**
```json
{
  "policies": [
    {
      "id": "string",
      "name": "string",
      "source_zone": "string",
      "destination_zone": "string",
      "protocol": "string",
      "destination_ports": [80, 443],
      "action": "allow|deny",
      "conditions": {},
      "priority": 100,
      "enabled": true
    }
  ]
}
```

#### POST /api/policies
Create new policy.

**Request Body:**
```json
{
  "id": "string",
  "name": "string",
  "source_zone": "string",
  "destination_zone": "string",
  "protocol": "tcp|udp|any",
  "destination_ports": [80, 443],
  "action": "allow|deny",
  "conditions": {},
  "priority": 100,
  "enabled": true
}
```

**Response (201):**
```json
{
  "message": "Policy created successfully"
}
```

#### DELETE /api/policies/{policy_id}
Delete policy.

**Response (200):**
```json
{
  "message": "Policy deleted successfully"
}
```

### Traffic Evaluation

#### POST /api/traffic/evaluate
Evaluate traffic against policies.

**Request Body:**
```json
{
  "source_ip": "10.3.0.101",
  "destination_ip": "10.1.0.10",
  "protocol": "tcp",
  "destination_port": "80"
}
```

**Response (200):**
```json
{
  "decision": "allow|deny",
  "policy_id": "string",
  "policy_name": "string",
  "source_zone": "string",
  "destination_zone": "string",
  "conditions": {},
  "priority": 100
}
```

### Traffic Analytics

#### GET /api/traffic/summary
Get traffic summary.

**Query Parameters:**
- `hours`: Number of hours to analyze (default: 1)

**Response (200):**
```json
{
  "time_period_hours": 1,
  "total_requests": 150,
  "allowed_requests": 120,
  "denied_requests": 30,
  "allow_rate": 80.0,
  "top_source_zones": {
    "user_devices": 100,
    "dmz": 50
  },
  "top_destination_zones": {
    "dmz": 80,
    "servers": 70
  }
}
```

## Integration API

### Unified Authentication

#### POST /api/auth/unified
Unified authentication across all components.

**Request Body:**
```json
{
  "username": "string",
  "password": "string",
  "device_info": {}
}
```

**Response (200):**
```json
{
  "access_token": "string",
  "user_id": "string",
  "device_id": "string",
  "role": "string",
  "expires_in": 28800,
  "compliance": {},
  "enforcement": {}
}
```

### Unified Access Control

#### POST /api/access/unified
Process unified access request.

**Request Body:**
```json
{
  "user_id": "string",
  "device_id": "string",
  "access_token": "string",
  "source_ip": "string",
  "destination_ip": "string",
  "destination_zone": "string",
  "destination_port": "string",
  "protocol": "tcp"
}
```

**Response (200):**
```json
{
  "request_id": "string",
  "timestamp": "string",
  "components_evaluated": {
    "nac": {},
    "microsegmentation": {},
    "sdp_controller": {}
  },
  "final_decision": "allow|deny",
  "reasons": ["string"],
  "tunnel": {
    "tunnel_id": "string",
    "client_config": "string"
  }
}
```

### Policy Management

#### POST /api/policies/unified
Create unified policy across components.

**Request Body:**
```json
{
  "name": "string",
  "source_zone": "string",
  "destination_zone": "string",
  "protocol": "string",
  "port_range": "string",
  "action": "allow|deny",
  "conditions": {}
}
```

**Response (201):**
```json
{
  "policy_id": "string",
  "message": "Unified policy created successfully"
}
```

#### GET /api/policies/unified
Get all unified policies.

**Response (200):**
```json
{
  "policies": {}
}
```

### System Status

#### GET /api/system/status
Get system-wide status.

**Response (200):**
```json
{
  "overall_status": "healthy|degraded|unhealthy",
  "health_percentage": 100,
  "services": {
    "sdp_controller": {
      "url": "string",
      "status": "healthy",
      "last_check": "string"
    }
  },
  "statistics": {
    "healthy_services": 5,
    "total_services": 5,
    "active_policies": 10
  },
  "recent_events": [
    {
      "event_type": "string",
      "source_service": "string",
      "severity": "string",
      "created_at": "string"
    }
  ],
  "timestamp": "string"
}
```

### Event Management

#### GET /api/events
Get recent system events.

**Query Parameters:**
- `hours`: Number of hours to retrieve (default: 24)

**Response (200):**
```json
{
  "events": [
    {
      "id": "string",
      "event_type": "string",
      "source_service": "string",
      "event_data": {},
      "severity": "info|warning|error|critical",
      "created_at": "string"
    }
  ],
  "count": 50,
  "time_period_hours": 24
}
```

## Monitoring Dashboard API

### Dashboard Status

#### GET /api/dashboard/status
Get dashboard status.

**Response (200):**
```json
{
  "status": "operational",
  "systemStatus": {},
  "realtimeMetrics": {
    "activeConnections": 50,
    "authenticationRate": 5,
    "policyViolations": 2,
    "complianceRate": 87.5
  },
  "timestamp": "string"
}
```

#### GET /api/dashboard/events
Get dashboard events.

**Response (200):**
```json
{
  "events": [],
  "count": 0
}
```

#### GET /api/dashboard/metrics
Get real-time metrics.

**Response (200):**
```json
{
  "activeConnections": 50,
  "authenticationRate": 5,
  "policyViolations": 2,
  "complianceRate": 87.5
}
```

## Common HTTP Status Codes

- **200 OK**: Request successful
- **201 Created**: Resource created successfully
- **400 Bad Request**: Invalid request parameters
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Access denied
- **404 Not Found**: Resource not found
- **500 Internal Server Error**: Server error
- **503 Service Unavailable**: Service temporarily unavailable

## Error Response Format

All APIs return errors in a consistent format:

```json
{
  "error": "Error message",
  "details": "Additional error details",
  "timestamp": "2024-01-01T12:00:00Z",
  "request_id": "string"
}
```

## Rate Limiting

APIs implement rate limiting to prevent abuse:

- **Authentication**: 10 requests per minute per IP
- **Policy Management**: 100 requests per minute per user
- **Traffic Evaluation**: 1000 requests per minute per service
- **Status/Health**: 60 requests per minute per IP

Rate limit headers are included in responses:
- `X-RateLimit-Limit`: Request limit per window
- `X-RateLimit-Remaining`: Remaining requests in current window
- `X-RateLimit-Reset`: Time when rate limit resets

## WebSocket Events (Monitoring Dashboard)

The monitoring dashboard supports real-time updates via WebSocket:

### Client Events
- `requestSystemRefresh`: Request system status refresh
- `requestMetricsRefresh`: Request metrics refresh

### Server Events
- `systemStatus`: System status update
- `realtimeMetrics`: Real-time metrics update
- `newEvents`: New security events
- `eventHistory`: Complete event history

## API Versioning

APIs use URL versioning (e.g., `/api/v1/`). Current version is v1 (implied when not specified).

## SDK and Client Libraries

Official client libraries are available for:
- Python: `pip install zerotrust-client`
- JavaScript/Node.js: `npm install zerotrust-client`
- Go: `go get github.com/zerotrust/go-client`

Example Python usage:
```python
from zerotrust_client import ZeroTrustClient

client = ZeroTrustClient(
    controller_url="http://localhost:8001",
    username="admin",
    password="password"
)

# Authenticate
token = client.authenticate()

# Request access
decision = client.request_access(
    destination_zone="dmz",
    destination_port="80",
    protocol="tcp"
)
```

This completes the API documentation. For additional examples and advanced usage, refer to the SDK documentation and example applications.
