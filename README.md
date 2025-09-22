# Zero Trust Network Implementation Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Node.js 16+](https://img.shields.io/badge/node.js-16+-green.svg)](https://nodejs.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![Zero Trust](https://img.shields.io/badge/zero%20trust-architecture-orange.svg)](https://www.nist.gov/publications/zero-trust-architecture)

A comprehensive, production-ready implementation of zero trust network architecture principles for educational, research, and demonstration purposes. This lab provides hands-on experience with modern zero trust concepts including Software-Defined Perimeter (SDP), micro-segmentation, PKI infrastructure, and continuous verification.

## 🏗️ Architecture Overview

This project implements the three core pillars of zero trust networking:

1. **Software-Defined Perimeter (SDP)** - Dynamic, encrypted tunnels with "dark network" approach
2. **Micro-Segmentation** - Network isolation with granular access controls
3. **Continuous Verification** - Ongoing authentication and compliance monitoring

## 📁 Project Structure

```
zero-trust-lab/
├── sdp/                    # Software-Defined Perimeter
│   ├── controller/         # SDP Controller (orchestration)
│   ├── gateway/           # SDP Gateways (secure connection points)
│   └── client/            # SDP Client software
├── microsegmentation/     # Network segmentation
│   ├── zones/             # Security zone definitions
│   ├── policies/          # Access control policies
│   └── firewall/          # Firewall rule management
├── pki/                   # Public Key Infrastructure
│   ├── ca/                # Certificate Authority
│   ├── certificates/      # Certificate management
│   └── enrollment/        # Auto-enrollment services
├── nac/                   # Network Access Control
│   ├── compliance/        # Device compliance checking
│   ├── enforcement/       # Access enforcement points
│   └── remediation/       # Non-compliant device handling
├── integration/           # Component integration layer
│   ├── api/               # REST API for inter-component communication
│   ├── events/            # Event handling and notifications
│   └── policies/          # Unified policy management
├── monitoring/            # Continuous verification
│   ├── dashboard/         # Web-based monitoring interface
│   ├── analytics/         # Behavioral analytics
│   └── logging/           # Audit and compliance logging
└── config/                # Configuration files
    ├── docker/            # Docker configurations
    ├── network/           # Network topology definitions
    └── security/          # Security policies and templates
```

## 🚀 Quick Start

### Prerequisites
- **Docker & Docker Compose** - Container orchestration
- **Python 3.8+** - Backend services
- **Node.js 16+** - Frontend dashboard
- **8GB RAM minimum** - Recommended for smooth operation

### One-Command Setup
```bash
# Clone the repository
git clone https://github.com/bunnyhp/zero-trust-network-lab.git
cd zero-trust-network-lab

# Run automated setup (installs dependencies, builds containers, initializes PKI)
python scripts/init-project.py
```

### Manual Setup
```bash
# Install dependencies
pip install -r requirements.txt
npm install

# Start all services
docker-compose up -d

# Initialize PKI infrastructure
python scripts/init-project.py
```

### Access the System
- **🌐 Dashboard**: http://localhost:8080
- **👤 Username**: `admin`
- **🔑 Password**: `zero-trust-admin`

### Verify Installation
```bash
# Check all services are running
docker-compose ps

# Test API endpoints
curl http://localhost:8001/health  # SDP Controller
curl http://localhost:8006/health  # Integration API
```

## 🔧 Components

### Software-Defined Perimeter
- **Controller**: Policy orchestration and authentication
- **Gateway**: Secure tunnel endpoints
- **Client**: User/device connection software

### Micro-Segmentation
- **Zone Management**: Dynamic security zone creation
- **Policy Engine**: Granular access control rules
- **Traffic Analysis**: Inter-zone communication monitoring

### PKI Infrastructure
- **Certificate Authority**: Hierarchical CA structure
- **Auto-Enrollment**: Automated certificate provisioning
- **Lifecycle Management**: Certificate renewal and revocation

### Network Access Control
- **Compliance Engine**: Device security posture assessment
- **Enforcement Points**: Dynamic access control
- **Remediation Services**: Non-compliant device handling

## 📊 Monitoring & Analytics

- Real-time network traffic visualization
- User behavior analytics
- Compliance status dashboard
- Security event correlation
- Audit trail management

## 🎓 Learning Objectives

By working with this implementation, you will understand:

- Zero trust architecture principles
- Software-defined networking concepts
- Certificate-based authentication
- Network micro-segmentation strategies
- Continuous security monitoring
- Policy-based access control

## 🔒 Security Features

- End-to-end encryption for all communications
- Certificate-based mutual authentication
- Dynamic policy enforcement
- Behavioral anomaly detection
- Comprehensive audit logging
- Automated threat response

## 📚 Documentation

- [Architecture Guide](docs/architecture.md)
- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [API Documentation](docs/api.md)
- [Troubleshooting](docs/troubleshooting.md)

## 🧪 Lab Exercises

1. **Basic Zero Trust Setup** - Configure core components
2. **Policy Creation** - Define and test access policies
3. **Threat Simulation** - Simulate and respond to security events
4. **Compliance Monitoring** - Monitor and enforce device compliance
5. **Integration Testing** - Test component interactions

## 🤝 Contributing

We welcome contributions from the cybersecurity community! This project thrives on collaboration and shared knowledge.

### How to Contribute
- 🐛 **Report Bugs** - Use our [bug report template](.github/ISSUE_TEMPLATE/bug_report.md)
- 💡 **Request Features** - Use our [feature request template](.github/ISSUE_TEMPLATE/feature_request.md)
- 🔧 **Submit Code** - Follow our [contributing guidelines](CONTRIBUTING.md)
- 📚 **Improve Docs** - Help others learn with better documentation
- 🎓 **Share Knowledge** - Contribute educational content and tutorials

### Quick Contribution Guide
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`python -m pytest && npm test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Community
- 💬 **Discussions** - Join our [GitHub Discussions](https://github.com/bunnyhp/zero-trust-network-lab/discussions)
- 🐛 **Issues** - Report bugs and request features
- 📖 **Wiki** - Community-contributed guides and examples
- 🌟 **Stars** - Show your support by starring the repository

## 🌟 Project Impact

This project aims to:
- **🎓 Educate** thousands of security professionals on zero trust principles
- **🔬 Advance** zero trust research and development
- **🤝 Build** a community of cybersecurity practitioners
- **🚀 Accelerate** zero trust adoption in organizations
- **📚 Provide** real-world implementation examples
- **🛡️ Improve** overall network security practices

## 📊 Repository Stats

![GitHub stars](https://img.shields.io/github/stars/bunnyhp/zero-trust-network-lab?style=social)
![GitHub forks](https://img.shields.io/github/forks/bunnyhp/zero-trust-network-lab?style=social)
![GitHub issues](https://img.shields.io/github/issues/bunnyhp/zero-trust-network-lab)
![GitHub pull requests](https://img.shields.io/github/issues-pr/bunnyhp/zero-trust-network-lab)

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 🛡️ Security Notice

**⚠️ Important**: This is a laboratory implementation for educational purposes. While it follows security best practices, it should be thoroughly reviewed, tested, and hardened before any production deployment.

For security vulnerabilities, please email: security@zerotrust-lab.org

---

<div align="center">

**⭐ Star this repository if you find it helpful!**

[Report Bug](https://github.com/bunnyhp/zero-trust-network-lab/issues) · [Request Feature](https://github.com/bunnyhp/zero-trust-network-lab/issues) · [Join Discussion](https://github.com/bunnyhp/zero-trust-network-lab/discussions)

Made with ❤️ by the Zero Trust Community

</div>
