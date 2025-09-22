#!/usr/bin/env python3
"""
Zero Trust SDP Client

The SDP Client handles authentication with the controller and establishes
secure tunnels to authorized gateways. It continuously validates security
posture and maintains encrypted connections.
"""

import os
import sys
import json
import time
import logging
import platform
import subprocess
import threading
from datetime import datetime
import requests
import psutil
import hashlib
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sdp_client.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DeviceProfiler:
    """Collects device information for compliance checking"""
    
    @staticmethod
    def get_device_info():
        """Collect comprehensive device information"""
        try:
            device_info = {
                'device_id': DeviceProfiler._get_device_id(),
                'name': platform.node(),
                'type': 'workstation',
                'os': {
                    'system': platform.system(),
                    'version': platform.version(),
                    'release': platform.release(),
                    'machine': platform.machine()
                },
                'network': DeviceProfiler._get_network_info(),
                'security': DeviceProfiler._get_security_info(),
                'hardware': DeviceProfiler._get_hardware_info(),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return device_info
            
        except Exception as e:
            logger.error(f"Error collecting device info: {str(e)}")
            return {}
    
    @staticmethod
    def _get_device_id():
        """Generate consistent device ID"""
        try:
            # Use MAC address as base for device ID
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                           for elements in range(0, 2*6, 2)][::-1])
            device_id = hashlib.sha256(mac.encode()).hexdigest()[:16]
            return device_id
        except:
            return str(uuid.uuid4())[:16]
    
    @staticmethod
    def _get_network_info():
        """Get network interface information"""
        try:
            interfaces = []
            for interface, addresses in psutil.net_if_addrs().items():
                interface_info = {'name': interface, 'addresses': []}
                for addr in addresses:
                    if addr.family == 2:  # IPv4
                        interface_info['addresses'].append({
                            'type': 'ipv4',
                            'address': addr.address,
                            'netmask': addr.netmask
                        })
                if interface_info['addresses']:
                    interfaces.append(interface_info)
            
            return {'interfaces': interfaces}
        except:
            return {}
    
    @staticmethod
    def _get_security_info():
        """Get security-related information"""
        security_info = {
            'antivirus_running': False,
            'firewall_enabled': False,
            'disk_encryption': False,
            'patch_level': 'unknown'
        }
        
        try:
            # Check for common antivirus processes (simplified)
            processes = [p.name().lower() for p in psutil.process_iter(['name'])]
            av_processes = ['avp.exe', 'mcshield.exe', 'windefend', 'avgnt.exe']
            security_info['antivirus_running'] = any(av in processes for av in av_processes)
            
            # Platform-specific security checks
            if platform.system() == 'Windows':
                security_info.update(DeviceProfiler._get_windows_security())
            elif platform.system() == 'Linux':
                security_info.update(DeviceProfiler._get_linux_security())
            
        except Exception as e:
            logger.warning(f"Could not collect security info: {str(e)}")
        
        return security_info
    
    @staticmethod
    def _get_windows_security():
        """Get Windows-specific security information"""
        try:
            # Check Windows Defender status
            result = subprocess.run(['powershell', '-Command', 
                                   'Get-MpComputerStatus | Select-Object AntivirusEnabled'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and 'True' in result.stdout:
                return {'antivirus_running': True, 'firewall_enabled': True}
        except:
            pass
        
        return {}
    
    @staticmethod
    def _get_linux_security():
        """Get Linux-specific security information"""
        security_info = {}
        
        try:
            # Check if firewall is running
            result = subprocess.run(['systemctl', 'is-active', 'ufw'], 
                                  capture_output=True, text=True)
            security_info['firewall_enabled'] = result.returncode == 0
            
            # Check for disk encryption
            result = subprocess.run(['lsblk', '-f'], capture_output=True, text=True)
            security_info['disk_encryption'] = 'crypto_LUKS' in result.stdout
            
        except:
            pass
        
        return security_info
    
    @staticmethod
    def _get_hardware_info():
        """Get hardware information"""
        try:
            return {
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_usage': psutil.disk_usage('/').percent if platform.system() != 'Windows' 
                             else psutil.disk_usage('C:').percent
            }
        except:
            return {}

class SDPClient:
    """Main SDP Client class"""
    
    def __init__(self, controller_url='http://localhost:8001', gateway_url='http://localhost:8002'):
        self.controller_url = controller_url
        self.gateway_url = gateway_url
        self.access_token = None
        self.device_info = DeviceProfiler.get_device_info()
        self.tunnel_config = None
        self.is_connected = False
        self.monitoring_thread = None
        
        logger.info(f"SDP Client initialized for device: {self.device_info.get('device_id')}")
    
    def authenticate(self, username, password):
        """Authenticate with SDP controller"""
        try:
            auth_data = {
                'username': username,
                'password': password,
                'device_info': self.device_info
            }
            
            response = requests.post(
                f'{self.controller_url}/api/auth/login',
                json=auth_data,
                timeout=10
            )
            
            if response.status_code == 200:
                auth_result = response.json()
                self.access_token = auth_result['access_token']
                self.user_id = auth_result['user_id']
                self.device_id = auth_result['device_id']
                
                logger.info(f"Authentication successful for user: {username}")
                return True
            else:
                logger.error(f"Authentication failed: {response.json().get('error', 'Unknown error')}")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return False
    
    def request_access(self, destination_zone, destination_port, protocol='tcp'):
        """Request access to network resource"""
        try:
            if not self.access_token:
                logger.error("Not authenticated")
                return False
            
            access_request = {
                'source_zone': 'user_devices',
                'destination_zone': destination_zone,
                'destination_port': destination_port,
                'protocol': protocol
            }
            
            headers = {'Authorization': f'Bearer {self.access_token}'}
            
            response = requests.post(
                f'{self.controller_url}/api/access/request',
                json=access_request,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                decision = response.json()
                if decision['decision'] == 'allow':
                    logger.info(f"Access granted to {destination_zone}:{destination_port}")
                    return self._establish_tunnel(decision)
                else:
                    logger.warning(f"Access denied: {decision.get('reason', 'Policy violation')}")
                    return False
            else:
                logger.error(f"Access request failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Access request error: {str(e)}")
            return False
    
    def _establish_tunnel(self, access_decision):
        """Establish VPN tunnel through gateway"""
        try:
            tunnel_request = {
                'user_id': self.user_id,
                'device_id': self.device_id,
                'access_token': self.access_token,
                'allowed_ips': '10.0.0.0/8'  # Default allowed networks
            }
            
            response = requests.post(
                f'{self.gateway_url}/api/tunnel',
                json=tunnel_request,
                timeout=15
            )
            
            if response.status_code == 201:
                tunnel_result = response.json()
                self.tunnel_config = tunnel_result['client_config']
                self.tunnel_id = tunnel_result['tunnel_id']
                
                # Configure local WireGuard client
                if self._configure_wireguard():
                    self.is_connected = True
                    self._start_monitoring()
                    logger.info(f"Tunnel established: {self.tunnel_id}")
                    return True
                else:
                    logger.error("Failed to configure local WireGuard")
                    return False
            else:
                logger.error(f"Tunnel creation failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Tunnel establishment error: {str(e)}")
            return False
    
    def _configure_wireguard(self):
        """Configure local WireGuard client"""
        try:
            config_path = 'client.conf'
            
            # Write WireGuard configuration
            with open(config_path, 'w') as f:
                f.write(self.tunnel_config)
            
            # Start WireGuard tunnel
            if platform.system() == 'Windows':
                # Windows WireGuard setup
                result = subprocess.run(['wg-quick', 'up', config_path], 
                                      capture_output=True, text=True)
            else:
                # Linux WireGuard setup
                result = subprocess.run(['sudo', 'wg-quick', 'up', config_path], 
                                      capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("WireGuard tunnel configured successfully")
                return True
            else:
                logger.error(f"WireGuard configuration failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"WireGuard configuration error: {str(e)}")
            return False
    
    def disconnect(self):
        """Disconnect from SDP network"""
        try:
            if self.tunnel_id:
                # Terminate tunnel at gateway
                headers = {'Authorization': f'Bearer {self.access_token}'}
                requests.delete(
                    f'{self.gateway_url}/api/tunnel/{self.tunnel_id}',
                    headers=headers,
                    timeout=5
                )
            
            # Stop local WireGuard
            if platform.system() == 'Windows':
                subprocess.run(['wg-quick', 'down', 'client.conf'], 
                             capture_output=True, text=True)
            else:
                subprocess.run(['sudo', 'wg-quick', 'down', 'client.conf'], 
                             capture_output=True, text=True)
            
            self.is_connected = False
            logger.info("Disconnected from SDP network")
            
        except Exception as e:
            logger.error(f"Disconnect error: {str(e)}")
    
    def _start_monitoring(self):
        """Start continuous monitoring thread"""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            return
        
        self.monitoring_thread = threading.Thread(target=self._monitor_connection, daemon=True)
        self.monitoring_thread.start()
    
    def _monitor_connection(self):
        """Monitor connection and device compliance"""
        while self.is_connected:
            try:
                # Update device information
                current_device_info = DeviceProfiler.get_device_info()
                
                # Check for significant changes
                if self._device_compliance_changed(current_device_info):
                    logger.warning("Device compliance status changed")
                    # Could trigger re-authentication or connection termination
                
                # Heartbeat to controller
                if self.access_token:
                    headers = {'Authorization': f'Bearer {self.access_token}'}
                    try:
                        response = requests.get(
                            f'{self.controller_url}/api/status',
                            headers=headers,
                            timeout=5
                        )
                        if response.status_code != 200:
                            logger.warning("Controller heartbeat failed")
                    except:
                        logger.warning("Controller unreachable")
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Monitoring error: {str(e)}")
                time.sleep(30)
    
    def _device_compliance_changed(self, current_info):
        """Check if device compliance status has changed"""
        try:
            # Compare key security indicators
            old_security = self.device_info.get('security', {})
            new_security = current_info.get('security', {})
            
            critical_fields = ['antivirus_running', 'firewall_enabled', 'disk_encryption']
            
            for field in critical_fields:
                if old_security.get(field) != new_security.get(field):
                    return True
            
            return False
            
        except:
            return False
    
    def get_status(self):
        """Get client connection status"""
        return {
            'connected': self.is_connected,
            'tunnel_id': getattr(self, 'tunnel_id', None),
            'device_id': self.device_info.get('device_id'),
            'last_update': datetime.utcnow().isoformat()
        }

def main():
    """Main client application"""
    if len(sys.argv) < 3:
        print("Usage: python client.py <username> <password> [controller_url] [gateway_url]")
        sys.exit(1)
    
    username = sys.argv[1]
    password = sys.argv[2]
    controller_url = sys.argv[3] if len(sys.argv) > 3 else 'http://localhost:8001'
    gateway_url = sys.argv[4] if len(sys.argv) > 4 else 'http://localhost:8002'
    
    # Initialize client
    client = SDPClient(controller_url, gateway_url)
    
    # Authenticate
    if not client.authenticate(username, password):
        print("Authentication failed")
        sys.exit(1)
    
    print("Authentication successful!")
    
    # Interactive mode
    try:
        while True:
            print("\nSDP Client Menu:")
            print("1. Request access to resource")
            print("2. Show connection status")
            print("3. Disconnect")
            print("4. Exit")
            
            choice = input("Enter choice (1-4): ").strip()
            
            if choice == '1':
                zone = input("Destination zone: ").strip()
                port = input("Destination port: ").strip()
                protocol = input("Protocol (tcp/udp) [tcp]: ").strip() or 'tcp'
                
                if client.request_access(zone, port, protocol):
                    print("Access granted and tunnel established!")
                else:
                    print("Access denied or tunnel failed")
            
            elif choice == '2':
                status = client.get_status()
                print(f"Connection Status: {json.dumps(status, indent=2)}")
            
            elif choice == '3':
                client.disconnect()
                print("Disconnected from SDP network")
            
            elif choice == '4':
                client.disconnect()
                print("Goodbye!")
                break
            
            else:
                print("Invalid choice")
                
    except KeyboardInterrupt:
        print("\nShutting down...")
        client.disconnect()

if __name__ == '__main__':
    main()
