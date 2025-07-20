"""
Risk assessment module for the IoT Risk Detection System.
Analyzes vulnerabilities, default credentials, and calculates risk scores.
"""
import logging
import requests
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..utils.config import config
from ..database.models import Device, Vulnerability, DeviceCredential, Alert
from ..database.database import get_db_session
from ..utils.notifications import notification_manager

logger = logging.getLogger(__name__)

class RiskAssessment:
    """Handles comprehensive risk assessment of IoT devices."""
    
    def __init__(self):
        self.cve_cache = {}
        self.default_credentials = self._load_default_credentials()
        self.vulnerability_patterns = {
            'weak_password': r'(password|passwd|admin|root|123456|password123)',
            'default_credentials': r'(admin:admin|root:root|admin:password)',
            'outdated_firmware': r'(firmware|version|build).*?(201[0-9]|202[0-2])',
            'insecure_protocols': r'(telnet|ftp|http://)',
            'open_ports': r'(22|23|21|3389|5900)'
        }
    
    def assess_device_risk(self, device_id: int) -> Dict:
        """
        Perform comprehensive risk assessment for a device.
        
        Args:
            device_id: ID of the device to assess
            
        Returns:
            Dict containing risk assessment results
        """
        logger.info(f"Starting risk assessment for device {device_id}")
        
        try:
            session = get_db_session()
            device = session.query(Device).filter_by(id=device_id).first()
            
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            # Perform various risk assessments
            vulnerability_risk = self._assess_vulnerabilities(device)
            credential_risk = self._assess_credentials(device)
            port_risk = self._assess_open_ports(device)
            traffic_risk = self._assess_traffic_patterns(device)
            
            # Calculate overall risk score
            overall_risk = self._calculate_overall_risk(
                vulnerability_risk, credential_risk, port_risk, traffic_risk
            )
            
            # Update device risk score
            device.risk_score = overall_risk['score']
            session.commit()
            
            # Generate alerts for high-risk findings
            self._generate_risk_alerts(device, overall_risk)
            
            return {
                'device_id': device_id,
                'overall_risk': overall_risk,
                'vulnerability_risk': vulnerability_risk,
                'credential_risk': credential_risk,
                'port_risk': port_risk,
                'traffic_risk': traffic_risk,
                'assessment_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Risk assessment failed for device {device_id}: {e}")
            raise
    
    def _assess_vulnerabilities(self, device: Device) -> Dict:
        """Assess vulnerabilities for a device."""
        try:
            session = get_db_session()
            
            # Get existing vulnerabilities
            vulnerabilities = session.query(Vulnerability).filter_by(
                device_id=device.id, status='open'
            ).all()
            
            # Check for new vulnerabilities based on device characteristics
            new_vulnerabilities = self._check_for_vulnerabilities(device)
            
            # Calculate vulnerability risk score
            risk_score = 0.0
            critical_count = 0
            high_count = 0
            medium_count = 0
            low_count = 0
            
            all_vulns = vulnerabilities + new_vulnerabilities
            
            for vuln in all_vulns:
                if vuln.severity == 'critical':
                    risk_score += 0.4
                    critical_count += 1
                elif vuln.severity == 'high':
                    risk_score += 0.3
                    high_count += 1
                elif vuln.severity == 'medium':
                    risk_score += 0.2
                    medium_count += 1
                elif vuln.severity == 'low':
                    risk_score += 0.1
                    low_count += 1
            
            # Normalize to 0-1 range
            risk_score = min(risk_score, 1.0)
            
            return {
                'score': risk_score,
                'critical_count': critical_count,
                'high_count': high_count,
                'medium_count': medium_count,
                'low_count': low_count,
                'total_count': len(all_vulns),
                'vulnerabilities': [
                    {
                        'id': vuln.id,
                        'cve_id': vuln.cve_id,
                        'title': vuln.title,
                        'severity': vuln.severity,
                        'cvss_score': vuln.cvss_score
                    }
                    for vuln in all_vulns
                ]
            }
            
        except Exception as e:
            logger.error(f"Vulnerability assessment error: {e}")
            return {'score': 0.0, 'total_count': 0, 'vulnerabilities': []}
    
    def _check_for_vulnerabilities(self, device: Device) -> List[Vulnerability]:
        """Check for new vulnerabilities based on device characteristics."""
        new_vulnerabilities = []
        
        try:
            # Check firmware vulnerabilities
            if device.firmware_version:
                firmware_vulns = self._check_firmware_vulnerabilities(device)
                new_vulnerabilities.extend(firmware_vulns)
            
            # Check service vulnerabilities
            service_vulns = self._check_service_vulnerabilities(device)
            new_vulnerabilities.extend(service_vulns)
            
            # Check for known IoT device vulnerabilities
            iot_vulns = self._check_iot_vulnerabilities(device)
            new_vulnerabilities.extend(iot_vulns)
            
            # Save new vulnerabilities to database
            session = get_db_session()
            for vuln in new_vulnerabilities:
                vuln.device_id = device.id
                session.add(vuln)
            session.commit()
            
        except Exception as e:
            logger.error(f"Error checking for vulnerabilities: {e}")
        
        return new_vulnerabilities
    
    def _check_firmware_vulnerabilities(self, device: Device) -> List[Vulnerability]:
        """Check for firmware-related vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Query CVE database for firmware vulnerabilities
            if device.vendor and device.firmware_version:
                query = f"{device.vendor} {device.firmware_version}"
                
                # Check cache first
                if query in self.cve_cache:
                    cve_data = self.cve_cache[query]
                else:
                    cve_data = self._query_cve_database(query)
                    self.cve_cache[query] = cve_data
                
                for cve in cve_data:
                    vuln = Vulnerability(
                        cve_id=cve.get('id'),
                        title=cve.get('summary', 'Firmware vulnerability'),
                        description=cve.get('summary'),
                        severity=self._calculate_cvss_severity(cve.get('cvss', 0)),
                        cvss_score=cve.get('cvss', 0),
                        affected_component='firmware'
                    )
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.error(f"Error checking firmware vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _check_service_vulnerabilities(self, device: Device) -> List[Vulnerability]:
        """Check for service-related vulnerabilities."""
        vulnerabilities = []
        
        try:
            session = get_db_session()
            ports = session.query(Port).filter_by(device_id=device.id).all()
            
            for port in ports:
                if port.service_name and port.service_version:
                    # Check for known service vulnerabilities
                    service_query = f"{port.service_name} {port.service_version}"
                    cve_data = self._query_cve_database(service_query)
                    
                    for cve in cve_data:
                        vuln = Vulnerability(
                            cve_id=cve.get('id'),
                            title=f"{port.service_name} vulnerability",
                            description=cve.get('summary'),
                            severity=self._calculate_cvss_severity(cve.get('cvss', 0)),
                            cvss_score=cve.get('cvss', 0),
                            affected_component=port.service_name
                        )
                        vulnerabilities.append(vuln)
                        
        except Exception as e:
            logger.error(f"Error checking service vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _check_iot_vulnerabilities(self, device: Device) -> List[Vulnerability]:
        """Check for IoT-specific vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check for common IoT device vulnerabilities
            if device.device_type == 'camera':
                # Check for camera-specific vulnerabilities
                camera_vulns = self._check_camera_vulnerabilities(device)
                vulnerabilities.extend(camera_vulns)
            
            elif device.device_type == 'router':
                # Check for router-specific vulnerabilities
                router_vulns = self._check_router_vulnerabilities(device)
                vulnerabilities.extend(router_vulns)
            
            # Check for default credentials
            if self._has_default_credentials(device):
                vuln = Vulnerability(
                    title="Default credentials detected",
                    description="Device may be using default username/password",
                    severity="high",
                    affected_component="authentication"
                )
                vulnerabilities.append(vuln)
                
        except Exception as e:
            logger.error(f"Error checking IoT vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _assess_credentials(self, device: Device) -> Dict:
        """Assess credential-related risks."""
        try:
            session = get_db_session()
            credentials = session.query(DeviceCredential).filter_by(device_id=device.id).all()
            
            risk_score = 0.0
            default_cred_count = 0
            weak_cred_count = 0
            
            for cred in credentials:
                if cred.is_default:
                    risk_score += 0.3
                    default_cred_count += 1
                
                if self._is_weak_credential(cred):
                    risk_score += 0.2
                    weak_cred_count += 1
            
            # Check for common default credentials
            if self._has_default_credentials(device):
                risk_score += 0.4
            
            risk_score = min(risk_score, 1.0)
            
            return {
                'score': risk_score,
                'default_credentials': default_cred_count,
                'weak_credentials': weak_cred_count,
                'total_credentials': len(credentials)
            }
            
        except Exception as e:
            logger.error(f"Credential assessment error: {e}")
            return {'score': 0.0, 'default_credentials': 0, 'weak_credentials': 0, 'total_credentials': 0}
    
    def _assess_open_ports(self, device: Device) -> Dict:
        """Assess risks from open ports."""
        try:
            session = get_db_session()
            ports = session.query(Port).filter_by(device_id=device.id, is_open=True).all()
            
            risk_score = 0.0
            high_risk_ports = []
            
            for port in ports:
                if port.port_number in config.HIGH_RISK_PORTS:
                    risk_score += 0.2
                    high_risk_ports.append({
                        'port': port.port_number,
                        'service': port.service_name,
                        'risk': config.HIGH_RISK_PORTS[port.port_number]
                    })
            
            risk_score = min(risk_score, 1.0)
            
            return {
                'score': risk_score,
                'total_open_ports': len(ports),
                'high_risk_ports': high_risk_ports
            }
            
        except Exception as e:
            logger.error(f"Port assessment error: {e}")
            return {'score': 0.0, 'total_open_ports': 0, 'high_risk_ports': []}
    
    def _assess_traffic_patterns(self, device: Device) -> Dict:
        """Assess risks from traffic patterns."""
        try:
            session = get_db_session()
            
            # Get recent traffic records
            recent_traffic = session.query(TrafficRecord).filter(
                TrafficRecord.device_id == device.id,
                TrafficRecord.timestamp >= datetime.utcnow() - timedelta(hours=24)
            ).all()
            
            risk_score = 0.0
            anomaly_count = 0
            
            for traffic in recent_traffic:
                if traffic.is_anomalous:
                    risk_score += 0.1
                    anomaly_count += 1
            
            risk_score = min(risk_score, 1.0)
            
            return {
                'score': risk_score,
                'total_traffic_records': len(recent_traffic),
                'anomaly_count': anomaly_count
            }
            
        except Exception as e:
            logger.error(f"Traffic assessment error: {e}")
            return {'score': 0.0, 'total_traffic_records': 0, 'anomaly_count': 0}
    
    def _calculate_overall_risk(self, vuln_risk: Dict, cred_risk: Dict, 
                               port_risk: Dict, traffic_risk: Dict) -> Dict:
        """Calculate overall risk score using weighted factors."""
        
        # Apply weights from configuration
        overall_score = (
            vuln_risk['score'] * config.RISK_WEIGHTS['vulnerabilities'] +
            cred_risk['score'] * config.RISK_WEIGHTS['default_credentials'] +
            port_risk['score'] * config.RISK_WEIGHTS['open_ports'] +
            traffic_risk['score'] * config.RISK_WEIGHTS['traffic_anomalies']
        )
        
        # Determine risk level
        if overall_score >= 0.8:
            risk_level = 'critical'
        elif overall_score >= 0.6:
            risk_level = 'high'
        elif overall_score >= 0.4:
            risk_level = 'medium'
        elif overall_score >= 0.2:
            risk_level = 'low'
        else:
            risk_level = 'minimal'
        
        return {
            'score': overall_score,
            'level': risk_level,
            'factors': {
                'vulnerabilities': vuln_risk['score'],
                'credentials': cred_risk['score'],
                'ports': port_risk['score'],
                'traffic': traffic_risk['score']
            }
        }
    
    def _generate_risk_alerts(self, device: Device, overall_risk: Dict) -> None:
        """Generate alerts for high-risk findings."""
        try:
            if overall_risk['level'] in ['high', 'critical']:
                # Send notification
                notification_manager.send_alert(
                    alert_type='high_risk_device',
                    message=f"Device {device.ip_address} has {overall_risk['level']} risk level",
                    severity=overall_risk['level'],
                    device_info={
                        'ip': device.ip_address,
                        'mac': device.mac_address,
                        'hostname': device.hostname,
                        'device_type': device.device_type
                    },
                    metadata={
                        'risk_score': overall_risk['score'],
                        'risk_factors': overall_risk['factors']
                    }
                )
                
                # Create alert record
                session = get_db_session()
                alert = Alert(
                    alert_type='high_risk_device',
                    device_id=device.id,
                    severity=overall_risk['level'],
                    title=f"High Risk Device: {device.ip_address}",
                    message=f"Device has {overall_risk['level']} risk level with score {overall_risk['score']:.2f}",
                    metadata=overall_risk
                )
                session.add(alert)
                session.commit()
                
        except Exception as e:
            logger.error(f"Error generating risk alerts: {e}")
    
    def _query_cve_database(self, query: str) -> List[Dict]:
        """Query CVE database for vulnerabilities."""
        try:
            # Use CIRCL CVE database
            url = f"{config.CVE_API_URL}/search"
            params = {'q': query}
            
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            logger.error(f"Error querying CVE database: {e}")
            return []
    
    def _calculate_cvss_severity(self, cvss_score: float) -> str:
        """Calculate severity level from CVSS score."""
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        else:
            return 'low'
    
    def _load_default_credentials(self) -> Dict:
        """Load default credentials database."""
        try:
            with open(config.DEFAULT_CREDS_FILE, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("Default credentials file not found")
            return {}
        except Exception as e:
            logger.error(f"Error loading default credentials: {e}")
            return {}
    
    def _has_default_credentials(self, device: Device) -> bool:
        """Check if device has default credentials."""
        if not device.vendor or not device.device_type:
            return False
        
        vendor_creds = self.default_credentials.get(device.vendor.lower(), {})
        device_creds = vendor_creds.get(device.device_type.lower(), [])
        
        return len(device_creds) > 0
    
    def _is_weak_credential(self, credential: DeviceCredential) -> bool:
        """Check if credential is weak."""
        if not credential.password:
            return False
        
        password = credential.password.lower()
        
        # Check against common weak passwords
        weak_patterns = [
            'password', '123456', 'admin', 'root', 'default',
            'guest', 'user', 'test', 'demo', 'temp'
        ]
        
        return any(pattern in password for pattern in weak_patterns)
    
    def _check_camera_vulnerabilities(self, device: Device) -> List[Vulnerability]:
        """Check for camera-specific vulnerabilities."""
        vulnerabilities = []
        
        # Common camera vulnerabilities
        camera_vulns = [
            {
                'title': 'RTSP Authentication Bypass',
                'description': 'Camera may be vulnerable to RTSP authentication bypass',
                'severity': 'high'
            },
            {
                'title': 'Default Admin Credentials',
                'description': 'Camera may be using default admin credentials',
                'severity': 'high'
            }
        ]
        
        for vuln_info in camera_vulns:
            vuln = Vulnerability(
                title=vuln_info['title'],
                description=vuln_info['description'],
                severity=vuln_info['severity'],
                affected_component='camera_firmware'
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_router_vulnerabilities(self, device: Device) -> List[Vulnerability]:
        """Check for router-specific vulnerabilities."""
        vulnerabilities = []
        
        # Common router vulnerabilities
        router_vulns = [
            {
                'title': 'WPS PIN Vulnerability',
                'description': 'Router may be vulnerable to WPS PIN attacks',
                'severity': 'medium'
            },
            {
                'title': 'Default Admin Access',
                'description': 'Router may be accessible with default credentials',
                'severity': 'high'
            }
        ]
        
        for vuln_info in router_vulns:
            vuln = Vulnerability(
                title=vuln_info['title'],
                description=vuln_info['description'],
                severity=vuln_info['severity'],
                affected_component='router_firmware'
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities

# Global risk assessment instance
risk_assessment = RiskAssessment() 