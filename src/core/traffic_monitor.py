"""
Traffic monitoring module for the IoT Risk Detection System.
Captures and analyzes network traffic for anomalies using Scapy.
"""
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque
import numpy as np

from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, Raw
from scapy.layers.inet import Ether

from ..utils.config import config
from ..database.models import Device, TrafficRecord, Alert
from ..database.database import get_db_session
from ..ai.models import anomaly_manager
from ..utils.notifications import notification_manager

logger = logging.getLogger(__name__)

class TrafficMonitor:
    """Monitors network traffic for anomalies and security threats."""
    
    def __init__(self):
        self.is_monitoring = False
        self.monitor_thread = None
        self.packet_buffer = deque(maxlen=config.PACKET_BUFFER_SIZE)
        self.device_traffic = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'connections': defaultdict(int),
            'ports': defaultdict(int),
            'protocols': defaultdict(int),
            'last_seen': None
        })
        self.anomaly_threshold = config.ANOMALY_THRESHOLD
        self.feature_window = deque(maxlen=config.FEATURE_WINDOW_SIZE)
        
    def start_monitoring(self, interface: Optional[str] = None) -> bool:
        """
        Start monitoring network traffic.
        
        Args:
            interface: Network interface to monitor (default: auto-detect)
            
        Returns:
            bool: True if monitoring started successfully
        """
        if self.is_monitoring:
            logger.warning("Traffic monitoring already running")
            return False
        
        try:
            logger.info("Starting traffic monitoring...")
            
            # Initialize anomaly detection models
            self._initialize_models()
            
            # Start monitoring thread
            self.is_monitoring = True
            self.monitor_thread = threading.Thread(
                target=self._monitor_traffic,
                args=(interface,),
                daemon=True
            )
            self.monitor_thread.start()
            
            logger.info("Traffic monitoring started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start traffic monitoring: {e}")
            self.is_monitoring = False
            return False
    
    def stop_monitoring(self) -> bool:
        """Stop traffic monitoring."""
        if not self.is_monitoring:
            logger.warning("Traffic monitoring not running")
            return False
        
        try:
            logger.info("Stopping traffic monitoring...")
            self.is_monitoring = False
            
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=5)
            
            logger.info("Traffic monitoring stopped")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping traffic monitoring: {e}")
            return False
    
    def _monitor_traffic(self, interface: Optional[str]) -> None:
        """Main traffic monitoring loop."""
        try:
            # Start packet capture
            sniff(
                iface=interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self.is_monitoring
            )
        except Exception as e:
            logger.error(f"Error in traffic monitoring: {e}")
            self.is_monitoring = False
    
    def _process_packet(self, packet) -> None:
        """Process individual network packet."""
        try:
            # Extract basic packet information
            packet_info = self._extract_packet_info(packet)
            if not packet_info:
                return
            
            # Add to buffer
            self.packet_buffer.append(packet_info)
            
            # Update device traffic statistics
            self._update_traffic_stats(packet_info)
            
            # Check for anomalies periodically
            if len(self.packet_buffer) % 100 == 0:
                self._check_for_anomalies()
            
            # Save to database periodically
            if len(self.packet_buffer) % 1000 == 0:
                self._save_traffic_records()
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _extract_packet_info(self, packet) -> Optional[Dict]:
        """Extract relevant information from a packet."""
        try:
            packet_info = {
                'timestamp': datetime.utcnow(),
                'length': len(packet),
                'protocol': 'unknown'
            }
            
            # Extract IP layer information
            if IP in packet:
                packet_info.update({
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': packet[IP].proto
                })
                
                # Extract TCP information
                if TCP in packet:
                    packet_info.update({
                        'src_port': packet[TCP].sport,
                        'dst_port': packet[TCP].dport,
                        'flags': str(packet[TCP].flags),
                        'protocol': 'TCP'
                    })
                
                # Extract UDP information
                elif UDP in packet:
                    packet_info.update({
                        'src_port': packet[UDP].sport,
                        'dst_port': packet[UDP].dport,
                        'protocol': 'UDP'
                    })
                
                # Extract ICMP information
                elif ICMP in packet:
                    packet_info.update({
                        'icmp_type': packet[ICMP].type,
                        'icmp_code': packet[ICMP].code,
                        'protocol': 'ICMP'
                    })
            
            # Extract ARP information
            elif ARP in packet:
                packet_info.update({
                    'src_ip': packet[ARP].psrc,
                    'dst_ip': packet[ARP].pdst,
                    'src_mac': packet[ARP].hwsrc,
                    'dst_mac': packet[ARP].hwdst,
                    'protocol': 'ARP'
                })
            
            # Extract payload information
            if Raw in packet:
                payload = packet[Raw].load
                packet_info['payload_size'] = len(payload)
                packet_info['payload_preview'] = payload[:100].hex()
            
            return packet_info
            
        except Exception as e:
            logger.debug(f"Error extracting packet info: {e}")
            return None
    
    def _update_traffic_stats(self, packet_info: Dict) -> None:
        """Update traffic statistics for devices."""
        try:
            # Update source device stats
            if 'src_ip' in packet_info:
                src_ip = packet_info['src_ip']
                self.device_traffic[src_ip]['packet_count'] += 1
                self.device_traffic[src_ip]['byte_count'] += packet_info['length']
                self.device_traffic[src_ip]['last_seen'] = packet_info['timestamp']
                
                if 'src_port' in packet_info:
                    self.device_traffic[src_ip]['ports'][packet_info['src_port']] += 1
                
                if 'dst_ip' in packet_info:
                    connection = f"{src_ip}:{packet_info.get('src_port', 0)} -> {packet_info['dst_ip']}:{packet_info.get('dst_port', 0)}"
                    self.device_traffic[src_ip]['connections'][connection] += 1
                
                self.device_traffic[src_ip]['protocols'][packet_info['protocol']] += 1
            
            # Update destination device stats
            if 'dst_ip' in packet_info:
                dst_ip = packet_info['dst_ip']
                self.device_traffic[dst_ip]['packet_count'] += 1
                self.device_traffic[dst_ip]['byte_count'] += packet_info['length']
                self.device_traffic[dst_ip]['last_seen'] = packet_info['timestamp']
                
                if 'dst_port' in packet_info:
                    self.device_traffic[dst_ip]['ports'][packet_info['dst_port']] += 1
                
                self.device_traffic[dst_ip]['protocols'][packet_info['protocol']] += 1
                
        except Exception as e:
            logger.error(f"Error updating traffic stats: {e}")
    
    def _check_for_anomalies(self) -> None:
        """Check for anomalies in recent traffic."""
        try:
            if len(self.packet_buffer) < 10:
                return
            
            # Extract features from recent traffic
            features = self._extract_traffic_features()
            if features is None:
                return
            
            # Add to feature window
            self.feature_window.append(features)
            
            # Check if we have enough data for anomaly detection
            if len(self.feature_window) < 50:
                return
            
            # Convert to numpy array
            feature_array = np.array(list(self.feature_window))
            
            # Predict anomalies
            anomaly_results = anomaly_manager.predict_anomalies(feature_array)
            
            # Process results
            self._process_anomaly_results(anomaly_results)
            
        except Exception as e:
            logger.error(f"Error checking for anomalies: {e}")
    
    def _extract_traffic_features(self) -> Optional[np.ndarray]:
        """Extract features from recent traffic for anomaly detection."""
        try:
            if len(self.packet_buffer) == 0:
                return None
            
            # Get recent packets
            recent_packets = list(self.packet_buffer)[-100:]
            
            # Calculate features
            features = []
            
            # Packet size statistics
            packet_sizes = [p['length'] for p in recent_packets]
            features.extend([
                np.mean(packet_sizes),
                np.std(packet_sizes),
                np.min(packet_sizes),
                np.max(packet_sizes)
            ])
            
            # Protocol distribution
            protocols = [p.get('protocol', 'unknown') for p in recent_packets]
            protocol_counts = defaultdict(int)
            for protocol in protocols:
                protocol_counts[protocol] += 1
            
            features.extend([
                protocol_counts.get('TCP', 0),
                protocol_counts.get('UDP', 0),
                protocol_counts.get('ICMP', 0),
                protocol_counts.get('ARP', 0)
            ])
            
            # Port statistics
            src_ports = [p.get('src_port', 0) for p in recent_packets if 'src_port' in p]
            dst_ports = [p.get('dst_port', 0) for p in recent_packets if 'dst_port' in p]
            
            features.extend([
                len(set(src_ports)),  # Unique source ports
                len(set(dst_ports)),  # Unique destination ports
                np.mean(src_ports) if src_ports else 0,
                np.mean(dst_ports) if dst_ports else 0
            ])
            
            # Connection patterns
            connections = []
            for p in recent_packets:
                if 'src_ip' in p and 'dst_ip' in p:
                    conn = f"{p['src_ip']}:{p.get('src_port', 0)} -> {p['dst_ip']}:{p.get('dst_port', 0)}"
                    connections.append(conn)
            
            features.extend([
                len(set(connections)),  # Unique connections
                len(connections) / max(len(set(connections)), 1)  # Connection reuse ratio
            ])
            
            # Time-based features
            timestamps = [p['timestamp'] for p in recent_packets]
            if len(timestamps) > 1:
                time_diffs = [(timestamps[i] - timestamps[i-1]).total_seconds() 
                             for i in range(1, len(timestamps))]
                features.extend([
                    np.mean(time_diffs),
                    np.std(time_diffs)
                ])
            else:
                features.extend([0, 0])
            
            return np.array(features)
            
        except Exception as e:
            logger.error(f"Error extracting traffic features: {e}")
            return None
    
    def _process_anomaly_results(self, results: Dict) -> None:
        """Process anomaly detection results."""
        try:
            if 'ensemble' in results and results['ensemble']:
                # Ensemble prediction
                ensemble_pred = results['ensemble_prediction']
                ensemble_conf = results['ensemble_confidence']
                
                # Check for anomalies
                anomaly_indices = np.where(ensemble_pred == 1)[0]
                
                for idx in anomaly_indices:
                    confidence = ensemble_conf[idx]
                    if confidence > self.anomaly_threshold:
                        self._handle_anomaly_detection(confidence, idx)
            
            elif 'model_name' in results:
                # Single model prediction
                predictions = results['predictions']
                probabilities = results['probabilities']
                
                # Check for anomalies based on model type
                model_name = results['model_name']
                if model_name == "isolation_forest":
                    # Isolation Forest: -1 = anomaly
                    anomaly_indices = np.where(predictions == -1)[0]
                elif model_name == "dbscan":
                    # DBSCAN: -1 = noise/anomaly
                    anomaly_indices = np.where(predictions == -1)[0]
                elif model_name == "lstm":
                    # LSTM: 0 = anomaly
                    anomaly_indices = np.where(predictions == 0)[0]
                else:
                    return
                
                for idx in anomaly_indices:
                    if idx < len(probabilities):
                        score = probabilities[idx]
                        if score > self.anomaly_threshold:
                            self._handle_anomaly_detection(score, idx)
                            
        except Exception as e:
            logger.error(f"Error processing anomaly results: {e}")
    
    def _handle_anomaly_detection(self, score: float, index: int) -> None:
        """Handle detected anomaly."""
        try:
            # Get the anomalous traffic data
            if index < len(self.feature_window):
                anomalous_features = list(self.feature_window)[index]
                
                # Find the device most likely responsible
                device_ip = self._identify_anomalous_device(anomalous_features)
                
                if device_ip:
                    # Create traffic record
                    self._create_anomaly_record(device_ip, score, anomalous_features)
                    
                    # Send alert
                    self._send_anomaly_alert(device_ip, score)
                    
        except Exception as e:
            logger.error(f"Error handling anomaly detection: {e}")
    
    def _identify_anomalous_device(self, features: np.ndarray) -> Optional[str]:
        """Identify the device most likely responsible for the anomaly."""
        try:
            # Simple heuristic: find device with most recent traffic
            if not self.device_traffic:
                return None
            
            # Get device with highest recent activity
            most_active_device = max(
                self.device_traffic.items(),
                key=lambda x: x[1]['packet_count']
            )[0]
            
            return most_active_device
            
        except Exception as e:
            logger.error(f"Error identifying anomalous device: {e}")
            return None
    
    def _create_anomaly_record(self, device_ip: str, score: float, features: np.ndarray) -> None:
        """Create traffic record for anomaly."""
        try:
            session = get_db_session()
            
            # Find device in database
            device = session.query(Device).filter_by(ip_address=device_ip).first()
            if not device:
                logger.warning(f"Device {device_ip} not found in database")
                return
            
            # Create traffic record
            traffic_record = TrafficRecord(
                device_id=device.id,
                source_ip=device_ip,
                destination_ip="unknown",  # Could be enhanced
                protocol="mixed",
                packet_count=1,
                byte_count=0,
                is_anomalous=True,
                anomaly_score=score,
                metadata={
                    'features': features.tolist(),
                    'detection_method': 'ai_anomaly_detection'
                }
            )
            
            session.add(traffic_record)
            session.commit()
            
        except Exception as e:
            logger.error(f"Error creating anomaly record: {e}")
    
    def _send_anomaly_alert(self, device_ip: str, score: float) -> None:
        """Send alert for detected anomaly."""
        try:
            session = get_db_session()
            device = session.query(Device).filter_by(ip_address=device_ip).first()
            
            if device:
                # Send notification
                notification_manager.send_alert(
                    alert_type='traffic_anomaly',
                    message=f"Anomalous traffic detected from {device_ip}",
                    severity='high' if score > 0.8 else 'medium',
                    device_info={
                        'ip': device.ip_address,
                        'mac': device.mac_address,
                        'hostname': device.hostname,
                        'device_type': device.device_type
                    },
                    metadata={
                        'anomaly_score': score,
                        'detection_timestamp': datetime.utcnow().isoformat()
                    }
                )
                
                # Create alert record
                alert = Alert(
                    alert_type='traffic_anomaly',
                    device_id=device.id,
                    severity='high' if score > 0.8 else 'medium',
                    title=f"Traffic Anomaly: {device_ip}",
                    message=f"Anomalous traffic pattern detected with score {score:.2f}",
                    metadata={'anomaly_score': score}
                )
                
                session.add(alert)
                session.commit()
                
        except Exception as e:
            logger.error(f"Error sending anomaly alert: {e}")
    
    def _save_traffic_records(self) -> None:
        """Save traffic records to database."""
        try:
            if not self.packet_buffer:
                return
            
            session = get_db_session()
            records_to_save = []
            
            # Process recent packets
            recent_packets = list(self.packet_buffer)[-1000:]  # Last 1000 packets
            
            for packet in recent_packets:
                if 'src_ip' in packet:
                    # Find device in database
                    device = session.query(Device).filter_by(ip_address=packet['src_ip']).first()
                    if device:
                        record = TrafficRecord(
                            device_id=device.id,
                            source_ip=packet['src_ip'],
                            destination_ip=packet.get('dst_ip', 'unknown'),
                            source_port=packet.get('src_port'),
                            destination_port=packet.get('dst_port'),
                            protocol=packet.get('protocol', 'unknown'),
                            packet_count=1,
                            byte_count=packet['length'],
                            flags=packet.get('flags'),
                            payload_size=packet.get('payload_size', 0),
                            is_anomalous=False,
                            metadata={
                                'timestamp': packet['timestamp'].isoformat(),
                                'packet_length': packet['length']
                            }
                        )
                        records_to_save.append(record)
            
            # Bulk insert
            if records_to_save:
                session.bulk_save_objects(records_to_save)
                session.commit()
                logger.info(f"Saved {len(records_to_save)} traffic records")
            
            # Clear buffer
            self.packet_buffer.clear()
            
        except Exception as e:
            logger.error(f"Error saving traffic records: {e}")
    
    def _initialize_models(self) -> None:
        """Initialize anomaly detection models."""
        try:
            # Create models
            isolation_forest = anomaly_manager.create_model("isolation_forest", "isolation_forest")
            dbscan = anomaly_manager.create_model("dbscan", "dbscan")
            lstm = anomaly_manager.create_model("lstm", "lstm", sequence_length=10)
            
            # Try to load pre-trained models
            anomaly_manager.load_all_models()
            
            logger.info("Anomaly detection models initialized")
            
        except Exception as e:
            logger.error(f"Error initializing models: {e}")
    
    def get_traffic_stats(self) -> Dict:
        """Get current traffic statistics."""
        try:
            stats = {
                'is_monitoring': self.is_monitoring,
                'packet_buffer_size': len(self.packet_buffer),
                'feature_window_size': len(self.feature_window),
                'devices_monitored': len(self.device_traffic),
                'total_packets_processed': sum(d['packet_count'] for d in self.device_traffic.values()),
                'total_bytes_processed': sum(d['byte_count'] for d in self.device_traffic.values()),
                'device_stats': {}
            }
            
            # Add per-device statistics
            for ip, data in self.device_traffic.items():
                stats['device_stats'][ip] = {
                    'packet_count': data['packet_count'],
                    'byte_count': data['byte_count'],
                    'last_seen': data['last_seen'].isoformat() if data['last_seen'] else None,
                    'unique_connections': len(data['connections']),
                    'unique_ports': len(data['ports']),
                    'protocols': dict(data['protocols'])
                }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting traffic stats: {e}")
            return {}

# Global traffic monitor instance
traffic_monitor = TrafficMonitor() 