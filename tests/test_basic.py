"""
Basic tests for the IoT Risk Detection System.
"""
import unittest
import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.utils.config import config
from src.database.models import Device, Alert, TrafficRecord
from src.database.database import db_service

class TestBasicFunctionality(unittest.TestCase):
    """Basic functionality tests."""
    
    def setUp(self):
        """Set up test environment."""
        # Create temporary directories
        self.temp_dir = tempfile.mkdtemp()
        self.data_dir = os.path.join(self.temp_dir, 'data')
        self.logs_dir = os.path.join(self.temp_dir, 'logs')
        self.models_dir = os.path.join(self.temp_dir, 'models')
        
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)
        os.makedirs(self.models_dir, exist_ok=True)
        
        # Update config to use temporary directories
        config.DATA_DIR = self.data_dir
        config.LOGS_DIR = self.logs_dir
        config.MODELS_DIR = self.models_dir
        config.DATABASE_URL = f"sqlite:///{self.data_dir}/test.db"
        
        # Initialize database
        db_service.initialize_database()
    
    def tearDown(self):
        """Clean up test environment."""
        # Remove temporary directory
        shutil.rmtree(self.temp_dir)
    
    def test_database_initialization(self):
        """Test database initialization."""
        # Check if database file was created using the same logic as Config.get_database_url()
        db_path = config.get_database_url().replace("sqlite:///", "")
        self.assertTrue(os.path.exists(db_path))
        
        # Check if tables were created
        session = db_service.get_session()
        try:
            # Try to query tables using text() wrapper
            from sqlalchemy import text
            session.execute(text("SELECT COUNT(*) FROM devices"))
            session.execute(text("SELECT COUNT(*) FROM alerts"))
            session.execute(text("SELECT COUNT(*) FROM traffic_records"))
            self.assertTrue(True)  # If we get here, tables exist
        except Exception as e:
            self.fail(f"Database tables not created properly: {e}")
        finally:
            session.close()
    
    def test_device_creation(self):
        """Test device creation and retrieval."""
        session = db_service.get_session()
        try:
            # Create a test device with unique IP
            device = Device(
                ip_address="192.168.1.250",
                mac_address="00:11:22:33:44:55",
                hostname="test-device-3",
                device_type="camera",
                vendor="Test Vendor",
                risk_score=0.5
            )
            session.add(device)
            session.commit()
            
            # Retrieve the device
            retrieved_device = session.query(Device).filter_by(ip_address="192.168.1.250").first()
            self.assertIsNotNone(retrieved_device)
            self.assertEqual(retrieved_device.hostname, "test-device-3")
            self.assertEqual(retrieved_device.device_type, "camera")
            self.assertEqual(retrieved_device.risk_score, 0.5)
            
        finally:
            session.close()
    
    def test_alert_creation(self):
        """Test alert creation and retrieval."""
        session = db_service.get_session()
        try:
            # Create a test alert
            alert = Alert(
                alert_type="test_alert",
                severity="high",
                title="Test Alert",
                message="This is a test alert",
                device_id=1
            )
            session.add(alert)
            session.commit()
            
            # Retrieve the alert
            retrieved_alert = session.query(Alert).filter_by(alert_type="test_alert").first()
            self.assertIsNotNone(retrieved_alert)
            self.assertEqual(retrieved_alert.severity, "high")
            self.assertEqual(retrieved_alert.title, "Test Alert")
            
        finally:
            session.close()
    
    def test_traffic_record_creation(self):
        """Test traffic record creation and retrieval."""
        session = db_service.get_session()
        try:
            # Create a test traffic record
            traffic_record = TrafficRecord(
                device_id=1,
                source_ip="192.168.1.100",
                destination_ip="192.168.1.1",
                protocol="TCP",
                packet_count=10,
                byte_count=1024,
                is_anomalous=False
            )
            session.add(traffic_record)
            session.commit()
            
            # Retrieve the traffic record
            retrieved_record = session.query(TrafficRecord).filter_by(source_ip="192.168.1.100").first()
            self.assertIsNotNone(retrieved_record)
            self.assertEqual(retrieved_record.protocol, "TCP")
            self.assertEqual(retrieved_record.packet_count, 10)
            self.assertEqual(retrieved_record.byte_count, 1024)
            self.assertFalse(retrieved_record.is_anomalous)
            
        finally:
            session.close()
    
    def test_config_validation(self):
        """Test configuration validation."""
        # Test valid configuration
        issues = config.validate_config()
        self.assertIsInstance(issues, list)
        
        # Test that required directories exist
        self.assertTrue(os.path.exists(config.DATA_DIR))
        self.assertTrue(os.path.exists(config.LOGS_DIR))
        self.assertTrue(os.path.exists(config.MODELS_DIR))
    
    def test_database_stats(self):
        """Test database statistics retrieval."""
        session = db_service.get_session()
        try:
            # Create some test data with unique IPs
            device = Device(ip_address="192.168.1.251", device_type="router")
            alert = Alert(alert_type="test_stats_2", severity="medium", title="Test Stats 2", message="Test")
            traffic = TrafficRecord(device_id=1, source_ip="192.168.1.251", destination_ip="192.168.1.1", protocol="TCP")
            
            session.add_all([device, alert, traffic])
            session.commit()
            
            # Get database stats
            stats = db_service.get_database_stats()
            
            # Check that stats contain expected keys
            expected_keys = ['devices', 'alerts', 'traffic_records']
            for key in expected_keys:
                self.assertIn(key, stats)
                self.assertGreaterEqual(stats[key], 1)
            
        finally:
            session.close()

class TestConfiguration(unittest.TestCase):
    """Configuration tests."""
    
    def test_config_loading(self):
        """Test configuration loading."""
        # Test that config has required attributes
        required_attrs = [
            'APP_NAME', 'APP_VERSION', 'DATABASE_URL', 'SCAN_NETWORK',
            'API_HOST', 'API_PORT', 'DASHBOARD_HOST', 'DASHBOARD_PORT'
        ]
        
        for attr in required_attrs:
            self.assertTrue(hasattr(config, attr))
    
    def test_risk_weights(self):
        """Test risk weight configuration."""
        weights = config.RISK_WEIGHTS
        
        # Check that all required weights are present
        required_weights = ['open_ports', 'vulnerabilities', 'default_credentials', 'traffic_anomalies', 'device_type']
        for weight in required_weights:
            self.assertIn(weight, weights)
            self.assertIsInstance(weights[weight], float)
            self.assertGreaterEqual(weights[weight], 0.0)
            self.assertLessEqual(weights[weight], 1.0)
    
    def test_device_risk_levels(self):
        """Test device risk level configuration."""
        risk_levels = config.DEVICE_RISK_LEVELS
        
        # Check that common device types are present
        common_types = ['camera', 'router', 'smart_tv', 'printer']
        for device_type in common_types:
            self.assertIn(device_type, risk_levels)
            self.assertIsInstance(risk_levels[device_type], float)
            self.assertGreaterEqual(risk_levels[device_type], 0.0)
            self.assertLessEqual(risk_levels[device_type], 1.0)

if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2) 