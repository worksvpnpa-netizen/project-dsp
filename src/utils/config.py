"""
Configuration settings for the Unified IoT Risk & Threat Detection System.
"""
import os
from dotenv import load_dotenv
from typing import Dict, List, Optional

# Load environment variables
load_dotenv()

class Config:
    """Main configuration class for the IoT Risk Detection System."""
    
    # Application Settings
    APP_NAME = "IoT Risk & Threat Detection System"
    APP_VERSION = "1.0.0"
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    
    # Database Configuration
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///data/iot_risk_detect.db")
    
    # Network Configuration
    SCAN_NETWORK = os.getenv("SCAN_NETWORK", "192.168.1.0/24")
    SCAN_INTERFACE = os.getenv("SCAN_INTERFACE", "eth0")
    SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "300"))  # 5 minutes
    SCAN_RATE = int(os.getenv("SCAN_RATE", "1000"))  # packets per second
    
    # API Configuration
    API_HOST = os.getenv("API_HOST", "0.0.0.0")
    API_PORT = int(os.getenv("API_PORT", "5000"))
    API_DEBUG = os.getenv("API_DEBUG", "False").lower() == "true"
    
    # Dashboard Configuration
    DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "localhost")
    DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8501"))
    
    # AI/ML Configuration
    ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "0.8"))
    MODEL_UPDATE_INTERVAL = int(os.getenv("MODEL_UPDATE_INTERVAL", "3600"))  # 1 hour
    FEATURE_WINDOW_SIZE = int(os.getenv("FEATURE_WINDOW_SIZE", "100"))
    
    # Notification Configuration
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
    EMAIL_SMTP_SERVER = os.getenv("EMAIL_SMTP_SERVER")
    EMAIL_USERNAME = os.getenv("EMAIL_USERNAME")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
    EMAIL_FROM = os.getenv("EMAIL_FROM")
    EMAIL_TO = os.getenv("EMAIL_TO")
    
    # Logging Configuration
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = os.getenv("LOG_FILE", "logs/iot_risk_detect.log")
    LOG_MAX_SIZE = int(os.getenv("LOG_MAX_SIZE", "10485760"))  # 10MB
    LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", "5"))
    
    # Security Configuration
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-jwt-secret-key")
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", "3600"))  # 1 hour
    
    # CVE Database Configuration
    CVE_API_URL = "https://cve.circl.lu/api/cve"
    CVE_UPDATE_INTERVAL = int(os.getenv("CVE_UPDATE_INTERVAL", "86400"))  # 24 hours
    
    # MAC Vendor Database
    MAC_VENDOR_API_URL = "https://api.macvendors.com"
    
    # Default Credentials Database
    DEFAULT_CREDS_FILE = "data/default_credentials.json"
    
    # Risk Scoring Weights
    RISK_WEIGHTS = {
        "open_ports": 0.2,
        "vulnerabilities": 0.3,
        "default_credentials": 0.25,
        "traffic_anomalies": 0.15,
        "device_type": 0.1
    }
    
    # Device Type Risk Levels
    DEVICE_RISK_LEVELS = {
        "camera": 0.8,
        "router": 0.9,
        "smart_tv": 0.6,
        "smartphone": 0.4,
        "laptop": 0.3,
        "desktop": 0.3,
        "printer": 0.5,
        "thermostat": 0.7,
        "light_bulb": 0.4,
        "speaker": 0.5,
        "unknown": 0.5
    }
    
    # High-Risk Ports
    HIGH_RISK_PORTS = {
        22: "SSH",
        23: "Telnet",
        21: "FTP",
        3389: "RDP",
        5900: "VNC",
        8080: "HTTP Proxy",
        8443: "HTTPS Alternative",
        22: "SSH",
        23: "Telnet",
        21: "FTP",
        3389: "RDP",
        5900: "VNC",
        8080: "HTTP Proxy",
        8443: "HTTPS Alternative"
    }
    
    # Monitoring Configuration
    TRAFFIC_CAPTURE_INTERVAL = int(os.getenv("TRAFFIC_CAPTURE_INTERVAL", "60"))  # 1 minute
    PACKET_BUFFER_SIZE = int(os.getenv("PACKET_BUFFER_SIZE", "1000"))
    MAX_PACKET_SIZE = int(os.getenv("MAX_PACKET_SIZE", "65535"))
    
    # Alert Configuration
    ALERT_COOLDOWN = int(os.getenv("ALERT_COOLDOWN", "300"))  # 5 minutes
    MAX_ALERTS_PER_HOUR = int(os.getenv("MAX_ALERTS_PER_HOUR", "10"))
    
    # File Paths
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    DATA_DIR = os.path.join(BASE_DIR, "data")
    MODELS_DIR = os.path.join(BASE_DIR, "models")
    LOGS_DIR = os.path.join(BASE_DIR, "logs")
    
    @classmethod
    def get_database_url(cls) -> str:
        """Get database URL with proper formatting."""
        if cls.DATABASE_URL.startswith("sqlite:///"):
            db_path = cls.DATABASE_URL.replace("sqlite:///", "")
            if not os.path.isabs(db_path):
                db_path = os.path.join(cls.BASE_DIR, db_path)
            return f"sqlite:///{db_path}"
        return cls.DATABASE_URL
    
    @classmethod
    def validate_config(cls) -> List[str]:
        """Validate configuration and return list of issues."""
        issues = []
        
        # Check required directories
        for dir_path in [cls.DATA_DIR, cls.MODELS_DIR, cls.LOGS_DIR]:
            if not os.path.exists(dir_path):
                try:
                    os.makedirs(dir_path, exist_ok=True)
                except Exception as e:
                    issues.append(f"Cannot create directory {dir_path}: {e}")
        
        # Check network configuration
        if not cls.SCAN_NETWORK:
            issues.append("SCAN_NETWORK is not configured")
        
        # Check notification configuration
        if cls.TELEGRAM_BOT_TOKEN and not cls.TELEGRAM_CHAT_ID:
            issues.append("TELEGRAM_BOT_TOKEN provided but TELEGRAM_CHAT_ID is missing")
        
        if cls.EMAIL_SMTP_SERVER and not all([cls.EMAIL_USERNAME, cls.EMAIL_PASSWORD]):
            issues.append("Email configuration incomplete")
        
        return issues

# Global configuration instance
config = Config() 