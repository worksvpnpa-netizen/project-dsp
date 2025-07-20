"""
Notification system for the IoT Risk Detection System.
Supports Telegram and email notifications for security alerts.
"""
import logging
import smtplib
import json
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Union
import requests

from .config import config

logger = logging.getLogger(__name__)

class NotificationManager:
    """Manages notifications for security alerts and system events."""
    
    def __init__(self):
        self.telegram_enabled = bool(config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_CHAT_ID)
        self.email_enabled = bool(
            config.EMAIL_SMTP_SERVER and 
            config.EMAIL_USERNAME and 
            config.EMAIL_PASSWORD
        )
        self.alert_history = []
        self.max_history = 1000
        
    def send_alert(self, 
                   alert_type: str, 
                   message: str, 
                   severity: str = "medium",
                   device_info: Optional[Dict] = None,
                   metadata: Optional[Dict] = None) -> bool:
        """
        Send a security alert through configured notification channels.
        
        Args:
            alert_type: Type of alert (e.g., 'anomaly_detected', 'vulnerability_found')
            message: Alert message
            severity: Alert severity ('low', 'medium', 'high', 'critical')
            device_info: Information about the affected device
            metadata: Additional alert metadata
            
        Returns:
            bool: True if at least one notification was sent successfully
        """
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": alert_type,
            "message": message,
            "severity": severity,
            "device_info": device_info or {},
            "metadata": metadata or {}
        }
        
        # Add to history
        self.alert_history.append(alert)
        if len(self.alert_history) > self.max_history:
            self.alert_history.pop(0)
        
        # Check alert cooldown
        if self._is_in_cooldown(alert_type, device_info):
            logger.info(f"Alert {alert_type} in cooldown, skipping notification")
            return False
        
        # Check rate limiting
        if self._is_rate_limited():
            logger.warning("Alert rate limit exceeded, skipping notification")
            return False
        
        success = False
        
        # Send Telegram notification
        if self.telegram_enabled:
            if self._send_telegram_alert(alert):
                success = True
        
        # Send email notification
        if self.email_enabled:
            if self._send_email_alert(alert):
                success = True
        
        if success:
            logger.info(f"Alert sent successfully: {alert_type}")
        else:
            logger.error(f"Failed to send alert: {alert_type}")
        
        return success
    
    def _send_telegram_alert(self, alert: Dict) -> bool:
        """Send alert via Telegram bot."""
        try:
            # Format message
            message = self._format_telegram_message(alert)
            
            # Send to Telegram
            url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
            data = {
                "chat_id": config.TELEGRAM_CHAT_ID,
                "text": message,
                "parse_mode": "HTML"
            }
            
            response = requests.post(url, data=data, timeout=10)
            response.raise_for_status()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")
            return False
    
    def _send_email_alert(self, alert: Dict) -> bool:
        """Send alert via email."""
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = config.EMAIL_FROM or config.EMAIL_USERNAME
            msg['To'] = config.EMAIL_TO
            msg['Subject'] = f"IoT Security Alert: {alert['type'].replace('_', ' ').title()}"
            
            # Format message body
            body = self._format_email_message(alert)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(config.EMAIL_SMTP_SERVER, 587) as server:
                server.starttls()
                server.login(config.EMAIL_USERNAME, config.EMAIL_PASSWORD)
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False
    
    def _format_telegram_message(self, alert: Dict) -> str:
        """Format alert for Telegram message."""
        severity_emoji = {
            "low": "🟢",
            "medium": "🟡", 
            "high": "🟠",
            "critical": "🔴"
        }
        
        emoji = severity_emoji.get(alert['severity'], "⚪")
        
        message = f"{emoji} <b>IoT Security Alert</b>\n\n"
        message += f"<b>Type:</b> {alert['type'].replace('_', ' ').title()}\n"
        message += f"<b>Severity:</b> {alert['severity'].upper()}\n"
        message += f"<b>Time:</b> {alert['timestamp']}\n\n"
        message += f"<b>Message:</b>\n{alert['message']}\n"
        
        if alert['device_info']:
            device = alert['device_info']
            message += f"\n<b>Device:</b>\n"
            if device.get('ip'):
                message += f"IP: {device['ip']}\n"
            if device.get('mac'):
                message += f"MAC: {device['mac']}\n"
            if device.get('hostname'):
                message += f"Hostname: {device['hostname']}\n"
            if device.get('device_type'):
                message += f"Type: {device['device_type']}\n"
        
        if alert['metadata']:
            message += f"\n<b>Details:</b>\n"
            for key, value in alert['metadata'].items():
                message += f"{key}: {value}\n"
        
        return message
    
    def _format_email_message(self, alert: Dict) -> str:
        """Format alert for email message."""
        severity_color = {
            "low": "#28a745",
            "medium": "#ffc107",
            "high": "#fd7e14", 
            "critical": "#dc3545"
        }
        
        color = severity_color.get(alert['severity'], "#6c757d")
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .alert {{ border-left: 4px solid {color}; padding: 10px; margin: 10px 0; }}
                .header {{ background-color: #f8f9fa; padding: 10px; }}
                .details {{ margin: 10px 0; }}
                .device-info {{ background-color: #e9ecef; padding: 10px; margin: 10px 0; }}
            </style>
        </head>
        <body>
            <div class="alert">
                <div class="header">
                    <h2>IoT Security Alert</h2>
                    <p><strong>Type:</strong> {alert['type'].replace('_', ' ').title()}</p>
                    <p><strong>Severity:</strong> {alert['severity'].upper()}</p>
                    <p><strong>Time:</strong> {alert['timestamp']}</p>
                </div>
                
                <div class="details">
                    <h3>Message:</h3>
                    <p>{alert['message']}</p>
                </div>
        """
        
        if alert['device_info']:
            device = alert['device_info']
            html += f"""
                <div class="device-info">
                    <h3>Affected Device:</h3>
                    <p><strong>IP:</strong> {device.get('ip', 'N/A')}</p>
                    <p><strong>MAC:</strong> {device.get('mac', 'N/A')}</p>
                    <p><strong>Hostname:</strong> {device.get('hostname', 'N/A')}</p>
                    <p><strong>Type:</strong> {device.get('device_type', 'N/A')}</p>
                </div>
            """
        
        if alert['metadata']:
            html += f"""
                <div class="details">
                    <h3>Additional Details:</h3>
                    <ul>
            """
            for key, value in alert['metadata'].items():
                html += f"<li><strong>{key}:</strong> {value}</li>"
            html += "</ul></div>"
        
        html += """
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _is_in_cooldown(self, alert_type: str, device_info: Optional[Dict]) -> bool:
        """Check if alert is in cooldown period."""
        if not device_info:
            return False
        
        device_id = device_info.get('ip') or device_info.get('mac')
        if not device_id:
            return False
        
        # Check recent alerts for this device and type
        cutoff_time = datetime.now().timestamp() - config.ALERT_COOLDOWN
        
        for alert in reversed(self.alert_history):
            if (alert['type'] == alert_type and 
                alert['device_info'].get('ip') == device_id):
                alert_time = datetime.fromisoformat(alert['timestamp']).timestamp()
                if alert_time > cutoff_time:
                    return True
        
        return False
    
    def _is_rate_limited(self) -> bool:
        """Check if we're exceeding the alert rate limit."""
        cutoff_time = datetime.now().timestamp() - 3600  # 1 hour
        
        recent_alerts = 0
        for alert in reversed(self.alert_history):
            alert_time = datetime.fromisoformat(alert['timestamp']).timestamp()
            if alert_time > cutoff_time:
                recent_alerts += 1
            else:
                break
        
        return recent_alerts >= config.MAX_ALERTS_PER_HOUR
    
    def get_alert_history(self, 
                         alert_type: Optional[str] = None,
                         severity: Optional[str] = None,
                         limit: int = 100) -> List[Dict]:
        """Get alert history with optional filtering."""
        alerts = self.alert_history.copy()
        
        if alert_type:
            alerts = [a for a in alerts if a['type'] == alert_type]
        
        if severity:
            alerts = [a for a in alerts if a['severity'] == severity]
        
        return alerts[-limit:]
    
    def clear_alert_history(self) -> None:
        """Clear alert history."""
        self.alert_history.clear()
        logger.info("Alert history cleared")

# Global notification manager instance
notification_manager = NotificationManager() 