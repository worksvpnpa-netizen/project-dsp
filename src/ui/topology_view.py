"""
Network Topology Visualization Module for IoT Risk Detection System.
Renders rich node cards with icons, IP, Vendor, AP/VLAN metadata, and Risk badges.
"""

import math
from PyQt5.QtWidgets import QGraphicsView, QGraphicsScene, QGraphicsRectItem, QGraphicsTextItem, QGraphicsLineItem, QGraphicsItemGroup
from PyQt5.QtCore import Qt, QRectF, QPointF
from PyQt5.QtGui import QPen, QBrush, QColor, QFont, QPainter

class NetworkTopologyWidget(QGraphicsView):
    """Interactive node graph rendering rich network topology card nodes."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHint(QPainter.Antialiasing)
        self.setRenderHint(QPainter.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
        
        self.setBackgroundBrush(QBrush(QColor("#11111b")))
        self.devices = []
        self.gateway_ip = "192.168.137.1"

    def set_data(self, devices, gateway_ip=None):
        """Populates and draws the rich card topology map."""
        self.devices = devices
        if gateway_ip:
            self.gateway_ip = gateway_ip
        self.draw_topology()

    def _get_device_type_info(self, vendor, ports):
        v = (vendor or '').lower()
        port_list = [p['port'] for p in ports] if isinstance(ports, list) else []
        
        if 554 in port_list or 'cam' in v or 'hikvision' in v or 'dahua' in v:
            return "📷 IP CAMERA"
        elif 'router' in v or 'gateway' in v or 'cisco' in v or 'tp-link' in v or 'netgear' in v:
            return "🌐 ROUTER / AP"
        elif 'tv' in v or 'samsung' in v or 'lg' in v or 'roku' in v:
            return "📺 SMART TV"
        elif 'printer' in v or 'hp' in v or 'canon' in v or 'epson' in v:
            return "🖨️ PRINTER"
        elif 'phone' in v or 'apple' in v or 'android' in v:
            return "📱 MOBILE / TAB"
        else:
            return "🖥️ IOT DEVICE"

    def draw_topology(self):
        """Renders central Gateway node and host device cards in an orbit layout."""
        self.scene.clear()
        
        if not self.devices:
            text = self.scene.addText("No network topology data available. Run a network scan.")
            text.setDefaultTextColor(QColor("#a6adc8"))
            text.setFont(QFont("Segoe UI", 12))
            text.setPos(-180, -10)
            return

        center_x, center_y = 0, 0
        
        # Draw Central Gateway Node Card
        gw_w, gw_h = 190, 110
        gw_card = self.scene.addRect(
            center_x - gw_w/2, center_y - gw_h/2, gw_w, gw_h,
            QPen(QColor("#89b4fa"), 3), QBrush(QColor("#1e1e2e"))
        )
        
        gw_text = self.scene.addText(
            f"🌐 CENTRAL GATEWAY\n"
            f"IP: {self.gateway_ip}\n"
            f"Location: Local Gateway\n"
            f"AP: Main Router / VLAN 137\n"
            f"Status: ACTIVE"
        )
        gw_text.setDefaultTextColor(QColor("#cdd6f4"))
        font = QFont("Consolas", 8, QFont.Bold)
        gw_text.setFont(font)
        gw_text.setPos(center_x - gw_w/2 + 10, center_y - gw_h/2 + 8)

        # Distribute Host Device Cards around Gateway
        num_devices = len(self.devices)
        orbit_radius = max(320, num_devices * 65)
        
        card_w, card_h = 200, 120
        
        for i, device in enumerate(self.devices):
            angle = (2 * math.pi / num_devices) * i
            node_x = center_x + orbit_radius * math.cos(angle)
            node_y = center_y + orbit_radius * math.sin(angle)
            
            # Risk Color Coding
            risk_label = device.get('risk_label', 'Low')
            if risk_label == 'High':
                color_hex = "#f38ba8" # Red
                bg_color = QColor("#2a1b24")
            elif risk_label == 'Medium':
                color_hex = "#fab387" # Orange
                bg_color = QColor("#2a241b")
            else:
                color_hex = "#a6e3a1" # Green
                bg_color = QColor("#1b2a1e")

            border_color = QColor(color_hex)
            
            # Draw Connection Link to Gateway
            line = self.scene.addLine(
                center_x, center_y, node_x, node_y,
                QPen(border_color, 2, Qt.DashLine)
            )
            line.setZValue(-1)
            
            # Device Card Background
            card_rect = self.scene.addRect(
                node_x - card_w/2, node_y - card_h/2, card_w, card_h,
                QPen(border_color, 2), QBrush(bg_color)
            )
            
            # Extract Card Data
            vendor = device.get('vendor') or 'Generic Device'
            if len(vendor) > 16:
                vendor = vendor[:14] + '..'
            ip = device.get('ip', 'Unknown')
            mac = device.get('mac', 'Unknown')
            vlan = device.get('vlan', 'VLAN 137')
            ap_name = device.get('ap_name', 'Hotspot-AP')
            dev_type = self._get_device_type_info(vendor, device.get('ports', []))
            
            card_str = (
                f"┌─────────────────────────┐\n"
                f"  {dev_type}\n"
                f"  IP: {ip}\n"
                f"  Vendor: {vendor}\n"
                f"  Loc: {ap_name} / {vlan}\n"
                f"  Risk: {risk_label.upper()}\n"
                f"└─────────────────────────┘"
            )
            
            txt_item = self.scene.addText(card_str)
            txt_item.setDefaultTextColor(border_color)
            card_font = QFont("Consolas", 8, QFont.Bold)
            txt_item.setFont(card_font)
            txt_item.setPos(node_x - card_w/2 + 5, node_y - card_h/2 + 5)

        self.setSceneRect(self.scene.itemsBoundingRect().adjusted(-80, -80, 80, 80))
