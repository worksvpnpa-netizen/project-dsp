"""
Multi-Tier Enterprise Network Topology Visualization Module.
Renders Core Router -> Switches/APs -> Subnets/VLANs -> Rich Device Cards.
"""

import math
from PyQt5.QtWidgets import QGraphicsView, QGraphicsScene, QGraphicsRectItem, QGraphicsTextItem, QGraphicsLineItem, QGraphicsItemGroup
from PyQt5.QtCore import Qt, QRectF, QPointF
from PyQt5.QtGui import QPen, QBrush, QColor, QFont, QPainter

class NetworkTopologyWidget(QGraphicsView):
    """Multi-tier hierarchical network topology view."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHint(QPainter.Antialiasing)
        self.setRenderHint(QPainter.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
        
        self.setBackgroundBrush(QBrush(QColor("#0f172a")))
        self.devices = []

    def set_data(self, devices, gateway_ip=None):
        """Populates and renders the multi-tier topology hierarchy."""
        self.devices = devices
        self.draw_topology()

    def draw_topology(self):
        """Renders Core Router (Level 1) -> Switches/APs (Level 2) -> Devices (Level 3)."""
        self.scene.clear()
        
        if not self.devices:
            text = self.scene.addText("No network topology data available. Please run a multi-subnet scan.")
            text.setDefaultTextColor(QColor("#94a3b8"))
            text.setFont(QFont("Segoe UI", 12))
            text.setPos(-200, -10)
            return

        # ---------------- LEVEL 1: CORE ROUTER ----------------
        core_x, core_y = 0, -250
        core_w, core_h = 240, 70
        
        core_rect = self.scene.addRect(
            core_x - core_w/2, core_y - core_h/2, core_w, core_h,
            QPen(QColor("#38bdf8"), 3), QBrush(QColor("#1e293b"))
        )
        
        core_txt = self.scene.addText("🏢 ENTERPRISE CORE ROUTER\nSubnets: Multi-VLAN L3 Core")
        core_txt.setDefaultTextColor(QColor("#f8fafc"))
        core_txt.setFont(QFont("Consolas", 9, QFont.Bold))
        core_txt.setPos(core_x - core_w/2 + 10, core_y - core_h/2 + 15)

        # Group Devices by Infrastructure Node (Switch / AP)
        infra_nodes = {}
        for dev in self.devices:
            disc = dev.get('discovered', {})
            sw_name = disc.get('connected_to', 'SW-01')
            if sw_name not in infra_nodes:
                infra_nodes[sw_name] = []
            infra_nodes[sw_name].append(dev)

        # ---------------- LEVEL 2: SWITCHES / ACCESS POINTS ----------------
        num_infra = len(infra_nodes)
        infra_spacing = 380
        start_infra_x = -((num_infra - 1) * infra_spacing) / 2
        
        for idx, (infra_name, dev_list) in enumerate(infra_nodes.items()):
            infra_x = start_infra_x + idx * infra_spacing
            infra_y = -50
            
            # Connect Core Router to Switch/AP
            line = self.scene.addLine(
                core_x, core_y + core_h/2, infra_x, infra_y - 30,
                QPen(QColor("#38bdf8"), 2, Qt.SolidLine)
            )
            line.setZValue(-1)
            
            # Draw Switch / AP Node Box
            box_w, box_h = 220, 60
            infra_icon = "📶" if "AP" in infra_name else "🔀"
            vlan_sample = dev_list[0].get('discovered', {}).get('vlan', '10') if dev_list else '10'
            
            self.scene.addRect(
                infra_x - box_w/2, infra_y - box_h/2, box_w, box_h,
                QPen(QColor("#818cf8"), 2), QBrush(QColor("#1e1b4b"))
            )
            
            sw_txt = self.scene.addText(f"{infra_icon} {infra_name} (VLAN {vlan_sample})\nDevices Attached: {len(dev_list)}")
            sw_txt.setDefaultTextColor(QColor("#e0e7ff"))
            sw_txt.setFont(QFont("Consolas", 8, QFont.Bold))
            sw_txt.setPos(infra_x - box_w/2 + 8, infra_y - box_h/2 + 12)

            # ---------------- LEVEL 3: RICH DEVICE CARDS ----------------
            num_devs = len(dev_list)
            dev_spacing = 220
            start_dev_x = infra_x - ((num_devs - 1) * dev_spacing) / 2
            
            for dev_idx, dev in enumerate(dev_list):
                dev_x = start_dev_x + dev_idx * dev_spacing
                dev_y = infra_y + 180 + (dev_idx % 2) * 30  # Staggered height
                
                # Connect Switch/AP to Device Card
                d_line = self.scene.addLine(
                    infra_x, infra_y + box_h/2, dev_x, dev_y - 60,
                    QPen(QColor("#64748b"), 1, Qt.DashLine)
                )
                d_line.setZValue(-1)
                
                # Risk Color Code
                r_label = dev.get('risk_label') or dev.get('inferred', {}).get('risk_label', 'Low')
                if r_label == 'High':
                    color_hex = "#f87171"
                    bg_color = QColor("#450a0a")
                elif r_label == 'Medium':
                    color_hex = "#fbbf24"
                    bg_color = QColor("#451a03")
                else:
                    color_hex = "#4ade80"
                    bg_color = QColor("#052e16")

                border_pen = QPen(QColor(color_hex), 2)
                
                # Device Card Box
                card_w, card_h = 205, 125
                self.scene.addRect(
                    dev_x - card_w/2, dev_y - card_h/2, card_w, card_h,
                    border_pen, QBrush(bg_color)
                )
                
                # Extract Data
                ip = dev.get('ip', '')
                mac = dev.get('mac', '')
                vendor = dev.get('vendor', 'Generic')
                if len(vendor) > 14:
                    vendor = vendor[:12] + '..'
                
                disc = dev.get('discovered', {})
                vlan = disc.get('vlan', '10')
                connected_to = disc.get('connected_to', 'SW-01')
                port_or_ap = disc.get('port_or_ap', 'Port 1')
                category = dev.get('inferred', {}).get('category', 'IoT Device')
                
                card_text = (
                    f"┌─────────────────────────┐\n"
                    f"  {category.upper()}\n"
                    f"  IP: {ip}\n"
                    f"  MAC: {mac[:14]}..\n"
                    f"  Vendor: {vendor}\n"
                    f"  VLAN: {vlan} | {connected_to}\n"
                    f"  Port: {port_or_ap}\n"
                    f"  Risk: {r_label.upper()}\n"
                    f"└─────────────────────────┘"
                )
                
                card_item = self.scene.addText(card_text)
                card_item.setDefaultTextColor(QColor(color_hex))
                card_item.setFont(QFont("Consolas", 8, QFont.Bold))
                card_item.setPos(dev_x - card_w/2 + 4, dev_y - card_h/2 + 4)

        self.setSceneRect(self.scene.itemsBoundingRect().adjusted(-80, -80, 80, 80))
