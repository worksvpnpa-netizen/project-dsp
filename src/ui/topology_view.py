"""
Entity-Relationship Topology Visualization Module in Light Theme.
Renders real 2-tier network graph schemas without fake intermediate nodes.
"""

import math
from PyQt5.QtWidgets import QGraphicsView, QGraphicsScene
from PyQt5.QtCore import Qt, QPointF
from PyQt5.QtGui import QPen, QBrush, QColor, QFont, QPainter

class NetworkTopologyWidget(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHint(QPainter.Antialiasing)
        self.setRenderHint(QPainter.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
        
        self.setBackgroundBrush(QBrush(QColor("#f8fafc")))
        self.topology_graph = {"nodes": [], "links": []}

    def set_data(self, topology_graph, gateway_ip=None):
        if isinstance(topology_graph, dict) and "nodes" in topology_graph:
            self.topology_graph = topology_graph
        elif isinstance(topology_graph, list):
            from src.core.infrastructure_discovery import TopologyBuilder
            builder = TopologyBuilder()
            self.topology_graph = builder.build_topology(topology_graph)
            
        self.draw_topology()

    def draw_topology(self):
        self.scene.clear()
        
        nodes = self.topology_graph.get("nodes", [])
        links = self.topology_graph.get("links", [])
        
        if not nodes:
            text = self.scene.addText("No network topology data available. Run a network scan.")
            text.setDefaultTextColor(QColor("#64748b"))
            text.setFont(QFont("Segoe UI", 12))
            text.setPos(-200, -10)
            return

        node_positions = {}
        
        router_nodes = [n for n in nodes if n.get("type") == "router"]
        device_nodes = [n for n in nodes if n.get("type") == "device"]

        # Level 1: Gateway Router
        for n in router_nodes:
            node_positions[n["id"]] = QPointF(0, -220)

        # Level 2: Real Discovered Endpoints
        num_devs = len(device_nodes)
        if num_devs > 0:
            spacing = 260
            start_x = -((num_devs - 1) * spacing) / 2
            for idx, n in enumerate(device_nodes):
                node_positions[n["id"]] = QPointF(start_x + idx * spacing, 80 + (idx % 2) * 40)

        # DRAW LINKS
        for l in links:
            src_id = l["source"]
            tgt_id = l["target"]
            if src_id in node_positions and tgt_id in node_positions:
                p1 = node_positions[src_id]
                p2 = node_positions[tgt_id]
                
                link_type = l.get("type", "access")
                pen = QPen(QColor("#8b5cf6"), 2, Qt.DashLine) if link_type == "wireless" else QPen(QColor("#94a3b8"), 2, Qt.SolidLine)

                line = self.scene.addLine(p1.x(), p1.y(), p2.x(), p2.y(), pen)
                line.setZValue(-1)
                
                medium_label = l.get("source_port", "")
                if medium_label:
                    mid_x = (p1.x() + p2.x()) / 2
                    mid_y = (p1.y() + p2.y()) / 2
                    lbl = self.scene.addText(medium_label)
                    lbl.setDefaultTextColor(QColor("#475569"))
                    lbl.setFont(QFont("Consolas", 7, QFont.Bold))
                    lbl.setPos(mid_x - 30, mid_y - 10)

        # DRAW NODES
        for n in nodes:
            nid = n["id"]
            pos = node_positions.get(nid, QPointF(0, 0))
            ntype = n.get("type", "device")
            
            if ntype == "router":
                w, h = 260, 75
                rect = self.scene.addRect(
                    pos.x() - w/2, pos.y() - h/2, w, h,
                    QPen(QColor("#0284c7"), 2), QBrush(QColor("#f0f9ff"))
                )
                txt_content = "[ROUTER] " + str(n["name"]) + "\nIP: " + str(n.get("ip",""))
                txt = self.scene.addText(txt_content)
                txt.setDefaultTextColor(QColor("#0369a1"))
                txt.setFont(QFont("Consolas", 8, QFont.Bold))
                txt.setPos(pos.x() - w/2 + 10, pos.y() - h/2 + 10)

            else: # Host Device Card
                w, h = 250, 145
                r_label = n.get("risk_label", "Low")
                if r_label == "High":
                    border_hex = "#dc2626"
                    text_hex = "#991b1b"
                elif r_label == "Medium":
                    border_hex = "#d97706"
                    text_hex = "#92400e"
                else:
                    border_hex = "#16a34a"
                    text_hex = "#166534"

                rect = self.scene.addRect(
                    pos.x() - w/2, pos.y() - h/2, w, h,
                    QPen(QColor(border_hex), 2), QBrush(QColor("#ffffff"))
                )
                
                vendor = str(n.get("vendor", "Generic"))
                if len(vendor) > 16: vendor = vendor[:14] + ".."

                ports_arr = n.get("ports", [])
                ports_str = ", ".join(str(p) for p in ports_arr[:4]) if ports_arr else "None"
                vlan_str = str(n.get("vlan", "137"))
                conn_str = str(n.get("connected_to", "Gateway Router"))
                port_ap = str(n.get("port_or_ap", "Ethernet / LAN"))
                cat_str = str(n.get("category","IoT Device")).upper()
                ip_str = str(n.get("ip",""))
                mac_str = str(n.get("mac",""))

                card_str = (
                    "+----------------------------+\n" +
                    "  [DEVICE] " + cat_str + "\n" +
                    "  IP: " + ip_str + "\n" +
                    "  MAC: " + mac_str + "\n" +
                    "  Vendor: " + vendor + "\n" +
                    "  Ports: " + ports_str + "\n" +
                    "  Medium: " + port_ap + "\n" +
                    "  Risk: " + r_label.upper() + "\n" +
                    "+----------------------------+"
                )
                
                txt = self.scene.addText(card_str)
                txt.setDefaultTextColor(QColor(text_hex))
                txt.setFont(QFont("Consolas", 7, QFont.Bold))
                txt.setPos(pos.x() - w/2 + 4, pos.y() - h/2 + 4)

        self.setSceneRect(self.scene.itemsBoundingRect().adjusted(-60, -60, 60, 60))
