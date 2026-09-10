import sys
import os
import csv
import threading
import time
import warnings

try:
    from scapy.data import MANUF_PATH, update_manuf
    if not os.path.exists(MANUF_PATH):
        update_manuf()
    os.environ['SCAPY_MANUF'] = MANUF_PATH
except Exception as e:
    warnings.filterwarnings("ignore", message=".*cannot read manuf.*")

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget, QMessageBox, QLineEdit, QLabel, QHBoxLayout,
    QFileDialog, QDialog, QFormLayout, QStatusBar, QTabWidget, QComboBox, QFrame
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QColor, QFont, QBrush

from src.ui.topology_view import NetworkTopologyWidget
from src.core.device_discovery import DeviceDiscovery
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
import numpy as np


def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0


if not is_admin():
    if sys.platform == 'win32':
        import ctypes
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()


def assess_device_risk(device):
    open_ports = [
        p['port'] for p in device.get('ports', [])
    ] if isinstance(device.get('ports'), list) else []

    vendor = (device.get('vendor') or '').lower()
    mac = (device.get('mac') or '').lower()
    category = device.get('inferred', {}).get('category', '')

    risk_score = 0.0
    reasons = []
    risky_ports = {23, 21, 3389, 5900, 445, 139, 5000, 8888, 80, 8080, 22}
    risky_found = [p for p in open_ports if p in risky_ports]

    if risky_found:
        risk_score += 0.4
        reasons.append(f"Open exposure ports: {risky_found}")

    if category == "IP Camera" and (80 in open_ports or 554 in open_ports):
        risk_score += 0.3
        reasons.append("Unencrypted Camera Stream Exposure (RTSP/HTTP)")

    if not vendor or 'generic' in vendor:
        risk_score += 0.2
        reasons.append("Unknown hardware MAC vendor OUI")

    if mac.startswith("00:00:00"):
        risk_score += 0.2
        reasons.append("Suspicious broadcast MAC address")

    risk_score = min(risk_score, 1.0)

    if risk_score >= 0.7:
        label = "High"
    elif risk_score >= 0.4:
        label = "Medium"
    else:
        label = "Low"

    return risk_score, label, "; ".join(reasons) or "Standard Operational Parameters"


def assess_botnet_risk(device, traffic):
    ip = device.get('ip', '')
    if not ip:
        return 0.0, "Low", "No IP address"

    ext_ips = set()
    suspicious_ports = set()
    bad_ip_contact = False
    known_bad_ips = {
        "185.234.219.167",
        "45.9.148.204",
        "185.220.101.1"
    }

    for pkt in traffic:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst

            if src == ip:
                ext_ips.add(dst)
                if dst in known_bad_ips:
                    bad_ip_contact = True
                if TCP in pkt:
                    suspicious_ports.add(pkt[TCP].dport)

            elif dst == ip:
                ext_ips.add(src)
                if src in known_bad_ips:
                    bad_ip_contact = True
                if TCP in pkt:
                    suspicious_ports.add(pkt[TCP].sport)

    risk_score = 0.0
    reasons = []

    if bad_ip_contact:
        risk_score += 0.7
        reasons.append("Contacted known C2 IP")

    if len(ext_ips) > 10:
        risk_score += 0.3
        reasons.append(f"High outbound contacts: {len(ext_ips)} IPs")

    if risk_score == 0.0:
        reasons.append("Normal traffic behavior")

    risk_score = min(risk_score, 1.0)
    label = (
        "High" if risk_score >= 0.7
        else ("Medium" if risk_score >= 0.4 else "Low")
    )

    return risk_score, label, "; ".join(reasons)


def ml_botnet_anomaly_scores(devices, traffic):
    features = []

    for device in devices:
        ip = device.get('ip')
        pkts = traffic.get(ip, [])
        ext_ips = set()
        ports = set()

        for p in pkts:
            if IP in p:
                if p[IP].src == ip:
                    ext_ips.add(p[IP].dst)
                    if TCP in p:
                        ports.add(p[TCP].dport)
                elif p[IP].dst == ip:
                    ext_ips.add(p[IP].src)
                    if TCP in p:
                        ports.add(p[TCP].sport)

        features.append([len(ext_ips), len(ports), len(pkts)])

    X = np.array(features)

    if len(X) < 2:
        return {
            device.get('ip'): (
                0.0,
                "Low",
                "Insufficient traffic samples for ML"
            )
            for device in devices
        }

    clf = IsolationForest(contamination=0.15, random_state=42)
    preds = clf.fit_predict(X)
    scores = clf.decision_function(X)

    ml_risks = {}

    for i, device in enumerate(devices):
        ip = device.get('ip')

        if preds[i] == -1:
            ml_risks[ip] = (
                1.0,
                "High",
                f"Anomalous pattern detected (score={scores[i]:.2f})"
            )
        else:
            ml_risks[ip] = (
                0.0,
                "Low",
                f"Normal traffic pattern (score={scores[i]:.2f})"
            )

    return ml_risks


class KPICard(QFrame):
    def __init__(self, title, value, icon, color_hex):
        super().__init__()

        self.setStyleSheet(f"""
            QFrame {{
                background-color: #ffffff;
                border: 1px solid #e2e8f0;
                border-left: 4px solid {color_hex};
                border-radius: 8px;
                padding: 10px;
            }}
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 6, 12, 6)

        lbl_title = QLabel(f"{icon} {title}")
        lbl_title.setStyleSheet(
            "color: #64748b; font-size: 11px; font-weight: bold;"
        )

        self.lbl_value = QLabel(str(value))
        self.lbl_value.setStyleSheet(
            f"color: {color_hex}; font-size: 22px; font-weight: bold;"
        )

        layout.addWidget(lbl_title)
        layout.addWidget(self.lbl_value)
        self.setLayout(layout)

    def set_value(self, val):
        self.lbl_value.setText(str(val))


class TrafficMonitorThread(QThread):
    traffic_captured = pyqtSignal(dict)

    def __init__(self, device_ips, duration=6):
        super().__init__()
        self.device_ips = set(device_ips)
        self.duration = duration
        self.captured = {ip: [] for ip in self.device_ips}

    def run(self):
        def pkt_handler(pkt):
            if IP in pkt:
                if pkt[IP].src in self.device_ips:
                    self.captured[pkt[IP].src].append(pkt)

                if pkt[IP].dst in self.device_ips:
                    self.captured[pkt[IP].dst].append(pkt)

        sniff(timeout=self.duration, prn=pkt_handler, store=False)
        self.traffic_captured.emit(self.captured)


class DeviceDetailsDialog(QDialog):
    def __init__(self, device, botnet_risk=None, ml_risk=None, parent=None):
        super().__init__(parent)

        self.setWindowTitle(f"Device Details - {device.get('ip')}")
        self.resize(520, 500)

        self.setStyleSheet("""
            QDialog {
                background-color: #ffffff;
                color: #0f172a;
            }
            QLabel {
                color: #334155;
                font-size: 12px;
            }
        """)

        layout = QFormLayout()
        layout.setSpacing(10)

        risk_score, risk_label, risk_reason = assess_device_risk(device)
        disc = device.get('discovered', {})
        iot_meta = device.get('iot_info', {})
        inferred = device.get('inferred', {})

        # Fingerbank fields are added by DeviceDiscovery.
        hostname = (
            device.get('hostname')
            or disc.get('hostname')
            or 'Not resolved'
        )

        fb_device = (
            device.get('fingerbank_device')
            or device.get('fingerbank', {}).get('device_name')
            or device.get('fingerbank', {}).get('name')
            or 'Not identified'
        )

        fb_os = (
            device.get('fingerbank_os')
            or device.get('fingerbank', {}).get('operating_system')
            or 'Not identified'
        )

        fb_manufacturer = (
            device.get('fingerbank_manufacturer')
            or device.get('fingerbank', {}).get('manufacturer')
            or 'Not identified'
        )

        fb_score = device.get(
            'fingerbank_score',
            device.get('fingerbank', {}).get('score')
        )

        if fb_score is None:
            fb_confidence = 'Not available'
        else:
            try:
                fb_confidence = f"{float(fb_score):.0f}%"
            except (TypeError, ValueError):
                fb_confidence = str(fb_score)

        layout.addRow(
            QLabel("<b>IP Address:</b>"),
            QLabel(device.get('ip', ''))
        )
        layout.addRow(
            QLabel("<b>Hostname:</b>"),
            QLabel(hostname)
        )
        layout.addRow(
            QLabel("<b>MAC Address:</b>"),
            QLabel(device.get('mac', ''))
        )
        layout.addRow(
            QLabel("<b>Hardware Vendor:</b>"),
            QLabel(device.get('vendor', ''))
        )
        layout.addRow(
            QLabel("<b>Device Category:</b>"),
            QLabel(inferred.get('category', 'IoT Device'))
        )

        layout.addRow(
            QLabel("<b>Fingerbank Device:</b>"),
            QLabel(fb_device)
        )
        layout.addRow(
            QLabel("<b>Fingerbank Manufacturer:</b>"),
            QLabel(fb_manufacturer)
        )
        layout.addRow(
            QLabel("<b>Fingerbank OS:</b>"),
            QLabel(fb_os)
        )
        layout.addRow(
            QLabel("<b>Fingerbank Confidence:</b>"),
            QLabel(fb_confidence)
        )

        if iot_meta.get('protocol'):
            layout.addRow(
                QLabel("<b>IoT Discovery Protocol:</b>"),
                QLabel(iot_meta.get('protocol', ''))
            )

        ports_str = (
            ', '.join(str(p['port']) for p in device.get('ports', []))
            if isinstance(device.get('ports'), list)
            else 'None'
        )

        layout.addRow(
            QLabel("<b>Open TCP Ports:</b>"),
            QLabel(ports_str or 'None')
        )
        layout.addRow(
            QLabel("<b>VLAN Subnet:</b>"),
            QLabel(str(disc.get('vlan', '137')))
        )
        layout.addRow(
            QLabel("<b>Connected Infrastructure:</b>"),
            QLabel(
                f"{disc.get('connected_to', 'Gateway')} / "
                f"{disc.get('port_or_ap', 'Wi-Fi')}"
            )
        )
        layout.addRow(
            QLabel("<b>Static Exposure Risk:</b>"),
            QLabel(
                f"{risk_label} ({risk_score:.2f}) - {risk_reason}"
            )
        )

        if botnet_risk:
            layout.addRow(
                QLabel("<b>Botnet Risk:</b>"),
                QLabel(
                    f"{botnet_risk[1]} ({botnet_risk[0]:.2f}) - "
                    f"{botnet_risk[2]}"
                )
            )

        if ml_risk:
            layout.addRow(
                QLabel("<b>ML Anomaly Risk:</b>"),
                QLabel(
                    f"{ml_risk[1]} ({ml_risk[0]:.2f}) - "
                    f"{ml_risk[2]}"
                )
            )

        self.setLayout(layout)


class ScanThread(QThread):
    scan_finished = pyqtSignal(list, str)
    scan_failed = pyqtSignal(str)

    def __init__(self, network):
        super().__init__()
        self.network = network
        self.topology_graph = {}

    def run(self):
        try:
            discovery = DeviceDiscovery()
            res = discovery.discover_devices(network=self.network)

            if isinstance(res, tuple):
                devices, topology_graph = res
            else:
                devices, topology_graph = res, {}

            self.topology_graph = topology_graph
            self.scan_finished.emit(devices, self.network)

        except Exception as e:
            self.scan_failed.emit(str(e))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle(
            "IoT Risk Detector & Cyber Defense Dashboard (Light Theme)"
        )
        self.setGeometry(80, 80, 1380, 780)
        self.apply_light_theme()

        # Header KPI Metrics
        self.kpi_total = KPICard(
            "TOTAL DEVICES", 0, "🌐", "#0284c7"
        )
        self.kpi_risk = KPICard(
            "HIGH RISK ALERTS", 0, "⚠️", "#dc2626"
        )
        self.kpi_infra = KPICard(
            "INFRASTRUCTURE NODES", 0, "🔀", "#7c3aed"
        )
        self.kpi_vlan = KPICard(
            "ACTIVE SUBNETS", 0, "🏷️", "#16a34a"
        )

        kpi_layout = QHBoxLayout()
        kpi_layout.addWidget(self.kpi_total)
        kpi_layout.addWidget(self.kpi_risk)
        kpi_layout.addWidget(self.kpi_infra)
        kpi_layout.addWidget(self.kpi_vlan)

        # Search & Controls Bar
        self.network_label = QLabel("Subnet Range:")
        self.network_label.setStyleSheet(
            "font-weight: bold; color: #334155;"
        )

        self.network_input = QLineEdit("")
        self.network_input.setPlaceholderText(
            "Auto-detect local network"
        )
        self.network_input.setFixedWidth(210)

        self.scan_button = QPushButton("🚀 Scan Network")
        self.scan_button.clicked.connect(self.scan_network)

        self.export_button = QPushButton("💾 Export CSV")
        self.export_button.clicked.connect(self.export_to_csv)
        self.export_button.setEnabled(False)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(
            "🔍 Filter IP, Hostname, MAC, Vendor, Device..."
        )
        self.search_input.textChanged.connect(self.apply_table_filters)

        self.cat_filter = QComboBox()
        self.cat_filter.addItems([
            "All Categories",
            "IP Camera",
            "Smartphone",
            "Smart TV / Media",
            "Printer",
            "Smart Home / IoT",
            "Workstation / PC",
            "Router / AP"
        ])
        self.cat_filter.currentIndexChanged.connect(
            self.apply_table_filters
        )

        self.risk_filter = QComboBox()
        self.risk_filter.addItems([
            "All Risk Levels",
            "High Risk Only",
            "Medium Risk",
            "Low Risk"
        ])
        self.risk_filter.currentIndexChanged.connect(
            self.apply_table_filters
        )

        ctrl_layout = QHBoxLayout()
        ctrl_layout.addWidget(self.network_label)
        ctrl_layout.addWidget(self.network_input)
        ctrl_layout.addWidget(self.scan_button)
        ctrl_layout.addWidget(self.export_button)
        ctrl_layout.addSpacing(15)
        ctrl_layout.addWidget(self.search_input)
        ctrl_layout.addWidget(self.cat_filter)
        ctrl_layout.addWidget(self.risk_filter)

        # 11-Column Table View
        self.table = QTableWidget()
        self.table.setColumnCount(11)
        self.table.setHorizontalHeaderLabels([
            "IP Address",
            "Hostname",
            "MAC Address",
            "Vendor",
            "Fingerbank Device",
            "Category",
            "VLAN / Subnet",
            "Connected To",
            "Medium (Interface)",
            "Risk Level",
            "Threat Scores"
        ])
        self.table.cellDoubleClicked.connect(self.show_device_details)

        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)

        self.topology_widget = NetworkTopologyWidget()

        self.tabs = QTabWidget()
        self.tabs.addTab(
            self.table,
            "📋 Device Lookup Table"
        )
        self.tabs.addTab(
            self.topology_widget,
            "🌐 Interactive Topology Map"
        )

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        main_layout = QVBoxLayout()
        main_layout.addLayout(kpi_layout)
        main_layout.addSpacing(6)
        main_layout.addLayout(ctrl_layout)
        main_layout.addSpacing(6)
        main_layout.addWidget(self.tabs)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.last_scan_devices = []
        self.last_botnet_risks = {}
        self.last_ml_risks = {}
        self.scan_thread = None
        self.traffic_thread = None

    def apply_light_theme(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #f8fafc; }
            QWidget {
                background-color: #f8fafc;
                color: #0f172a;
                font-family: 'Segoe UI', Arial;
            }
            QLineEdit, QComboBox {
                background-color: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                padding: 6px 10px;
                color: #0f172a;
                font-size: 12px;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #0284c7;
            }
            QPushButton {
                background-color: #0284c7;
                border: none;
                border-radius: 6px;
                padding: 7px 16px;
                color: #ffffff;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover { background-color: #0369a1; }
            QPushButton:disabled {
                background-color: #cbd5e1;
                color: #94a3b8;
            }
            QTabWidget::pane {
                border: 1px solid #e2e8f0;
                background-color: #ffffff;
                border-radius: 6px;
            }
            QTabBar::tab {
                background-color: #f1f5f9;
                color: #64748b;
                padding: 8px 18px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                font-weight: bold;
                border: 1px solid #e2e8f0;
            }
            QTabBar::tab:selected {
                background-color: #0284c7;
                color: #ffffff;
                border-color: #0284c7;
            }
            QTableWidget {
                background-color: #ffffff;
                gridline-color: #e2e8f0;
                border: 1px solid #cbd5e1;
                font-size: 12px;
                color: #0f172a;
            }
            QHeaderView::section {
                background-color: #f1f5f9;
                color: #0284c7;
                font-weight: bold;
                padding: 7px;
                border: 1px solid #e2e8f0;
            }
            QStatusBar {
                background-color: #f8fafc;
                color: #64748b;
                font-weight: 500;
            }
        """)

    def scan_network(self):
        network = self.network_input.text().strip()

        if self.scan_thread and self.scan_thread.isRunning():
            return

        self.scan_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.table.setRowCount(0)

        if network:
            status_network = network
        else:
            status_network = "Auto-detect local network"

        self.status_bar.showMessage(
            "Scanning subnets with 6-Engine Multi-Protocol Discovery: "
            f"{status_network}..."
        )

        # Empty input means automatic local-network detection.
        self.scan_thread = ScanThread(network if network else None)
        self.scan_thread.scan_finished.connect(self.on_scan_finished)
        self.scan_thread.scan_failed.connect(self.on_scan_failed)
        self.scan_thread.start()

    def on_scan_finished(self, devices, network):
        self.last_scan_devices = devices

        # Reset previous threat results for every new scan.
        self.last_botnet_risks = {}
        self.last_ml_risks = {}

        device_ips = [
            d.get('ip') for d in devices
            if d.get('ip')
        ]

        if device_ips:
            self.traffic_thread = TrafficMonitorThread(
                device_ips,
                duration=6
            )
            self.traffic_thread.traffic_captured.connect(
                lambda traffic: self.on_traffic_captured(
                    devices, traffic, network
                )
            )
            self.traffic_thread.start()

            self.status_bar.showMessage(
                "Capturing live traffic for botnet & ML threat assessment..."
            )
        else:
            self.update_table(
                devices, {}, {}, network
            )

    def on_traffic_captured(self, devices, traffic, network):
        botnet_risks = {
            d.get('ip'): assess_botnet_risk(
                d,
                traffic.get(d.get('ip'), [])
            )
            for d in devices
        }

        ml_risks = ml_botnet_anomaly_scores(
            devices,
            traffic
        )

        self.last_botnet_risks = botnet_risks
        self.last_ml_risks = ml_risks

        self.update_table(
            devices,
            botnet_risks,
            ml_risks,
            network
        )

    @staticmethod
    def _fingerbank_display(device):
        fb = device.get('fingerbank', {})

        if isinstance(fb, dict):
            name = (
                device.get('fingerbank_device')
                or fb.get('device_name')
                or fb.get('name')
                or ''
            )
            score = (
                device.get('fingerbank_score')
                if device.get('fingerbank_score') is not None
                else fb.get('score')
            )

            if name and score is not None:
                try:
                    return f"{name} ({float(score):.0f}%)"
                except (TypeError, ValueError):
                    return f"{name} ({score})"

            if name:
                return name

        return "Not identified"

    def update_table(self, devices, botnet_risks, ml_risks, network):
        high_risk_count = 0
        vlans_set = set()

        self.table.setRowCount(len(devices))

        for row, device in enumerate(devices):
            disc = device.get('discovered', {})
            inferred = device.get('inferred', {})

            vlans_set.add(
                disc.get('vlan', '137')
            )

            risk_score, risk_label, risk_reason = assess_device_risk(
                device
            )
            device['risk_label'] = risk_label

            b_score, b_label, _ = botnet_risks.get(
                device.get('ip'),
                (0.0, "Low", "")
            )

            ml_score, ml_label, _ = ml_risks.get(
                device.get('ip'),
                (0.0, "Low", "")
            )

            if (
                risk_label == "High"
                or b_label == "High"
                or ml_label == "High"
            ):
                high_risk_count += 1

            hostname = (
                device.get('hostname')
                or disc.get('hostname')
                or 'Not resolved'
            )

            fingerbank_device = self._fingerbank_display(
                device
            )

            values = [
                device.get('ip', ''),
                hostname,
                device.get('mac', ''),
                device.get('vendor', 'Generic'),
                fingerbank_device,
                inferred.get('category', 'IoT Device'),
                str(disc.get('vlan', '137')),
                str(disc.get('connected_to', 'Gateway')),
                str(disc.get('port_or_ap', 'Wi-Fi')),
            ]

            for column, value in enumerate(values):
                self.table.setItem(
                    row,
                    column,
                    QTableWidgetItem(str(value))
                )

            risk_item = QTableWidgetItem(
                f"{risk_label} ({risk_score:.2f})"
            )

            if risk_label == "High":
                risk_item.setBackground(
                    QColor(254, 226, 226)
                )
                risk_item.setForeground(
                    QBrush(QColor(220, 38, 38))
                )
            elif risk_label == "Medium":
                risk_item.setBackground(
                    QColor(254, 243, 199)
                )
                risk_item.setForeground(
                    QBrush(QColor(217, 119, 6))
                )
            else:
                risk_item.setBackground(
                    QColor(220, 252, 231)
                )
                risk_item.setForeground(
                    QBrush(QColor(22, 163, 74))
                )

            risk_item.setToolTip(risk_reason)
            self.table.setItem(row, 9, risk_item)

            threat_item = QTableWidgetItem(
                f"Botnet: {b_label} | ML: {ml_label}"
            )
            threat_item.setToolTip(
                f"Botnet: {b_label} ({b_score:.2f}) | "
                f"ML: {ml_label} ({ml_score:.2f})"
            )
            self.table.setItem(row, 10, threat_item)

        # Update KPI Cards
        self.kpi_total.set_value(len(devices))
        self.kpi_risk.set_value(high_risk_count)
        self.kpi_infra.set_value(1 if devices else 0)
        self.kpi_vlan.set_value(
            len(vlans_set) if vlans_set else 1
        )

        # Pass Graph Data to Topology Widget
        top_graph = getattr(
            self.scan_thread,
            'topology_graph',
            devices
        )
        self.topology_widget.set_data(top_graph)

        self.export_button.setEnabled(bool(devices))
        self.scan_button.setEnabled(True)

        self.status_bar.showMessage(
            f"Scan complete: {len(devices)} active devices mapped "
            f"({high_risk_count} high risk alerts)."
        )

    def apply_table_filters(self):
        query = self.search_input.text().lower().strip()
        cat_sel = self.cat_filter.currentText()
        risk_sel = self.risk_filter.currentText()

        for row in range(self.table.rowCount()):
            searchable_values = []

            # Search across IP, hostname, MAC, vendor and
            # Fingerbank device identification.
            for column in (0, 1, 2, 3, 4):
                item = self.table.item(row, column)
                if item:
                    searchable_values.append(
                        item.text().lower()
                    )

            cat = (
                self.table.item(row, 5).text()
                if self.table.item(row, 5)
                else ""
            )

            risk = (
                self.table.item(row, 9).text()
                if self.table.item(row, 9)
                else ""
            )

            matches_search = (
                not query
                or any(
                    query in value
                    for value in searchable_values
                )
            )

            matches_cat = (
                cat_sel == "All Categories"
                or cat_sel in cat
            )

            matches_risk = (
                risk_sel == "All Risk Levels"
                or risk_sel.split()[0] in risk
            )

            self.table.setRowHidden(
                row,
                not (
                    matches_search
                    and matches_cat
                    and matches_risk
                )
            )

    def on_scan_failed(self, error):
        QMessageBox.critical(
            self,
            "Scan Error",
            f"Failed to execute scan: {error}"
        )
        self.scan_button.setEnabled(True)
        self.status_bar.clearMessage()

    def export_to_csv(self):
        if not self.last_scan_devices:
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save CSV",
            "network_devices.csv",
            "CSV Files (*.csv)"
        )

        if filename:
            with open(
                filename,
                mode='w',
                newline='',
                encoding='utf-8'
            ) as f:
                writer = csv.writer(f)

                writer.writerow([
                    "IP Address",
                    "Hostname",
                    "MAC Address",
                    "Vendor",
                    "Fingerbank Device",
                    "Fingerbank OS",
                    "Fingerbank Confidence",
                    "Category",
                    "VLAN",
                    "Connected To",
                    "Port / AP",
                    "Risk Level",
                    "Botnet Risk",
                    "ML Risk"
                ])

                for dev in self.last_scan_devices:
                    disc = dev.get('discovered', {})
                    inferred = dev.get('inferred', {})

                    fb = dev.get('fingerbank', {})
                    if not isinstance(fb, dict):
                        fb = {}

                    fb_device = (
                        dev.get('fingerbank_device')
                        or fb.get('device_name')
                        or fb.get('name')
                        or ''
                    )

                    fb_os = (
                        dev.get('fingerbank_os')
                        or fb.get('operating_system')
                        or ''
                    )

                    fb_score = (
                        dev.get('fingerbank_score')
                        if dev.get('fingerbank_score') is not None
                        else fb.get('score', '')
                    )

                    b_risk = self.last_botnet_risks.get(
                        dev.get('ip'),
                        (0.0, "Low", "")
                    )

                    ml_risk = self.last_ml_risks.get(
                        dev.get('ip'),
                        (0.0, "Low", "")
                    )

                    writer.writerow([
                        dev.get('ip', ''),
                        dev.get('hostname', '') or disc.get('hostname', ''),
                        dev.get('mac', ''),
                        dev.get('vendor', ''),
                        fb_device,
                        fb_os,
                        fb_score,
                        inferred.get('category', ''),
                        disc.get('vlan', ''),
                        disc.get('connected_to', ''),
                        disc.get('port_or_ap', ''),
                        dev.get('risk_label', ''),
                        f"{b_risk[1]} ({b_risk[0]:.2f})",
                        f"{ml_risk[1]} ({ml_risk[0]:.2f})"
                    ])

            QMessageBox.information(
                self,
                "Export Complete",
                f"Exported to {filename}"
            )

    def show_device_details(self, row, column):
        if 0 <= row < len(self.last_scan_devices):
            dev = self.last_scan_devices[row]

            b_risk = self.last_botnet_risks.get(
                dev.get('ip')
            )

            ml_risk = self.last_ml_risks.get(
                dev.get('ip')
            )

            dialog = DeviceDetailsDialog(
                dev,
                b_risk,
                ml_risk,
                self
            )
            dialog.exec_()


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
