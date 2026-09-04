import sys
import os
import csv
import threading
import time
import warnings
# --- Fix for Scapy manuf warning ---
try:
    from scapy.data import MANUF_PATH, update_manuf
    if not os.path.exists(MANUF_PATH):
        print('[Startup] Downloading Wireshark manuf file for Scapy...')
        update_manuf()
    os.environ['SCAPY_MANUF'] = MANUF_PATH
except Exception as e:
    print(f'[Startup] Could not update manuf file: {e}')
    warnings.filterwarnings("ignore", message=".*cannot read manuf.*")
# --- End fix ---
from PyQt5.QtWidgets import (QApplication, QTabWidget, QMainWindow, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QMessageBox, QLineEdit, QLabel, QHBoxLayout, QFileDialog, QDialog, QFormLayout, QStatusBar)
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
        # Windows
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

if not is_admin():
    if sys.platform == 'win32':
        import ctypes
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()
    else:
        print("[Warning] Running without root privileges. Network sniffing/ARP scan may require root/sudo.")

def assess_device_risk(device):
    open_ports = [p['port'] for p in device.get('ports', [])]
    vendor = (device.get('vendor') or '').lower()
    mac = (device.get('mac') or '').lower()
    risk_score = 0.0
    reasons = []
    risky_ports = {23, 21, 3389, 5900, 445, 139, 5000, 8888, 80, 8080, 22}
    risky_found = [p for p in open_ports if p in risky_ports]
    if risky_found:
        risk_score += 0.5
        reasons.append(f"Open risky ports: {risky_found}")
    if not vendor:
        risk_score += 0.2
        reasons.append("Unknown vendor")
    if mac.startswith("00:00:00"):
        risk_score += 0.2
        reasons.append("Suspicious MAC address")
    if not open_ports:
        risk_score += 0.1
        reasons.append("No open ports detected")
    risk_score = min(risk_score, 1.0)
    if risk_score >= 0.7:
        label = "High"
    elif risk_score >= 0.4:
        label = "Medium"
    else:
        label = "Low"
    return risk_score, label, "; ".join(reasons)

def extract_traffic_features(device, pkts):
    ip = device.get('ip', '')
    ext_ips = set()
    port_set = set()
    pkt_count = 0
    for pkt in pkts:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            if src == ip:
                ext_ips.add(dst)
                pkt_count += 1
                if TCP in pkt:
                    port_set.add(pkt[TCP].dport)
                if UDP in pkt:
                    port_set.add(pkt[UDP].dport)
            elif dst == ip:
                ext_ips.add(src)
                pkt_count += 1
                if TCP in pkt:
                    port_set.add(pkt[TCP].sport)
                if UDP in pkt:
                    port_set.add(pkt[UDP].sport)
    return [len(ext_ips), len(port_set), pkt_count]

def ml_botnet_anomaly_scores(devices, traffic):
    # Extract features: [unique ext IPs, unique ports, packet count]
    features = []
    for device in devices:
        ip = device.get('ip')
        pkts = traffic.get(ip, [])
        features.append(extract_traffic_features(device, pkts))
    X = np.array(features)
    if len(X) < 2:
        # Not enough data for ML, return all normal
        return {device.get('ip'): (0.0, "Low", "Not enough data for ML") for device in devices}
    clf = IsolationForest(contamination=0.15, random_state=42)
    preds = clf.fit_predict(X)
    scores = clf.decision_function(X)
    ml_risks = {}
    for i, device in enumerate(devices):
        ip = device.get('ip')
        if preds[i] == -1:
            ml_risks[ip] = (1.0, "High", f"Anomalous traffic pattern (score={scores[i]:.2f})")
        else:
            ml_risks[ip] = (0.0, "Low", f"Normal traffic pattern (score={scores[i]:.2f})")
    return ml_risks

def assess_botnet_risk(device, traffic, known_bad_ips=None):
    if known_bad_ips is None:
        known_bad_ips = {"185.234.219.167", "45.9.148.204", "185.220.101.1"}  # Example bad IPs
    ip = device.get('ip', '')
    if not ip:
        return 0.0, "Low", "No IP address"
    ext_ips = set()
    suspicious_ports = set()
    bad_ip_contact = False
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
                if UDP in pkt:
                    suspicious_ports.add(pkt[UDP].dport)
            elif dst == ip:
                ext_ips.add(src)
                if src in known_bad_ips:
                    bad_ip_contact = True
                if TCP in pkt:
                    suspicious_ports.add(pkt[TCP].sport)
                if UDP in pkt:
                    suspicious_ports.add(pkt[UDP].sport)
    risk_score = 0.0
    reasons = []
    if bad_ip_contact:
        risk_score += 0.7
        reasons.append("Contacted known bad IP")
    if len(ext_ips) > 10:
        risk_score += 0.3
        reasons.append(f"Many unique external IPs: {len(ext_ips)}")
    risky_ports = {23, 21, 3389, 5900, 445, 139, 5000, 8888, 80, 8080, 22}
    if suspicious_ports & risky_ports:
        risk_score += 0.2
        reasons.append(f"Suspicious ports: {suspicious_ports & risky_ports}")
    if risk_score == 0.0:
        reasons.append("No botnet-like behavior detected")
    risk_score = min(risk_score, 1.0)
    if risk_score >= 0.7:
        label = "High"
    elif risk_score >= 0.4:
        label = "Medium"
    else:
        label = "Low"
    return risk_score, label, "; ".join(reasons)

class TrafficMonitorThread(QThread):
    traffic_captured = pyqtSignal(dict)
    def __init__(self, device_ips, duration=10):
        super().__init__()
        self.device_ips = set(device_ips)
        self.duration = duration
        self.captured = {ip: [] for ip in self.device_ips}
    def run(self):
        print(f"[TrafficMonitor] Capturing traffic for {self.duration} seconds...")
        def pkt_handler(pkt):
            if IP in pkt:
                if pkt[IP].src in self.device_ips or pkt[IP].dst in self.device_ips:
                    if pkt[IP].src in self.captured:
                        self.captured[pkt[IP].src].append(pkt)
                    if pkt[IP].dst in self.captured:
                        self.captured[pkt[IP].dst].append(pkt)
        sniff(timeout=self.duration, prn=pkt_handler, store=False)
        print(f"[TrafficMonitor] Traffic capture complete.")
        self.traffic_captured.emit(self.captured)

class DeviceDetailsDialog(QDialog):
    def __init__(self, device, botnet_risk=None, ml_risk=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Device Details")
        layout = QFormLayout()
        risk_score, risk_label, risk_reason = assess_device_risk(device)
        layout.addRow("IP Address:", QLabel(device.get('ip', '')))
        layout.addRow("MAC Address:", QLabel(device.get('mac', '')))
        layout.addRow("Vendor:", QLabel(device.get('vendor', '')))
        ports = ', '.join(str(p['port']) for p in device.get('ports', []))
        layout.addRow("Open Ports:", QLabel(ports))
        layout.addRow("Risk:", QLabel(f"{risk_label} ({risk_score:.2f})"))
        layout.addRow("Risk Reason:", QLabel(risk_reason or "-"))
        if botnet_risk:
            b_score, b_label, b_reason = botnet_risk
            layout.addRow("Botnet Risk:", QLabel(f"{b_label} ({b_score:.2f})"))
            layout.addRow("Botnet Reason:", QLabel(b_reason or "-"))
        if ml_risk:
            ml_score, ml_label, ml_reason = ml_risk
            layout.addRow("ML Anomaly Risk:", QLabel(f"{ml_label} ({ml_score:.2f})"))
            layout.addRow("ML Reason:", QLabel(ml_reason or "-"))
        self.setLayout(layout)

class ScanThread(QThread):
    scan_finished = pyqtSignal(list, str)
    scan_failed = pyqtSignal(str)
    def __init__(self, network):
        super().__init__()
        self.network = network
    def run(self):
        try:
            print(f"[Thread] === Starting scan on {self.network} ===")
            discovery = DeviceDiscovery()
            print(f"[Thread] ARP scan initiated...")
            devices = discovery.discover_devices(network=self.network)
            print(f"[Thread] ARP scan complete. {len(devices)} device(s) found.")
            for idx, device in enumerate(devices):
                print(f"[Thread] Device {idx+1}: IP={device.get('ip','')}, MAC={device.get('mac','')}, Vendor={device.get('vendor','')}, Ports={[p['port'] for p in device.get('ports',[])]}")
            print(f"[Thread] === Scan finished on {self.network} ===")
            self.scan_finished.emit(devices, self.network)
        except Exception as e:
            print(f"[Thread] ERROR during scan: {e}")
            self.scan_failed.emit(str(e))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IoT Device Scanner & Threat Assessment")
        self.setGeometry(100, 100, 1300, 650)
        self.network_label = QLabel("Network Range:")
        self.network_input = QLineEdit()
        self.network_input.setText("192.168.137.0/24, 10.10.20.0/24")
        self.scan_button = QPushButton("Scan Network")
        self.scan_button.clicked.connect(self.scan_network)
        self.export_button = QPushButton("Export to CSV")
        self.export_button.clicked.connect(self.export_to_csv)
        self.export_button.setEnabled(False)
        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Vendor", "VLAN", "Connected To", "Port / AP", "Risk", "Botnet Risk", "ML Anomaly Risk"])
        self.table.cellDoubleClicked.connect(self.show_device_details)
        # UI/UX: bold headers, alternating row colors
        header = self.table.horizontalHeader()
        font = QFont()
        font.setBold(True)
        for i in range(self.table.columnCount()):
            item = self.table.horizontalHeaderItem(i)
            if item:
                item.setFont(font)
        
        self.topology_widget = NetworkTopologyWidget()

        self.tabs = QTabWidget()
        self.tabs.addTab(self.table, "📋 Device Table View")
        self.tabs.addTab(self.topology_widget, "🌐 Network Topology Map")

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        top_layout = QHBoxLayout()
        top_layout.addWidget(self.network_label)
        top_layout.addWidget(self.network_input)
        top_layout.addWidget(self.scan_button)
        top_layout.addWidget(self.export_button)
        layout = QVBoxLayout()
        layout.addLayout(top_layout)
        layout.addWidget(self.tabs)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        self.scan_thread = None
        self.traffic_thread = None
        self.last_scan_devices = []
        self.last_botnet_risks = {}
        self.last_ml_risks = {}
    def scan_network(self):
        network = self.network_input.text().strip()
        print(f"[GUI] User requested scan on network: {network}")
        self.scan_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.table.setRowCount(0)
        self.last_botnet_risks = {}
        self.last_ml_risks = {}
        self.status_bar.showMessage("Scanning devices...")
        self.scan_thread = ScanThread(network)
        self.scan_thread.scan_finished.connect(self.on_scan_finished)
        self.scan_thread.scan_failed.connect(self.on_scan_failed)
        self.scan_thread.start()
    def on_scan_finished(self, devices, network):
        print(f"[GUI] Scan finished. Populating table with {len(devices)} device(s).")
        self.table.setRowCount(len(devices))
        self.last_scan_devices = devices
        device_ips = [d.get('ip') for d in devices if d.get('ip')]
        if device_ips:
            self.traffic_thread = TrafficMonitorThread(device_ips, duration=10)
            self.traffic_thread.traffic_captured.connect(lambda traffic: self.on_traffic_captured(devices, traffic, network))
            self.traffic_thread.start()
            self.status_bar.showMessage("Capturing traffic for ML/botnet analysis...")
            QMessageBox.information(self, "Traffic Monitoring", "Capturing traffic for 10 seconds to analyze botnet risk...")
        else:
            self.update_table(devices, {}, {}, network)
    def on_traffic_captured(self, devices, traffic, network):
        print(f"[GUI] Traffic captured. Analyzing botnet and ML risk...")
        botnet_risks = {}
        for device in devices:
            ip = device.get('ip')
            pkts = traffic.get(ip, [])
            botnet_risks[ip] = assess_botnet_risk(device, pkts)
        ml_risks = ml_botnet_anomaly_scores(devices, traffic)
        self.last_botnet_risks = botnet_risks
        self.last_ml_risks = ml_risks
        self.update_table(devices, botnet_risks, ml_risks, network)
    def update_table(self, devices, botnet_risks, ml_risks, network):
        self.table.setRowCount(len(devices))
        high_risk_count = 0
        for row, device in enumerate(devices):
            # Alternating row color
            if row % 2 == 0:
                for col in range(self.table.columnCount()):
                    self.table.setItem(row, col, QTableWidgetItem())
                    self.table.item(row, col).setBackground(QColor(245, 245, 245))
            disc = device.get('discovered', {})
            self.table.setItem(row, 0, QTableWidgetItem(device.get('ip', '')))
            self.table.setItem(row, 1, QTableWidgetItem(device.get('mac', '')))
            self.table.setItem(row, 2, QTableWidgetItem(device.get('vendor', '')))
            self.table.setItem(row, 3, QTableWidgetItem(str(disc.get('vlan', '10'))))
            self.table.setItem(row, 4, QTableWidgetItem(str(disc.get('connected_to', 'SW-01'))))
            self.table.setItem(row, 5, QTableWidgetItem(str(disc.get('port_or_ap', 'Port 1'))))
            
            # Risk assessment
            risk_score, risk_label, risk_reason = assess_device_risk(device)
            device['risk_label'] = risk_label
            risk_item = QTableWidgetItem(f"{risk_label} ({risk_score:.2f})")
            if risk_label == "High":
                risk_item.setBackground(QColor(255, 102, 102))
                risk_item.setForeground(QBrush(Qt.white))
                high_risk_count += 1
            elif risk_label == "Medium":
                risk_item.setBackground(QColor(255, 204, 102))
            else:
                risk_item.setBackground(QColor(153, 255, 153))
            risk_item.setToolTip(risk_reason)
            self.table.setItem(row, 6, risk_item)
            
            # Botnet risk
            b_score, b_label, b_reason = botnet_risks.get(device.get('ip'), (0.0, "Low", "Not analyzed"))
            botnet_item = QTableWidgetItem(f"{b_label} ({b_score:.2f})")
            if b_label == "High":
                botnet_item.setBackground(QColor(255, 51, 51))
                botnet_item.setForeground(QBrush(Qt.white))
                high_risk_count += 1
            elif b_label == "Medium":
                botnet_item.setBackground(QColor(255, 204, 102))
            else:
                botnet_item.setBackground(QColor(153, 255, 153))
            botnet_item.setToolTip(b_reason)
            self.table.setItem(row, 7, botnet_item)
            
            # ML anomaly risk
            ml_score, ml_label, ml_reason = ml_risks.get(device.get('ip'), (0.0, "Low", "Not analyzed"))
            ml_item = QTableWidgetItem(f"{ml_label} ({ml_score:.2f})")
            if ml_label == "High":
                ml_item.setBackground(QColor(255, 51, 153))
                ml_item.setForeground(QBrush(Qt.white))
                high_risk_count += 1
            elif ml_label == "Medium":
                ml_item.setBackground(QColor(255, 204, 255))
            else:
                ml_item.setBackground(QColor(204, 255, 255))
            ml_item.setToolTip(ml_reason)
            self.table.setItem(row, 8, ml_item)
        print(f"[GUI] Table update complete.")
        # Update Network Topology Widget
        for d in devices:
            r_score, r_label, _ = assess_device_risk(d)
            d['risk_label'] = r_label
        gateway_ip = network.rsplit('.', 1)[0] + '.1' if '.' in network else '192.168.137.1'
        self.topology_widget.set_data(devices, gateway_ip=gateway_ip)

        self.export_button.setEnabled(True if devices else False)
        self.status_bar.showMessage(f"Scan complete: {len(devices)} devices, {high_risk_count} high risk.")
        QMessageBox.information(self, "Scan Complete", f"Found {len(devices)} devices on {network}.")
        self.scan_button.setEnabled(True)
    def on_scan_failed(self, error):
        print(f"[GUI] Scan failed: {error}")
        QMessageBox.critical(self, "Error", f"Scan failed: {error}")
        self.scan_button.setEnabled(True)
        self.export_button.setEnabled(False)
        self.status_bar.clearMessage()
    def export_to_csv(self):
        if not self.last_scan_devices:
            QMessageBox.warning(self, "No Data", "No scan results to export.")
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Save CSV", "scan_results.csv", "CSV Files (*.csv)")
        if not filename:
            return
        try:
            with open(filename, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["IP Address", "MAC Address", "Vendor", "Open Ports", "Risk", "Risk Reason", "Botnet Risk", "Botnet Reason", "ML Anomaly Risk", "ML Reason"])
                for device in self.last_scan_devices:
                    ports = ', '.join(str(p['port']) for p in device.get('ports', []))
                    risk_score, risk_label, risk_reason = assess_device_risk(device)
                    b_score, b_label, b_reason = self.last_botnet_risks.get(device.get('ip'), (0.0, "Low", "Not analyzed"))
                    ml_score, ml_label, ml_reason = self.last_ml_risks.get(device.get('ip'), (0.0, "Low", "Not analyzed"))
                    writer.writerow([
                        device.get('ip', ''),
                        device.get('mac', ''),
                        device.get('vendor', ''),
                        ports,
                        f"{risk_label} ({risk_score:.2f})",
                        risk_reason,
                        f"{b_label} ({b_score:.2f})",
                        b_reason,
                        f"{ml_label} ({ml_score:.2f})",
                        ml_reason
                    ])
            QMessageBox.information(self, "Export Complete", f"Results exported to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Could not export results: {e}")
    def show_device_details(self, row, column):
        if not (0 <= row < len(self.last_scan_devices)):
            return
        device = self.last_scan_devices[row]
        botnet_risk = self.last_botnet_risks.get(device.get('ip'))
        ml_risk = self.last_ml_risks.get(device.get('ip'))
        dialog = DeviceDetailsDialog(device, botnet_risk, ml_risk, self)
        dialog.exec_()

if __name__ == "__main__":
    print("[MAIN] IoT Device Scanner & Threat Assessment GUI starting...")
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_()) 