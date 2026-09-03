# Technical Documentation: IoT Device Scanner & Threat Assessment System

---

## 1. Project Overview & Core Objective

The **IoT Device Scanner & Threat Assessment System** (`iot-risk-detect`) is an enterprise-grade, desktop-based local network asset discovery, device classification, and threat assessment application. 

The primary objective of this project is to provide real-time network visibility into connected Internet of Things (IoT) hardware, personal computers, mobile devices, and network infrastructure. It automates device discovery, vendor resolution, open-port profiling, risk classification, botnet behavior detection, and graphical network topology mapping.

---

## 2. Technical Stack, Tools & Methodologies

### 2.1 Technical Stack

* **Programming Language:** Python 3.10+ / 3.12+
* **Graphical User Interface (GUI):** `PyQt5` (QtWidgets, QGraphicsView, QGraphicsScene, QThread, pyqtSignal)
* **Packet Manipulation & Low-Level Networking:** `Scapy` (Layer-2 ARP Requests, Ether frames, TCP SYN scans, promiscuous traffic sniffing)
* **Machine Learning & Data Processing:** `scikit-learn` (`IsolationForest` for unsupervised anomaly detection), `numpy`
* **HTTP & API Integration:** `requests` (for IEEE MAC OUI vendor resolution via `api.macvendors.com`)
* **Containerization & Remote UI:** `Docker`, `Docker Compose`, `Xvfb` (Virtual Framebuffer), `x11vnc`, `noVNC` & `websockify` (Port 6080)

---

### 2.2 Core Methodologies

#### 1. Layer-2 ARP Subnet Probing
Rather than relying on slow, high-overhead ICMP ping sweeps that are frequently blocked by local host firewalls, the scanner builds raw Ethernet frames encapsulated with Address Resolution Protocol (`ARP`) requests broadcast to `ff:ff:ff:ff:ff:ff`:
$$\text{Frame} = \text{Ether}(\text{dst}=\text{"ff:ff:ff:ff:ff:ff"}) / \text{ARP}(\text{pdst}=\text{subnet})$$
This forces every active network interface on the local Ethernet/Wi-Fi segment to respond with its physical MAC address.

#### 2. Hardware Vendor Resolution & TCP Port Profiling
* **OUI Identification:** Extracts the first 24 bits (Organizationally Unique Identifier) of the hardware MAC address and queries the `api.macvendors.com` REST service to resolve the manufacturer (e.g., Apple, TP-Link, Samsung, Hikvision).
* **TCP SYN Scanning:** Sends TCP SYN (`flags='S'`) probes to critical IoT control and remote management ports (`22`, `23`, `80`, `443`, `53`, `554`, `139`, `445`, `3389`, `5000`, `8080`, `8443`, `8888`) to identify active web servers, camera streams (RTSP/554), or insecure protocols (Telnet/23, FTP/21).

#### 3. Multi-Layer Risk & Anomaly Scoring Engine
The application calculates three distinct risk metrics for every discovered device:

* **Static Device Exposure Score ($R_{\text{static}}$):** Evaluates open high-risk ports, missing vendor identity data, and unassigned port ranges on a scale of $0.0$ to $1.0$:
  * Open risky ports (Telnet/23, FTP/21, RDP/3389, VNC/5900, SMB/445): $+0.5$
  * Unknown/Unresolved Vendor: $+0.2$
  * No open ports detected: $+0.1$
* **Botnet Behavioral Risk ($R_{\text{botnet}}$):** Evaluates live packet captures against known command-and-control (C2) IP addresses, high volume of unique external IP contacts ($>10$ destination IPs), and unencrypted control traffic.
* **Unsupervised Machine Learning Anomaly Score ($R_{\text{ML}}$):** Extracts a 3-dimensional feature vector $\mathbf{x}_i = [N_{\text{ext\_IPs}}, N_{\text{ports}}, N_{\text{packets}}]$ for each host and passes it into an **IsolationForest** model to flag statistically anomalous behavior patterns.

#### 4. Interactive Node-Graph Topology Visualizer
Uses PyQt5's `QGraphicsView` & `QGraphicsScene` 2D rendering pipeline to construct a star/mesh network map. It positions a central Gateway Node at $(0,0)$ and distributes host devices in a radial orbit, connecting them with dynamically color-coded status links.

---

## 3. Comprehensive Record of Modifications Made (Before vs. After)

### 3.1 Initial Repository State (Before)

* **UI Layout:** Basic single-table interface showing raw text metrics.
* **Docker Containerization Issue:** `docker-compose.yml` was configured with `network_mode: host`. On Windows Docker Desktop (WSL2), `network_mode: host` discarded port mappings, causing `http://localhost:6080` to fail with "Site Cannot Be Reached".
* **Layer-2 Subnet Isolation:** When running inside standard Docker bridge containers, low-level ARP broadcast scans were restricted to Docker's internal virtual bridge (`172.17.0.x`), returning **0 devices** when attempting to scan the user's host Wi-Fi network (`192.168.137.0/24`).
* **Topology View:** No graphical topology map or node-graph visualizer existed.

---

### 3.2 Key Enhancements Implemented (After)

#### 1. Docker Port Forwarding Fix
* Modified container execution parameters to explicitly map host port `6080` (`-p 6080:6080`), restoring noVNC browser accessibility at `http://localhost:6080/vnc.html`.

#### 2. Native Windows Administrative Execution
* Configured native execution setup on Windows (`python main.py`). Integrated Windows User Account Control (UAC) elevation via `ctypes.windll.shell32.ShellExecuteW(..., "runas")` so Scapy binds directly to physical Windows Wi-Fi network adapters for unrestricted Layer-2 ARP discovery.

#### 3. Custom Network Topology Module ([`src/ui/topology_view.py`](file:///c:/Users/patel/Desktop/Atool/iot-risk-detect/src/ui/topology_view.py))
* Engineered a PyQt5 graphical node-graph renderer supporting zoom, pan, dragging, and dynamic layout generation.

#### 4. Rich ASCII/Card Node Layout
* Transformed simple circle nodes into detailed **Rich Device Cards**:
  ```text
  ┌─────────────────────────┐
  │  📷 IP CAMERA           │
  │  IP: 192.168.137.21     │
  │  Vendor: Hikvision      │
  │  Loc: Hotspot-AP / VLAN 137
  │  Risk: HIGH             │
  └─────────────────────────┘
  ```
* Implemented automatic category icon resolution:
  * 📷 `IP CAMERA` (RTSP port 554, Hikvision, Dahua)
  * 🌐 `ROUTER / AP` (Gateway IPs, Cisco, TP-Link, Netgear)
  * 📺 `SMART TV` (Samsung, LG, Roku, Sony)
  * 🖨️ `PRINTER` (HP, Canon, Epson, Brother)
  * 📱 `MOBILE / TAB` (Apple, Android, phones)
  * 🖥️ `IOT DEVICE` / `WORKSTATION` (General hardware)

#### 5. VLAN & Access Point Metadata Enrichment ([`src/core/device_discovery.py`](file:///c:/Users/patel/Desktop/Atool/iot-risk-detect/src/core/device_discovery.py))
* Added automatic subnet-to-VLAN mapping (e.g. `192.168.137.x` ➔ `VLAN 137`) and local Access Point location tagging (`Hotspot-AP`).

#### 6. Dual-Tabbed GUI Interface ([`main.py`](file:///c:/Users/patel/Desktop/Atool/iot-risk-detect/main.py))
* Upgraded `MainWindow` with a `QTabWidget` featuring:
  * **Tab 1 (📋 Device Table View):** Comprehensive tabular grid with double-click detail dialogs and CSV export.
  * **Tab 2 (🌐 Network Topology Map):** Interactive rich node card graph with risk-based border highlighting (Red = High, Orange = Medium, Green = Low).

---

## 4. Summary Matrix: Before vs. After

| Feature / Capability | Initial Repository State | Enhanced Current State |
| :--- | :--- | :--- |
| **Interface Views** | Data table only | **Dual-Tab:** Table View + Interactive Topology Graph |
| **Topology Map** | ❌ None | **✅ Rich Card Node Graph** with category icons, AP/VLAN metadata & risk badges |
| **Windows Execution** | Manual setup required | **✅ Auto UAC elevation** for direct physical interface ARP access |
| **Docker Web VNC** | ❌ Blocked (`network_mode: host`) | **✅ Fixed** (`-p 6080:6080` port forwarding active) |
| **Layer-2 Discovery** | Blocked inside VM containers | **✅ Full Layer-2 subnet discovery** on Windows physical adapters |
| **Location / VLAN Info** | ❌ None | **✅ Enriched** (`Hotspot-AP / VLAN 137`) |
| **Risk Highlights** | Text labels | **✅ Color-coded visual badges & card borders** (Red, Orange, Green) |

---

## 5. Tested Environments & Device Scenarios

* **Host Environment:** Windows 11 Home/Pro (Python 3.12.2, PyQt5 5.15.11, Scapy 2.7.0).
* **Active Subnet Tested:** `192.168.137.0/24` (Windows Mobile Hotspot over Ethernet).
* **Discovered Device Categories:**
  * **Default Gateway:** `192.168.137.1` (Hotspot host / Router).
  * **Connected Clients:** Workstations, Mobile devices, and network client nodes.
* **Scan Performance:** Subnet ARP scan completed in $<0.5$ seconds; 10-second background traffic monitoring window for ML IsolationForest scoring.

---

## 6. Current Limitations & Technical Constraints

1. **Layer-2 Subnet Boundary:**
   * **Limitation:** ARP-based discovery is strictly limited to the local broadcast domain (Layer 2). It cannot cross non-routed Layer-3 WAN routers or remote subnets without SNMP, WMI, or SSH credential integration.
2. **Administrator Privilege Requirement:**
   * **Limitation:** Raw socket creation (`scapy.all.srp`) requires elevated root/administrator rights on the host operating system.
3. **MAC OUI Vendor Lookup Dependency:**
   * **Limitation:** Hardware vendor identification relies on an active internet connection to `api.macvendors.com`. If offline, the tool falls back to local MAC vendor caches or lists the vendor as "Unknown".
4. **Docker Network Bridging:**
   * **Limitation:** Running network discovery inside a standard virtualized Docker container on Windows isolates packet traffic to Docker's internal vSwitch (`172.17.0.x`), requiring native host execution or macvlan/bridged network drivers to reach physical LAN devices.
