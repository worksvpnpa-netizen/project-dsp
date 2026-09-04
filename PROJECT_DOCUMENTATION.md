# Enterprise Documentation: Multi-Subnet & Infrastructure-Aware IoT Risk Detection System

---

## 1. Executive Summary & Scalable Architecture

The **IoT Risk Detection System** has been upgraded to a **Scalable Enterprise Multi-Subnet Architecture**. Unlike traditional single-subnet tools that rely exclusively on local Layer-2 ARP broadcasts, this engine scans across Layer-3 routed boundaries, parses multiple CIDR subnets, queries infrastructure bridge tables (SNMP/LLDP), and cleanly separates **Discovered (Deterministic)** infrastructure data from **Inferred (Heuristic)** risk predictions.

```text
                    Enterprise Network
                           │
                    ┌──────▼──────┐
                    │ Core Router │
                    └──────┬──────┘
                           │
             ┌─────────────┼─────────────┐
             │             │             │
          VLAN 10        VLAN 20       VLAN 30
        10.10.10.0/24  10.10.20.0/24 10.10.30.0/24
             │             │             │
          IoT devices   IoT devices   IoT devices
```

---

## 2. Key Scalable Technical Upgrades

### 2.1 Multi-Subnet & Hybrid L2/L3 Discovery Engine
* **Input Range Parsing:** Accepts comma-separated CIDR subnets (`192.168.137.0/24, 10.10.20.0/24, 10.10.30.0/24`).
* **Layer-2 ARP Probing:** Ultra-fast Scapy ARP requests broadcast for local subnet hosts.
* **Layer-3 ICMP & Socket SYN Probing:** Thread-pooled socket probes (`concurrent.futures`) across routed WAN/VLAN boundaries where ARP broadcast frames are discarded by Layer-3 routers.

---

### 2.2 Discovered vs. Inferred Data Model Separation
To maintain strict technical credibility, host properties are explicitly divided:

1. **Discovered (Deterministic Infrastructure Data):**
   * `VLAN`: Genuine VLAN ID extracted from 802.1Q tags or SNMP bridge tables (`1.3.6.1.2.1.17.4.3.1.2`).
   * `Connected To`: Switch / Wireless Controller name (`SW-01`, `SW-02`, `AP-03`).
   * `Port / AP`: Exact physical switch port or wireless SSID/channel (`Port 14`, `Wi-Fi 802.11ax`).

2. **Inferred (Heuristic & Model Predictions):**
   * `Category`: Inferred device classification (`IP Camera`, `Smart TV`, `Router`, `Workstation`).
   * `Risk Score`: Static vulnerability rating based on open risky ports.
   * `Botnet & ML Anomaly Risk`: Unsupervised `IsolationForest` anomaly classification.

---

### 2.3 Multi-Tier Enterprise Topology Hierarchy
The `NetworkTopologyWidget` (`QGraphicsView`) renders a 4-tier visual hierarchy:

```text
[LEVEL 1]                    🏢 ENTERPRISE CORE ROUTER
                                        │
           ┌────────────────────────────┴────────────────────────────┐
           ▼                                                         ▼
[LEVEL 2]  🔀 SW-01 (VLAN 10)                                      📶 AP-02 (VLAN 20)
           │                                                         │
           ▼                                                         ▼
[LEVEL 3]  ┌───────────────────────────┐                            ┌───────────────────────────┐
           │ 📷 Camera-01              │                            │ 📱 Smartphone             │
           │ IP: 10.10.10.15           │                            │ IP: 10.10.20.21           │
           │ MAC: 00:11:22:33:44:55    │                            │ MAC: 00:22:33:44:55:66    │
           │ Vendor: Hikvision         │                            │ Vendor: Apple             │
           │ VLAN: 10 | SW-01          │                            │ VLAN: 20 | AP-02          │
           │ Port: Port 14             │                            │ Port: Wi-Fi               │
           │ Risk: HIGH                │                            │ Risk: LOW                 │
           └───────────────────────────┘                            └───────────────────────────┘
```

---

## 3. Data Schema Matrix

| Property | Data Type | Source | Example Value |
| :--- | :--- | :--- | :--- |
| **IP Address** | Discovered | Socket/Packet Response | `10.10.20.15` |
| **MAC Address** | Discovered | Layer-2 ARP / SNMP Table | `00:11:22:33:44:55` |
| **Vendor** | Discovered | IEEE OUI Lookup API | `Hikvision` |
| **VLAN** | Discovered | 802.1Q Tag / SNMP MIB | `20` |
| **Connected To** | Discovered | LLDP/CDP MIB | `SW-02` |
| **Port / AP** | Discovered | Switch MAC Table | `Port 14` |
| **Category** | Inferred | Heuristic Fingerprinting | `IP Camera` |
| **Risk Score** | Inferred | Port Vulnerability Matrix | `High (0.75)` |
| **ML Anomaly** | Inferred | `IsolationForest` Model | `Low (0.10)` |

---

## 4. Verification & Testing

* **Multi-Subnet Execution:** Verified concurrent scanning across `192.168.137.0/24` and `10.10.20.0/24`.
* **GUI Integration:** Verified 9-column data grid and multi-tier visual graph rendering.
* **Compilation Check:** Verified via `python -m py_compile main.py` (Exit Code 0).
