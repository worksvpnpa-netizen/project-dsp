# Enterprise Documentation: Dark Cyber-Defense Dashboard UI/UX
---

## 1. Executive Summary & Interface Redesign

The **IoT Risk Detection System** interface has been completely redesigned into a modern **Dark Cyber-Defense Dashboard** (`PyQt5`). This UI prioritizes instantaneous visual answer to the two core questions:
1. **WHAT ARE THEY?** (Device Category, Hardware Vendor, Open TCP Ports, Static & Threat Risk Scores)
2. **WHERE ARE THEY?** (VLAN ID, Switch / Access Point Name, Physical Port / Wi-Fi Channel, Subnet)

```text
┌────────────────────────────────────────────────────────────────────────────┐
│ 🌐 TOTAL DEVICES: 14  │ ⚠️ HIGH RISK: 2 │ 🔀 INFRASTRUCTURE: 3 │ 🏷️ VLANs: 2│
└────────────────────────────────────────────────────────────────────────────┘
│ 🔍 Search IP/MAC/Vendor | 📁 Category Filter | 🛡️ Risk Filter | 🚀 Scan    │
├────────────────────────────────────────────────────────────────────────────┤
│ [TAB 1: 📋 Device Lookup Table]          │ [TAB 2: 🌐 Interactive Map]    │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Key Interface Modules

### 2.1 Header KPI Metrics Panel
* **Total Devices:** Real-time counter of active connected endpoints.
* **High Risk Alerts:** Highlights vulnerable hosts requiring immediate mitigation.
* **Infrastructure Nodes:** Tracks Core Routers, Switches, and Access Points.
* **Active Subnets:** Count of scanned VLAN segments.

### 2.2 Instant Search & Multi-Filter Control Bar
* **Real-Time Search (`QLineEdit`):** Filters lookup table rows instantly as you type IP, MAC, or Vendor name.
* **Category Filter (`QComboBox`):** Filter by `IP Camera`, `Router / AP`, `Smart TV`, `Printer`, `Smartphone`, `Workstation`.
* **Risk Filter (`QComboBox`):** Filter by `High Risk Only`, `Medium Risk`, `Low Risk`.

### 2.3 9-Column High-Definition Device Lookup Table
1. `IP Address` (Host IP)
2. `MAC Address` (Hardware MAC)
3. `Vendor` (IEEE OUI Manufacturer)
4. `Category` (Inferred Device Type: WHAT IT IS)
5. `VLAN` (Subnet Tag: WHERE IT IS)
6. `Connected To` (Switch / Access Point Name)
7. `Port / AP` (Physical Switch Port / Wi-Fi Channel)
8. `Risk Level` (Color-coded Pill Badges: Red/Amber/Green)
9. `Threat Scores` (Botnet C2 & Machine Learning IsolationForest Scores)

---

## 3. Local Verification & Git Status

* **Local Compilation:** Verified error-free (`python -m py_compile main.py`).
* **Git Status:** **NOT pushed to GitHub.** As requested, all changes remain local.