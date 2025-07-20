# IoT Risk Detect: FOSS IoT Security & Botnet Detection Desktop App

<img width="992" height="525" alt="Screenshot 2025-07-20 191034" src="https://github.com/user-attachments/assets/3b73c044-2ddf-482a-956d-8cb9adc91fa1" />


## 🚀 Project Vision
IoT Risk Detect is a free and open-source (FOSS) desktop tool for real-time discovery, risk assessment, and botnet/anomaly detection of IoT devices on your local network. It empowers users, researchers, and defenders to:
- **Discover** all IoT devices on their network
- **Assess risk** (open ports, vendor, suspicious MACs)
- **Detect botnet-like behavior** (heuristics + ML anomaly detection)
- **Export and analyze** results for further action

**No cloud, no vendor lock-in, no data collection. 100% local, 100% FOSS.**

---

## ✨ Features
- **Network scan:** ARP-based device discovery
- **Risk assessment:** Open ports, vendor, MAC analysis
- **Botnet detection:**
  - Heuristic (bad IPs, port/protocol, external IPs)
  - ML-based (Isolation Forest anomaly detection)
- **Detailed device view:** Double-click for all info & risk reasons
- **Export:** Save results (CSV) for compliance or research
- **Modern GUI:** PyQt5, color-coded, status bar, responsive
- **No database, no server, no web UI**

---

## 🛠️ Installation
### Native (Recommended)
1. **Clone the repo:**
   ```sh
   git clone https://github.com/flatmarstheory/iot-risk-detect.git
   cd iot-risk-detect
   ```
2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
3. **Run the app:**
   ```sh
   python main.py
   ```
   > _Run as administrator/root for full network scan capability._

### Docker
1. **Build the image:**
   ```sh
   docker build -t iot-risk-detect .
   ```
2. **Run the app:**
   ```sh
   docker run --rm -it --net=host --env DISPLAY=$DISPLAY \
     -v /tmp/.X11-unix:/tmp/.X11-unix iot-risk-detect
   ```
   > _You must allow X11 forwarding for GUI apps in Docker. See docs for Windows/Mac._

---

## 🤝 Contributing
- PRs, issues, and feature requests welcome!
- See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
- Attribution: [flatmarstheory](https://github.com/flatmarstheory)

---

## 📜 License
MIT License. See [LICENSE](LICENSE).

---

## 💡 FOSS & IoT Security Focus
- 100% open source, no telemetry, no vendor lock-in
- Designed for researchers, defenders, and privacy advocates
- Use at your own risk. For educational and defensive purposes only.

---

## 🌐 Links
- GitHub: [flatmarstheory/iot-risk-detect](https://github.com/flatmarstheory/iot-risk-detect)
- Sponsor: [Buy Me a Coffee](https://bmc.link/flatmarstheory) 
