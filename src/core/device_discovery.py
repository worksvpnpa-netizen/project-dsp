"""
Device discovery module for the IoT Risk Detection System.
Uses Nmap scanning and MAC address vendor lookups to identify IoT devices.
"""
import logging
import requests
import time
from scapy.all import ARP, Ether, srp, IP, TCP, sr1

logger = logging.getLogger(__name__)

class DeviceDiscovery:
    """Handles network device discovery and identification using Scapy."""
    
    def __init__(self):
        self.mac_vendor_cache = {}
        self.device_type_patterns = {
            'camera': ['cam', 'ipcam', 'hikvision', 'dahua', 'axis'],
            'router': ['router', 'gateway', 'tplink', 'netgear', 'dlink', 'cisco'],
            'smart_tv': ['tv', 'smarttv', 'samsung', 'lg', 'sony'],
            'printer': ['printer', 'hp', 'canon', 'epson', 'brother'],
            'thermostat': ['nest', 'thermostat', 'ecobee'],
            'light_bulb': ['bulb', 'light', 'philips', 'hue'],
            'speaker': ['speaker', 'sonos', 'alexa', 'google'],
            'laptop': ['laptop', 'notebook', 'thinkpad', 'macbook'],
            'desktop': ['desktop', 'workstation', 'dell', 'hp'],
            'smartphone': ['phone', 'android', 'iphone', 'ios'],
        }

    def discover_devices(self, network="192.168.1.0/24"):
        logger.info(f"Starting ARP scan on {network}")
        print(f"[DeviceDiscovery] ARP scan on {network} (timeout=0.3)...")
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        try:
            result = srp(packet, timeout=0.3, verbose=1)[0]
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")
            print(f"[DeviceDiscovery] ERROR: ARP scan failed: {e}")
            return []
        hosts = []
        for sent, received in result:
            try:
                vendor = self.lookup_mac_vendor(received.hwsrc)
                ports = self._scan_ports(received.psrc)
                hosts.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': vendor,
                    'ports': ports
                })
                print(f"[DeviceDiscovery] Found: IP={received.psrc}, MAC={received.hwsrc}, Vendor={vendor}, Ports={[p['port'] for p in ports]}")
            except Exception as e:
                logger.warning(f"Error processing host {received.psrc}: {e}")
                print(f"[DeviceDiscovery] WARNING: Error processing host {received.psrc}: {e}")
        if not hosts:
            print(f"[DeviceDiscovery] WARNING: No devices found on {network}.")
        logger.info(f"Discovered {len(hosts)} devices")
        print(f"[DeviceDiscovery] ARP scan complete. {len(hosts)} device(s) found.")
        return hosts

    def lookup_mac_vendor(self, mac):
        if not mac:
            return None
        if mac in self.mac_vendor_cache:
            return self.mac_vendor_cache[mac]
        try:
            url = f"https://api.macvendors.com/{mac}"
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                vendor = resp.text.strip()
                self.mac_vendor_cache[mac] = vendor
                return vendor
        except Exception as e:
            logger.debug(f"MAC vendor lookup failed for {mac}: {e}")
        return None

    def _scan_ports(self, ip, ports=[22, 23, 80, 443, 8080, 8443, 53, 554, 139, 445, 3389, 5000, 8888]):
        logger.info(f"Scanning ports on {ip}")
        print(f"[DeviceDiscovery] Scanning ports on {ip}...")
        open_ports = []
        for port in ports:
            try:
                pkt = IP(dst=ip)/TCP(dport=port, flags='S')
                resp = sr1(pkt, timeout=0.3, verbose=0)
                if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
                    open_ports.append({'port': port, 'state': 'open'})
                    # Send RST to close the connection
                    sr1(IP(dst=ip)/TCP(dport=port, flags='R'), timeout=0.3, verbose=0)
            except Exception as e:
                logger.warning(f"Port scan error on {ip}:{port}: {e}")
                print(f"[DeviceDiscovery] WARNING: Port scan error on {ip}:{port}: {e}")
        print(f"[DeviceDiscovery] Open ports on {ip}: {[p['port'] for p in open_ports]}")
        logger.info(f"Open ports on {ip}: {[p['port'] for p in open_ports]}")
        return open_ports 