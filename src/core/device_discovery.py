"""
Single Unified Device Discovery Module for Enterprise IoT Risk Detection System.
Provides 1 fast, deterministic, clean discovery engine combining Layer-2 ARP Probing,
OS ARP Cache harvesting, and Multi-Threaded Service Port Scanning.
"""
import logging
import requests
import time
import socket
import re
import subprocess
import concurrent.futures
from scapy.all import ARP, Ether, srp, IP, TCP, sr1

logger = logging.getLogger(__name__)

class DeviceDiscovery:
    """Single Unified Engine for fast, accurate network device discovery."""
    
    def __init__(self):
        self.mac_vendor_cache = {
            '00:12:7B': 'CP Plus',
            '3C:EF:8C': 'CP Plus / Dahua',
            '4C:11:BF': 'CP Plus / Dahua',
            '70:8D:09': 'CP Plus / Dahua',
            'E0:50:8B': 'CP Plus / Dahua',
            'BC:32:5B': 'CP Plus / Dahua',
            'A0:BD:CD': 'CP Plus / Dahua',
            '00:1A:07': 'CP Plus / Dahua'
        }

    def discover_devices(self, network="192.168.137.0/24, 192.168.1.0/24, 192.168.0.0/24"):
        """Executes 1 Single Unified Engine to capture all physically connected active network devices."""
        subnets = [s.strip() for s in network.split(',') if s.strip()]
        hosts_map = {} # IP -> host_dict
        
        print(f"[UnifiedDiscoveryEngine] Starting scan on subnets: {subnets}")
        logger.info(f"Starting unified scan on subnets: {subnets}")

        # Step 1: Harvest OS ARP Cache (Instant discovery of all active IP/MAC entries)
        for dev in self._harvest_system_arp_cache():
            if dev.get('ip') and dev.get('mac') and dev['mac'] != '00:00:00:00:00:00':
                hosts_map[dev['ip']] = dev

        # Step 2: Layer-2 ARP Sweep across subnets
        for subnet in subnets:
            self._wake_up_hosts(subnet)
            for dev in self._scapy_arp_sweep(subnet):
                ip = dev['ip']
                mac = dev['mac']
                if mac and mac != '00:00:00:00:00:00':
                    if ip in hosts_map:
                        hosts_map[ip]['mac'] = mac
                    else:
                        hosts_map[ip] = dev

        all_hosts = list(hosts_map.values())

        # Step 3: Multi-Threaded Service Port Scan, Vendor Lookup & Smart Category Classification
        def process_host(dev):
            ip = dev['ip']
            dev['ports'] = self._scan_ports(ip)
            if not dev.get('vendor') or dev['vendor'] == 'Generic Device':
                dev['vendor'] = self.lookup_mac_vendor(dev.get('mac'))
            category = self._classify_device(dev)
            dev['inferred'] = {'category': category}

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(process_host, all_hosts)

        # Filter out gateway IP and invalid MAC entries
        gateway_ip = subnets[0].rsplit('.', 1)[0] + '.1' if subnets and '.' in subnets[0] else '192.168.137.1'
        filtered_hosts = [
            h for h in all_hosts 
            if h.get('ip') != gateway_ip 
            and h.get('mac') 
            and h.get('mac') != '00:00:00:00:00:00'
        ]

        # Step 4: Build Infrastructure Topology Relationship Graph
        from src.core.infrastructure_discovery import TopologyBuilder
        builder = TopologyBuilder()
        topology_graph = builder.build_topology(filtered_hosts, subnets)

        print(f"[UnifiedDiscoveryEngine] Scan complete. Found {len(filtered_hosts)} verified physical host(s).")
        return filtered_hosts, topology_graph

    def _wake_up_hosts(self, network):
        """Fast socket sweep to wake up sleeping network devices."""
        base_ip = network.rsplit('.', 1)[0] if '/' in network else "192.168.137"
        target_ips = [f"{base_ip}.{i}" for i in range(1, 255)]
        
        def ping_ip(ip_str):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.08)
                sock.connect((ip_str, 80))
                sock.close()
            except Exception:
                pass
                
        with concurrent.futures.ThreadPoolExecutor(max_workers=60) as executor:
            executor.map(ping_ip, target_ips)

    def _harvest_system_arp_cache(self):
        """Parses system ARP cache ('arp -a') across all subnets."""
        hosts = []
        try:
            output = subprocess.check_output("arp -a", shell=True).decode("utf-8", errors="ignore")
            pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fa-f]{2}[-:][0-9a-fa-f]{2}[-:][0-9a-fa-f]{2}[-:][0-9a-fa-f]{2}[-:][0-9a-fa-f]{2}[-:][0-9a-fa-f]{2})')
            for line in output.splitlines():
                if 'dynamic' in line.lower() or 'static' in line.lower():
                    match = pattern.search(line)
                    if match:
                        ip = match.group(1).strip()
                        mac = match.group(2).strip().replace('-', ':').upper()
                        if not ip.startswith("127.") and not mac.startswith("FF:") and not mac.startswith("01:00:5E"):
                            hosts.append({'ip': ip, 'mac': mac, 'vendor': self.lookup_mac_vendor(mac), 'ports': []})
        except Exception as e:
            logger.warning(f"ARP harvest failed: {e}")
        return hosts

    def _scapy_arp_sweep(self, network):
        """Scapy Layer-2 ARP Sweep."""
        hosts = []
        try:
            arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network)
            result = srp(arp_pkt, timeout=0.4, retry=1, verbose=0)[0]
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc.upper()
                if mac and mac != '00:00:00:00:00:00':
                    hosts.append({'ip': ip, 'mac': mac, 'vendor': self.lookup_mac_vendor(mac), 'ports': []})
        except Exception as e:
            logger.warning(f"Scapy ARP sweep error: {e}")
        return hosts

    def lookup_mac_vendor(self, mac):
        """Looks up hardware MAC vendor OUI."""
        if not mac or mac.startswith("00:00:00") or mac.startswith("FF:"):
            return "Generic Device"
        prefix = mac.upper()[:8]
        if prefix in self.mac_vendor_cache:
            return self.mac_vendor_cache[prefix]
        try:
            resp = requests.get(f"https://api.macvendors.com/{mac}", timeout=1.2)
            if resp.status_code == 200:
                vendor = resp.text.strip()
                self.mac_vendor_cache[prefix] = vendor
                return vendor
        except Exception:
            pass
        return "Generic Device"

    def _scan_ports(self, ip, ports=[80, 443, 554, 8000, 25001, 37777, 37810, 34567, 8899, 22, 139, 445, 3389]):
        """Fast multi-threaded TCP port scan."""
        open_ports = []
        def check(p):
            try:
                pkt = IP(dst=ip)/TCP(dport=p, flags='S')
                resp = sr1(pkt, timeout=0.1, verbose=0)
                if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
                    sr1(IP(dst=ip)/TCP(dport=p, flags='R'), timeout=0.05, verbose=0)
                    return {'port': p, 'state': 'open'}
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports)) as executor:
            results = executor.map(check, ports)
            for r in results:
                if r: open_ports.append(r)
        return open_ports

    def _classify_device(self, device):
        """Determines device category cleanly."""
        ports = [p['port'] for p in device.get('ports', [])] if isinstance(device.get('ports'), list) else []
        vendor = (device.get('vendor') or '').lower()

        cctv_ports = {554, 8000, 25001, 37777, 37810, 34567, 8899}
        cctv_vendors = ['cp plus', 'cpplus', 'dahua', 'hikvision', 'axis', 'reolink', 'amcrest', 'indivision', 'uniview', 'xiongmai', 'ezviz', 'imou']
        if any(p in cctv_ports for p in ports) or any(k in vendor for k in cctv_vendors):
            return "IP Camera"

        if any(v in vendor for v in ['apple', 'samsung', 'xiaomi', 'huawei', 'oneplus', 'oppo', 'vivo', 'realme', 'google', 'lg electronics', 'motorola']):
            return "Smartphone"

        if any(v in vendor for v in ['roku', 'sony', 'lg electronics', 'vizio', 'toshiba', 'tcl']):
            return "Smart TV"

        if 9100 in ports or 631 in ports or any(v in vendor for v in ['hp', 'epson', 'canon', 'brother', 'xerox', 'lexmark']):
            return "Printer"

        if 3389 in ports or 445 in ports or 139 in ports or 22 in ports:
            return "Workstation / PC"

        return "IoT Device"
