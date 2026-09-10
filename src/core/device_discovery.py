"""
Universal Automatic Device Discovery Engine
============================================

Designed for enterprise IoT / hidden-device discovery.

The engine automatically determines usable local IPv4 networks and
performs:

    1. Local network detection
    2. OS ARP cache harvesting
    3. Layer-2 ARP discovery
    4. TCP service discovery
    5. MAC vendor identification
    6. Hostname discovery
    7. Fingerbank device fingerprinting
    8. Device classification
    9. Infrastructure topology generation

Usage:

    discovery = DeviceDiscovery()
    devices, topology = discovery.discover_devices()

No hardcoded subnet is required.

IMPORTANT:
    ARP discovery works on the local Layer-2 network/VLAN.
    It does not automatically discover devices behind routers
    or on other VLANs.
"""

import concurrent.futures
import ipaddress
import logging
import os
import platform
import re
import socket
import subprocess
from pathlib import Path

import requests

from scapy.all import ARP, Ether, srp


logger = logging.getLogger(__name__)


class DeviceDiscovery:
    """Universal automatic network discovery engine."""

    def __init__(self):
        # ========================================================
        # MAC Vendor Cache
        # ========================================================

        self.mac_vendor_cache = {
            "00:12:7B": "CP Plus",
            "3C:EF:8C": "CP Plus / Dahua",
            "4C:11:BF": "CP Plus / Dahua",
            "70:8D:09": "CP Plus / Dahua",
            "E0:50:8B": "CP Plus / Dahua",
            "BC:32:5B": "CP Plus / Dahua",
            "A0:BD:CD": "CP Plus / Dahua",
            "00:1A:07": "CP Plus / Dahua",
        }

        # ========================================================
        # Ports used for device/service identification
        # ========================================================

        self.scan_ports = [
            22,       # SSH
            80,       # HTTP
            443,      # HTTPS
            139,      # NetBIOS
            445,      # SMB
            554,      # RTSP
            631,      # IPP
            9100,     # JetDirect printers
            3389,     # RDP
            8000,     # CCTV/common management
            8899,     # CCTV
            25001,    # CCTV
            34567,    # DVR/NVR
            37777,    # Dahua
            37810,    # CCTV
        ]

        # Socket timeout is deliberately short because this scanner
        # may check many hosts and ports.
        self.port_timeout = 0.35

        # ========================================================
        # Fingerbank device fingerprinting
        # ========================================================

        self._load_local_env_file()

        self.fingerbank_api_key = os.getenv(
            "FINGERBANK_API_KEY",
            ""
        ).strip()

        self.fingerbank_url = (
            "https://api.fingerbank.org/"
            "api/v2/combinations/interrogate"
        )

        self.fingerbank_cache = {}

        if self.fingerbank_api_key:
            logger.info("Fingerbank integration enabled")
        else:
            logger.warning(
                "Fingerbank integration disabled: "
                "FINGERBANK_API_KEY was not found"
            )

    # ============================================================
    # MAIN DISCOVERY FUNCTION
    # ============================================================

    def discover_devices(self, network=None):
        """
        Discover devices on the local network.

        network:
            None -> automatically detect local IPv4 networks.

            Optional:
                "192.168.1.0/24"

            Multiple networks:
                "192.168.1.0/24,10.0.0.0/24"
        """

        print()
        print("=" * 70)
        print("        UNIVERSAL DEVICE DISCOVERY ENGINE")
        print("=" * 70)

        # ========================================================
        # STEP 1 - Determine networks
        # ========================================================

        if network:
            print(
                f"[Discovery] Manual network supplied: {network}"
            )
            subnets = self._parse_networks(network)
        else:
            print(
                "[Discovery] Automatically detecting local network..."
            )
            subnets = self._get_local_networks()

        subnets = [
            item for item in subnets
            if isinstance(item, ipaddress.IPv4Network)
        ]

        if not subnets:
            print(
                "[Discovery] ERROR: "
                "Could not determine a local IPv4 network."
            )
            logger.error("No IPv4 network detected.")
            return [], {}

        print()
        print("[Discovery] Networks detected:")
        for subnet in subnets:
            print(f"    -> {subnet}")

        logger.info(
            "Starting discovery on %s",
            [str(x) for x in subnets]
        )

        # ========================================================
        # STEP 2 - Local addresses
        # ========================================================

        local_ips = self._get_local_ipv4_addresses()

        print(
            f"[Discovery] Local IP addresses: "
            f"{sorted(local_ips)}"
        )

        # ========================================================
        # STEP 3 - Existing OS ARP cache
        # ========================================================

        print()
        print("[Discovery] Reading existing ARP cache...")

        hosts_map = {}

        arp_cache_hosts = self._harvest_system_arp_cache()

        for device in arp_cache_hosts:
            ip = device.get("ip")
            mac = device.get("mac")

            if not ip or not mac:
                continue

            if ip in local_ips:
                continue

            # Only retain cache entries that belong to one of the
            # networks we are actually scanning.
            if not self._ip_belongs_to_networks(ip, subnets):
                continue

            hosts_map[ip] = device

        print(
            f"[Discovery] ARP cache returned "
            f"{len(hosts_map)} device(s)."
        )

        # ========================================================
        # STEP 4 - Active ARP discovery
        # ========================================================

        print()

        for subnet in subnets:
            print(
                f"[Discovery] Scanning network: {subnet}"
            )

            discovered = self._scapy_arp_sweep(subnet)

            for device in discovered:
                ip = device.get("ip")
                mac = device.get("mac")

                if not ip or not mac:
                    continue

                if ip in local_ips:
                    continue

                if ip in hosts_map:
                    hosts_map[ip]["mac"] = mac

                    if (
                        not hosts_map[ip].get("vendor")
                        or hosts_map[ip].get("vendor")
                        == "Generic Device"
                    ):
                        hosts_map[ip]["vendor"] = device.get(
                            "vendor",
                            "Generic Device"
                        )
                else:
                    hosts_map[ip] = device

        all_hosts = list(hosts_map.values())

        print()
        print(
            f"[Discovery] ARP discovery found "
            f"{len(all_hosts)} device(s)."
        )

        # ========================================================
        # STEP 5 - Service discovery / identification
        # ========================================================

        print()
        print("[Discovery] Starting service discovery...")

        def process_host(device):
            ip = device.get("ip")

            if not ip:
                return device

            # ----------------------------------------------------
            # TCP service scan
            # ----------------------------------------------------

            try:
                device["ports"] = self._scan_ports(ip)
            except Exception as e:
                logger.debug(
                    "Port scan failed for %s: %s",
                    ip,
                    e
                )
                device["ports"] = []

            # ----------------------------------------------------
            # Vendor lookup
            # ----------------------------------------------------

            if (
                not device.get("vendor")
                or device.get("vendor") == "Generic Device"
            ):
                device["vendor"] = self.lookup_mac_vendor(
                    device.get("mac")
                )

            # ----------------------------------------------------
            # Hostname
            # ----------------------------------------------------

            try:
                hostname = self._resolve_hostname(ip)
                if hostname:
                    device["hostname"] = hostname
            except Exception:
                pass

            # ----------------------------------------------------
            # Fingerbank
            # ----------------------------------------------------

            try:
                fingerbank = self._fingerbank_identify(device)

                if fingerbank:
                    device["fingerbank"] = fingerbank
                    device["fingerbank_device"] = (
                        fingerbank.get("device_name")
                        or fingerbank.get("name")
                    )
                    device["fingerbank_score"] = fingerbank.get(
                        "score"
                    )
                    device["fingerbank_version"] = fingerbank.get(
                        "version"
                    )
                    device["fingerbank_os"] = fingerbank.get(
                        "operating_system"
                    )
                    device["fingerbank_manufacturer"] = (
                        fingerbank.get("manufacturer")
                    )

            except Exception as e:
                logger.debug(
                    "Fingerbank processing failed for %s: %s",
                    ip,
                    e
                )

            # ----------------------------------------------------
            # Classification
            # ----------------------------------------------------

            device["inferred"] = {
                "category": self._classify_device(device)
            }

            return device

        # Fingerbank requests + service checks are I/O-bound, but
        # keep concurrency deliberately low for Windows stability.
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=4
        ) as executor:
            processed = list(
                executor.map(process_host, all_hosts)
            )

        all_hosts = processed

        # ========================================================
        # STEP 6 - Filter invalid devices
        # ========================================================

        filtered_hosts = []

        for device in all_hosts:
            ip = device.get("ip")
            mac = device.get("mac")

            if not ip or not mac:
                continue

            mac = str(mac).upper().replace("-", ":")

            if ip in local_ips:
                continue

            if mac == "00:00:00:00:00:00":
                continue

            if mac == "FF:FF:FF:FF:FF:FF":
                continue

            if mac.startswith("FF:"):
                continue

            if mac.startswith("01:00:5E"):
                continue

            device["mac"] = mac
            filtered_hosts.append(device)

        # ========================================================
        # STEP 7 - Sort
        # ========================================================

        def ip_sort(device):
            try:
                return int(ipaddress.IPv4Address(device["ip"]))
            except Exception:
                return 0

        filtered_hosts.sort(key=ip_sort)

        # ========================================================
        # STEP 8 - Topology
        # ========================================================

        topology_graph = {}

        try:
            from src.core.infrastructure_discovery import TopologyBuilder

            builder = TopologyBuilder()

            topology_graph = builder.build_topology(
                filtered_hosts,
                [str(subnet) for subnet in subnets]
            )

        except Exception as e:
            logger.warning(
                "Topology construction failed: %s",
                e
            )

        # ========================================================
        # FINAL RESULT
        # ========================================================

        print()
        print("=" * 70)
        print("[Discovery] COMPLETE")
        print(
            f"[Discovery] Networks scanned : {len(subnets)}"
        )
        print(
            f"[Discovery] Devices found    : {len(filtered_hosts)}"
        )
        print("=" * 70)
        print()

        return filtered_hosts, topology_graph

    # ============================================================
    # AUTOMATIC NETWORK DETECTION
    # ============================================================

    def _get_local_networks(self):
        """
        Detect usable local IPv4 networks.

        Windows:
            PowerShell Get-NetIPAddress is preferred because it
            exposes PrefixLength directly. ipconfig is the fallback.

        Linux:
            ip -o -4 addr show is used.

        The actual network address is calculated using
        ipaddress.IPv4Network(..., strict=False).

        Example:
            172.30.100.25 + /24
            -> 172.30.100.0/24
        """

        networks = []
        system = platform.system().lower()

        if system == "windows":
            networks = self._get_windows_networks()

        elif system == "linux":
            networks = self._get_linux_networks()

        # --------------------------------------------------------
        # Generic fallback
        # --------------------------------------------------------

        if not networks:
            try:
                local_ip = self._get_local_ip()

                if local_ip:
                    network = ipaddress.IPv4Network(
                        f"{local_ip}/24",
                        strict=False
                    )

                    if network.prefixlen >= 16:
                        networks.append(network)

                    print(
                        "[Network Detection] "
                        f"Fallback -> {network}"
                    )

            except Exception as e:
                logger.warning(
                    "Network fallback failed: %s",
                    e
                )

        # --------------------------------------------------------
        # Deduplicate
        # --------------------------------------------------------

        unique_networks = []

        for network in networks:
            if network not in unique_networks:
                unique_networks.append(network)

        return unique_networks

    # ============================================================
    # WINDOWS NETWORK DETECTION
    # ============================================================

    def _get_windows_networks(self):
        """
        Detect Windows IPv4 networks.

        Primary method:
            PowerShell Get-NetIPAddress

        Fallback:
            ipconfig parsing
        """

        networks = []

        # --------------------------------------------------------
        # Primary: PowerShell structured output
        # --------------------------------------------------------

        powershell_commands = [
            (
                "Get-NetIPAddress -AddressFamily IPv4 "
                "| Where-Object {$_.IPAddress -notlike '127.*' "
                "-and $_.IPAddress -notlike '169.254.*'} "
                "| Select-Object IPAddress,PrefixLength "
                "| ConvertTo-Json -Compress"
            ),
        ]

        for command in powershell_commands:
            try:
                output = subprocess.check_output(
                    [
                        "powershell",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        command,
                    ],
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    timeout=5,
                ).strip()

                if output:
                    import json

                    parsed = json.loads(output)

                    if isinstance(parsed, dict):
                        parsed = [parsed]

                    for item in parsed:
                        ip = str(
                            item.get("IPAddress", "")
                        ).strip()

                        prefix_value = item.get("PrefixLength")

                        if not ip or prefix_value is None:
                            continue

                        try:
                            prefix = int(prefix_value)
                            ip_obj = ipaddress.IPv4Address(ip)

                            if (
                                ip_obj.is_loopback
                                or ip_obj.is_link_local
                                or ip_obj.is_multicast
                            ):
                                continue

                            if prefix < 16:
                                logger.warning(
                                    "Ignoring very large "
                                    "network prefix /%s for %s",
                                    prefix,
                                    ip
                                )
                                continue

                            if not 16 <= prefix <= 32:
                                continue

                            network = ipaddress.IPv4Network(
                                f"{ip}/{prefix}",
                                strict=False
                            )

                            if network not in networks:
                                networks.append(network)

                                print(
                                    "[Network Detection] "
                                    f"{ip}/{prefix} "
                                    f"-> {network}"
                                )

                        except Exception as e:
                            logger.debug(
                                "Invalid Windows network "
                                "%s/%s: %s",
                                ip,
                                prefix_value,
                                e
                            )

                    if networks:
                        return networks

            except Exception as e:
                logger.debug(
                    "PowerShell network detection failed: %s",
                    e
                )

        # --------------------------------------------------------
        # Fallback: ipconfig
        # --------------------------------------------------------

        try:
            output = subprocess.check_output(
                ["ipconfig"],
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=5,
            )

            current_ip = None

            for raw_line in output.splitlines():
                line = raw_line.strip()

                ipv4_match = re.search(
                    r"(?:IPv4 Address|IPv4-Adresse|Adresse IPv4)"
                    r"[^:]*:\s*"
                    r"(\d+\.\d+\.\d+\.\d+)",
                    line,
                    re.IGNORECASE
                )

                if ipv4_match:
                    current_ip = ipv4_match.group(1)
                    continue

                mask_match = re.search(
                    r"(?:Subnet Mask|Subnetzmaske|Masque de sous-réseau)"
                    r"[^:]*:\s*"
                    r"(\d+\.\d+\.\d+\.\d+)",
                    line,
                    re.IGNORECASE
                )

                if mask_match and current_ip:
                    mask = mask_match.group(1)

                    try:
                        ip_obj = ipaddress.IPv4Address(
                            current_ip
                        )

                        if (
                            ip_obj.is_loopback
                            or ip_obj.is_link_local
                            or ip_obj.is_multicast
                        ):
                            current_ip = None
                            continue

                        network = ipaddress.IPv4Network(
                            f"{current_ip}/{mask}",
                            strict=False
                        )

                        if network.prefixlen < 16:
                            logger.warning(
                                "Ignoring very large network %s",
                                network
                            )
                        elif network not in networks:
                            networks.append(network)

                            print(
                                "[Network Detection] "
                                f"{current_ip} / {mask} "
                                f"-> {network}"
                            )

                    except Exception as e:
                        logger.debug(
                            "ipconfig network calculation failed: %s",
                            e
                        )

                    current_ip = None

        except Exception as e:
            logger.warning(
                "Windows ipconfig network detection failed: %s",
                e
            )

        return networks

    # ============================================================
    # LINUX NETWORK DETECTION
    # ============================================================

    def _get_linux_networks(self):
        """Detect usable Linux/Raspberry Pi IPv4 networks."""

        networks = []

        try:
            output = subprocess.check_output(
                [
                    "ip",
                    "-o",
                    "-4",
                    "addr",
                    "show"
                ],
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=5,
            )

            for line in output.splitlines():
                match = re.search(
                    r"\binet\s+"
                    r"(\d+\.\d+\.\d+\.\d+)/(\d+)",
                    line
                )

                if not match:
                    continue

                ip = match.group(1)
                prefix = int(match.group(2))

                try:
                    ip_obj = ipaddress.IPv4Address(ip)

                    if (
                        ip_obj.is_loopback
                        or ip_obj.is_link_local
                        or ip_obj.is_multicast
                    ):
                        continue

                    if prefix < 16 or prefix > 32:
                        continue

                    network = ipaddress.IPv4Network(
                        f"{ip}/{prefix}",
                        strict=False
                    )

                    if network not in networks:
                        networks.append(network)

                        print(
                            "[Network Detection] "
                            f"{ip}/{prefix} "
                            f"-> {network}"
                        )

                except Exception:
                    continue

        except Exception as e:
            logger.warning(
                "Linux network detection failed: %s",
                e
            )

        return networks

    # ============================================================
    # MANUAL NETWORK PARSER
    # ============================================================

    def _parse_networks(self, network):
        """Parse CIDR networks or plain IPv4 addresses."""

        networks = []

        if not network:
            return networks

        if isinstance(network, (list, tuple)):
            values = network
        else:
            values = str(network).split(",")

        for value in values:
            value = str(value).strip()

            if not value:
                continue

            try:
                parsed = ipaddress.IPv4Network(
                    value,
                    strict=False
                )

                if parsed.prefixlen < 16:
                    logger.warning(
                        "Ignoring very large network: %s",
                        parsed
                    )
                    continue

                networks.append(parsed)
                continue

            except ValueError:
                pass

            # Plain IPv4 address -> /24 compatibility fallback.
            try:
                parsed = ipaddress.IPv4Network(
                    f"{value}/24",
                    strict=False
                )

                logger.warning(
                    "Network '%s' had no prefix. "
                    "Interpreting it as %s",
                    value,
                    parsed
                )

                networks.append(parsed)

            except Exception as e:
                logger.warning(
                    "Invalid network '%s': %s",
                    value,
                    e
                )

        return networks

    # ============================================================
    # NETWORK MEMBERSHIP
    # ============================================================

    @staticmethod
    def _ip_belongs_to_networks(ip, networks):
        """Return True when an IPv4 address belongs to a scanned subnet."""

        try:
            address = ipaddress.IPv4Address(ip)

            return any(
                address in network
                for network in networks
            )

        except Exception:
            return False

    # ============================================================
    # LOCAL IP ADDRESS DETECTION
    # ============================================================

    def _get_local_ipv4_addresses(self):
        """Return usable IPv4 addresses assigned to this host."""

        addresses = set()

        try:
            hostname = socket.gethostname()

            results = socket.getaddrinfo(
                hostname,
                None,
                socket.AF_INET
            )

            for result in results:
                ip = result[4][0]

                try:
                    ip_obj = ipaddress.IPv4Address(ip)

                    if (
                        not ip_obj.is_loopback
                        and not ip_obj.is_link_local
                        and not ip_obj.is_multicast
                    ):
                        addresses.add(ip)

                except Exception:
                    pass

        except Exception:
            pass

        try:
            local_ip = self._get_local_ip()

            if local_ip:
                addresses.add(local_ip)

        except Exception:
            pass

        # Windows: obtain all IPv4 addresses from PowerShell as
        # another way of catching adapters that hostname resolution
        # does not expose.
        if platform.system().lower() == "windows":
            try:
                command = (
                    "Get-NetIPAddress -AddressFamily IPv4 "
                    "| Select-Object -ExpandProperty IPAddress"
                )

                output = subprocess.check_output(
                    [
                        "powershell",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        command,
                    ],
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    timeout=5,
                )

                for line in output.splitlines():
                    ip = line.strip()

                    try:
                        ip_obj = ipaddress.IPv4Address(ip)

                        if (
                            not ip_obj.is_loopback
                            and not ip_obj.is_link_local
                            and not ip_obj.is_multicast
                        ):
                            addresses.add(ip)

                    except Exception:
                        pass

            except Exception:
                pass

        return addresses

    # ============================================================
    # GET PRIMARY LOCAL IP
    # ============================================================

    def _get_local_ip(self):
        """
        Determine the primary local IPv4 address.

        No packet is sent to the destination. The UDP socket is
        only used so Windows/Linux selects the interface it would
        use for that destination.
        """

        sock = None

        try:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )

            sock.settimeout(1)

            sock.connect(("8.8.8.8", 80))

            return sock.getsockname()[0]

        except Exception:
            return None

        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    # ============================================================
    # LOCAL .ENV LOADING
    # ============================================================

    def _load_local_env_file(self):
        """
        Load simple KEY=VALUE entries from .env.

        Existing environment variables take precedence.
        """

        candidates = [
            Path.cwd() / ".env",
            Path(__file__).resolve().parents[2] / ".env",
        ]

        env_path = None

        for candidate in candidates:
            try:
                if candidate.is_file():
                    env_path = candidate
                    break
            except Exception:
                pass

        if not env_path:
            return

        try:
            for raw_line in env_path.read_text(
                encoding="utf-8",
                errors="ignore"
            ).splitlines():

                line = raw_line.strip()

                if not line or line.startswith("#"):
                    continue

                if line.startswith("export "):
                    line = line[7:].strip()

                if "=" not in line:
                    continue

                key, value = line.split("=", 1)

                key = key.strip()
                value = value.strip()

                if not key:
                    continue

                if (
                    len(value) >= 2
                    and value[0] == value[-1]
                    and value[0] in {"\"", "'"}
                ):
                    value = value[1:-1]

                os.environ.setdefault(key, value)

        except Exception as e:
            logger.debug(
                "Could not load project .env file: %s",
                e
            )

    # ============================================================
    # HOSTNAME DISCOVERY
    # ============================================================

    def _resolve_hostname(self, ip):
        """Attempt reverse DNS and Windows NetBIOS hostname discovery."""

        if not ip:
            return None

        # --------------------------------------------------------
        # Reverse DNS
        # --------------------------------------------------------

        try:
            hostname, aliases, addresses = socket.gethostbyaddr(ip)

            if hostname:
                hostname = hostname.rstrip(".").strip()

                if hostname and hostname != ip:
                    return hostname

        except Exception:
            pass

        # --------------------------------------------------------
        # Windows NetBIOS
        # --------------------------------------------------------

        if platform.system().lower() == "windows":
            try:
                output = subprocess.check_output(
                    ["nbtstat", "-A", ip],
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    timeout=2.5
                )

                for line in output.splitlines():
                    match = re.match(
                        r"^\s*([A-Za-z0-9_.-]{1,63})"
                        r"\s+<00>\s+UNIQUE",
                        line,
                        re.IGNORECASE
                    )

                    if match:
                        return match.group(1)

            except Exception:
                pass

        return None

    # ============================================================
    # FINGERBANK DEVICE FINGERPRINTING
    # ============================================================

    def _fingerbank_identify(self, device):
        """
        Identify a device with Fingerbank.

        MAC is the minimum fingerprint. Hostname is added when
        available to improve identification.
        """

        if not self.fingerbank_api_key:
            return {}

        mac = str(device.get("mac", "")).strip()

        if not mac:
            return {}

        mac = mac.replace("-", ":").lower()

        if mac in {
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff"
        }:
            return {}

        if mac in self.fingerbank_cache:
            return self.fingerbank_cache[mac]

        payload = {"mac": mac}

        hostname = device.get("hostname")

        if hostname:
            payload["hostname"] = str(hostname)

        headers = {
            "Authorization": f"Bearer {self.fingerbank_api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        try:
            response = requests.post(
                self.fingerbank_url,
                json=payload,
                headers=headers,
                timeout=5
            )

            if response.status_code == 404:
                logger.debug(
                    "Fingerbank: no profile found for %s",
                    mac
                )
                self.fingerbank_cache[mac] = {}
                return {}

            if response.status_code == 401:
                logger.error(
                    "Fingerbank API key rejected (HTTP 401). "
                    "Check FINGERBANK_API_KEY in .env."
                )
                return {}

            if response.status_code == 403:
                logger.error(
                    "Fingerbank API access forbidden (HTTP 403)."
                )
                return {}

            if response.status_code == 429:
                logger.warning(
                    "Fingerbank rate limit reached (HTTP 429)."
                )
                return {}

            if response.status_code != 200:
                logger.warning(
                    "Fingerbank returned HTTP %s for %s",
                    response.status_code,
                    mac
                )
                return {}

            data = response.json()

            fb_device = data.get("device") or {}
            manufacturer = data.get("manufacturer") or {}
            operating_system = data.get("operating_system") or {}
            vulnerabilities = data.get("vulnerabilities") or {}

            result = {
                "device_id": fb_device.get("id"),
                "name": fb_device.get("name"),
                "device_name": data.get("device_name"),
                "score": data.get("score"),
                "version": data.get("version"),
                "manufacturer": manufacturer.get("name"),
                "operating_system": operating_system.get("name"),
                "operating_system_id": operating_system.get("id"),
                "can_be_more_precise": fb_device.get(
                    "can_be_more_precise"
                ),
                "request_id": data.get("request_id"),
                "vulnerabilities": vulnerabilities
            }

            self.fingerbank_cache[mac] = result

            logger.info(
                "Fingerbank: %s -> %s (score=%s)",
                mac,
                result.get("device_name")
                or result.get("name")
                or "Unknown",
                result.get("score")
            )

            return result

        except requests.RequestException as e:
            logger.warning(
                "Fingerbank request failed for %s: %s",
                mac,
                e
            )

        except ValueError as e:
            logger.warning(
                "Fingerbank returned invalid JSON for %s: %s",
                mac,
                e
            )

        except Exception as e:
            logger.warning(
                "Fingerbank processing failed for %s: %s",
                mac,
                e
            )

        return {}

    # ============================================================
    # OS ARP CACHE
    # ============================================================

    def _harvest_system_arp_cache(self):
        """Read the operating system's existing ARP/neighbor cache."""

        hosts = []

        try:
            system = platform.system().lower()

            if system == "windows":
                output = subprocess.check_output(
                    ["arp", "-a"],
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    timeout=5
                )

            else:
                try:
                    output = subprocess.check_output(
                        ["ip", "neigh"],
                        text=True,
                        encoding="utf-8",
                        errors="ignore",
                        timeout=5
                    )

                except Exception:
                    output = subprocess.check_output(
                        ["arp", "-a"],
                        text=True,
                        encoding="utf-8",
                        errors="ignore",
                        timeout=5
                    )

            windows_pattern = re.compile(
                r"(\d{1,3}(?:\.\d{1,3}){3})"
                r"\s+"
                r"([0-9a-fA-F]{2}"
                r"(?:[-:][0-9a-fA-F]{2}){5})"
            )

            linux_pattern = re.compile(
                r"(\d{1,3}(?:\.\d{1,3}){3})"
                r".*?"
                r"(?:lladdr\s+)"
                r"([0-9a-fA-F]{2}"
                r"(?:[:\-][0-9a-fA-F]{2}){5})"
            )

            for line in output.splitlines():
                match = (
                    windows_pattern.search(line)
                    or linux_pattern.search(line)
                )

                if not match:
                    continue

                ip = match.group(1)
                mac = (
                    match.group(2)
                    .replace("-", ":")
                    .upper()
                )

                try:
                    ip_obj = ipaddress.IPv4Address(ip)
                except Exception:
                    continue

                if (
                    ip_obj.is_loopback
                    or ip_obj.is_multicast
                    or ip_obj.is_link_local
                ):
                    continue

                if (
                    mac == "00:00:00:00:00:00"
                    or mac == "FF:FF:FF:FF:FF:FF"
                    or mac.startswith("01:00:5E")
                ):
                    continue

                hosts.append(
                    {
                        "ip": ip,
                        "mac": mac,
                        "vendor": self.lookup_mac_vendor(mac),
                        "ports": []
                    }
                )

        except Exception as e:
            logger.warning(
                "ARP cache harvesting failed: %s",
                e
            )

        return hosts

    # ============================================================
    # SCAPY ARP SWEEP
    # ============================================================

    def _scapy_arp_sweep(self, network):
        """
        Perform one sequential Layer-2 ARP sweep.

        The Scapy operation is intentionally not wrapped in a
        ThreadPoolExecutor. This avoids overlapping Scapy
        send/receive operations on Windows.
        """

        hosts = []

        try:
            if isinstance(network, str):
                network = ipaddress.IPv4Network(
                    network,
                    strict=False
                )

            elif not isinstance(
                network,
                ipaddress.IPv4Network
            ):
                network = ipaddress.IPv4Network(
                    str(network),
                    strict=False
                )

            network_cidr = str(network)

            print(f"[ARP] Sweeping {network_cidr}")

            # Maximum 4096 addresses per sweep.
            if network.num_addresses > 4096:
                logger.warning(
                    "Skipping oversized ARP network: %s",
                    network
                )
                return hosts

            packet = (
                Ether(dst="ff:ff:ff:ff:ff:ff")
                / ARP(pdst=network_cidr)
            )

            answered, unanswered = srp(
                packet,
                timeout=1.5,
                retry=1,
                verbose=0
            )

            for sent, received in answered:
                try:
                    ip = received.psrc
                    mac = received.hwsrc.upper()

                    if not ip or not mac:
                        continue

                    if (
                        mac == "00:00:00:00:00:00"
                        or mac == "FF:FF:FF:FF:FF:FF"
                        or mac.startswith("01:00:5E")
                    ):
                        continue

                    hosts.append(
                        {
                            "ip": ip,
                            "mac": mac,
                            "vendor": self.lookup_mac_vendor(mac),
                            "ports": []
                        }
                    )

                except Exception:
                    continue

            print(
                f"[ARP] {network_cidr}: "
                f"{len(hosts)} device(s) responded"
            )

        except Exception as e:
            logger.warning(
                "ARP sweep failed for %s: %s",
                network,
                e
            )

            print(f"[ARP] Failed: {e}")

        return hosts

    # ============================================================
    # MAC VENDOR LOOKUP
    # ============================================================

    def lookup_mac_vendor(self, mac):
        """Look up a MAC vendor using local cache then MACVendors API."""

        if not mac:
            return "Generic Device"

        mac = str(mac).upper().replace("-", ":")

        if (
            mac.startswith("00:00:00")
            or mac.startswith("FF:")
        ):
            return "Generic Device"

        prefix = mac[:8]

        if prefix in self.mac_vendor_cache:
            return self.mac_vendor_cache[prefix]

        try:
            response = requests.get(
                f"https://api.macvendors.com/{mac}",
                timeout=1.2
            )

            if response.status_code == 200:
                vendor = response.text.strip()

                if vendor:
                    self.mac_vendor_cache[prefix] = vendor
                    return vendor

        except Exception:
            pass

        return "Generic Device"

    # ============================================================
    # TCP PORT SCANNING
    # ============================================================

    def _scan_ports(self, ip, ports=None):
        """
        Scan TCP services using normal sockets.

        This intentionally does NOT use Scapy sr1() for TCP probing.
        On Windows, many simultaneous Scapy sr1() operations can
        produce OSError [Errno 9] Bad file descriptor.

        A normal TCP connect is sufficient for service discovery
        because the scanner only needs to determine whether the
        service is accepting TCP connections.
        """

        if ports is None:
            ports = self.scan_ports

        open_ports = []

        for port in ports:
            try:
                with socket.socket(
                    socket.AF_INET,
                    socket.SOCK_STREAM
                ) as sock:

                    sock.settimeout(self.port_timeout)

                    result = sock.connect_ex(
                        (ip, int(port))
                    )

                    if result == 0:
                        open_ports.append(
                            {
                                "port": int(port),
                                "state": "open"
                            }
                        )

            except (
                socket.timeout,
                ConnectionRefusedError,
                OSError,
                ValueError
            ):
                continue

        open_ports.sort(
            key=lambda item: item["port"]
        )

        return open_ports

    # ============================================================
    # DEVICE CLASSIFICATION
    # ============================================================

    def _classify_device(self, device):
        """Infer a broad device category from available evidence."""

        ports = []

        for item in device.get("ports", []):
            if isinstance(item, dict) and "port" in item:
                try:
                    ports.append(int(item["port"]))
                except Exception:
                    pass

        vendor = (
            device.get("vendor") or ""
        ).lower()

        hostname = (
            device.get("hostname") or ""
        ).lower()

        fingerbank = device.get("fingerbank") or {}

        fb_name = (
            fingerbank.get("device_name")
            or fingerbank.get("name")
            or ""
        ).lower()

        fb_os = (
            fingerbank.get("operating_system")
            or ""
        ).lower()

        fb_manufacturer = (
            fingerbank.get("manufacturer")
            or ""
        ).lower()

        fb_text = " ".join(
            [
                fb_name,
                fb_os,
                fb_manufacturer
            ]
        )

        all_text = " ".join(
            [
                vendor,
                hostname,
                fb_text
            ]
        )

        # ========================================================
        # IP CAMERA / CCTV
        # ========================================================

        cctv_ports = {
            554, 8000, 8899,
            25001, 34567,
            37777, 37810
        }

        cctv_names = [
            "camera",
            "cctv",
            "dvr",
            "nvr",
            "hikvision",
            "dahua",
            "axis",
            "reolink",
            "amcrest",
            "uniview",
            "xiongmai",
            "ezviz",
            "imou",
        ]

        cctv_vendors = [
            "cp plus",
            "cpplus",
            "dahua",
            "hikvision",
            "axis",
            "reolink",
            "amcrest",
            "uniview",
            "xiongmai",
            "ezviz",
            "imou",
        ]

        if (
            any(port in cctv_ports for port in ports)
            or any(name in all_text for name in cctv_vendors)
            or any(name in all_text for name in cctv_names)
        ):
            return "IP Camera"

        # ========================================================
        # PRINTER
        # ========================================================

        printer_names = [
            "printer",
            "print",
            "laserjet",
            "deskjet",
            "officejet",
            "pixma",
            "epson",
            "brother",
            "xerox",
            "lexmark",
        ]

        printer_vendors = [
            "hp",
            "epson",
            "canon",
            "brother",
            "xerox",
            "lexmark",
        ]

        if (
            9100 in ports
            or 631 in ports
            or any(name in all_text for name in printer_vendors)
            or any(name in all_text for name in printer_names)
        ):
            return "Printer"

        # ========================================================
        # SMARTPHONE / TABLET
        # ========================================================

        smartphone_names = [
            "android",
            "iphone",
            "ipad",
            "smartphone",
            "mobile",
            "ios",
            "galaxy",
            "pixel",
            "oneplus",
            "xiaomi",
            "redmi",
            "oppo",
            "vivo",
            "realme",
            "huawei",
            "motorola",
        ]

        smartphone_vendors = [
            "apple",
            "samsung",
            "xiaomi",
            "huawei",
            "oneplus",
            "oppo",
            "vivo",
            "realme",
            "google",
            "motorola",
        ]

        if (
            any(name in all_text for name in smartphone_names)
            or any(name in vendor for name in smartphone_vendors)
        ):
            return "Smartphone / Tablet"

        # ========================================================
        # SMART TV / MEDIA DEVICE
        # ========================================================

        tv_names = [
            "smart tv",
            "television",
            "roku",
            "chromecast",
            "fire tv",
            "android tv",
            "google tv",
            "apple tv",
        ]

        tv_vendors = [
            "roku",
            "sony",
            "lg electronics",
            "vizio",
            "toshiba",
            "tcl",
        ]

        if (
            any(name in all_text for name in tv_names)
            or any(name in vendor for name in tv_vendors)
        ):
            return "Smart TV / Media Device"

        # ========================================================
        # RASPBERRY PI / SINGLE BOARD COMPUTER
        # ========================================================

        sbc_names = [
            "raspberry pi",
            "raspberrypi",
            "single board computer",
            "raspbian",
        ]

        if any(name in all_text for name in sbc_names):
            return "Raspberry Pi / SBC"

        # ========================================================
        # WORKSTATION / PC / SERVER
        # ========================================================

        windows_names = [
            "windows",
            "microsoft windows",
            "windows kernel",
        ]

        linux_names = [
            "linux",
            "ubuntu",
            "debian",
            "fedora",
            "centos",
            "red hat",
        ]

        pc_vendors = [
            "dell",
            "hewlett",
            "lenovo",
            "asus",
            "acer",
            "intel",
            "microsoft",
            "gigabyte",
            "msi",
            "apple",
        ]

        if (
            any(name in all_text for name in windows_names)
            or any(name in all_text for name in linux_names)
            or any(name in vendor for name in pc_vendors)
            or any(port in ports for port in [22, 139, 445, 3389])
        ):
            return "Workstation / PC"

        # ========================================================
        # DEFAULT
        # ========================================================

        return "IoT Device"
