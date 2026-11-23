"""MODULE 06 - Authorized device inventory of YOUR OWN private LAN (host discovery + MAC vendor lookup)."""
import ipaddress, json, os, re, socket, subprocess, time
from concurrent.futures import ThreadPoolExecutor
from core import config, system_check as sc

OUI_FILES = ["/usr/share/ieee-data/oui.txt", "/var/lib/ieee-data/oui.txt", "/usr/share/nmap/nmap-mac-prefixes"]
BUILTIN = {"B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi", "001A11": "Google", "F4F5D8": "Google",
           "3C5AB4": "Google", "FCFC48": "Apple", "A4B197": "Apple", "F0DBF8": "Apple", "001E58": "D-Link", "14CC20": "TP-Link",
           "50C7BF": "TP-Link", "F4F26D": "TP-Link", "C0A0BB": "D-Link", "00E04C": "Realtek", "001132": "Synology"}
_oui = None

def load_oui():
    global _oui
    if _oui is not None: return _oui
    _oui = dict(BUILTIN)
    for f in OUI_FILES:
        try:
            for line in open(f, errors="ignore"):
                m = re.match(r"^\s*([0-9A-F]{6})\s+\(base 16\)\s+(.+)$", line) or re.match(r"^([0-9A-F]{6})\s+(.+)$", line)
                if m: _oui[m.group(1).upper()] = m.group(2).strip()
            break
        except OSError: continue
    return _oui

def vendor(mac):
    if not mac: return "Unknown"
    h = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(h) < 6: return "Unknown"
    if int(h[1], 16) & 0x2: return "Randomized/private MAC"
    return load_oui().get(h[:6], "Unknown vendor")

def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(("10.255.255.255", 1)); return s.getsockname()[0]       # no packet is sent for UDP connect
    except OSError: return None
    finally: s.close()

def default_cidr():
    ip = local_ip()
    return str(ipaddress.ip_network(f"{ip}/24", strict=False)) if ip else None

def check_cidr(text):
    """Return (network, error). Only private ranges up to 1024 addresses are allowed."""
    try: net = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError: return None, "Not a valid network (example: 192.168.1.0/24)."
    if net.version != 4 or not net.is_private: return None, "Only private IPv4 ranges (your own LAN) are allowed."
    if net.num_addresses > 1024: return None, "Range too large (max /22 = 1024 addresses)."
    return net, None

def parse_arp(text):
    """Parse /proc/net/arp or `ip neigh` output into {ip: mac}."""
    out = {}
    for line in text.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+(?:dev \S+\s+lladdr|0x\d\s+0x\d\s+)\s*([0-9a-f:]{17})", line, re.I)
        if m and m.group(2) != "00:00:00:00:00:00": out[m.group(1)] = m.group(2).lower()
    return out

def read_arp():
    arp = {}
    try: arp.update(parse_arp(open("/proc/net/arp").read()))
    except OSError: pass
    if sc.have("ip"): arp.update(parse_arp(sc.run(["ip", "neigh"])[1]))
    return arp

def _ping(ip):
    try: return ip if subprocess.run(["ping", "-c", "1", "-W", "1", str(ip)], capture_output=True, timeout=3).returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired): return None

def sweep(net):
    hosts = [str(h) for h in net.hosts()]
    if sc.have("ping"):
        with ThreadPoolExecutor(max_workers=48) as ex: alive = [h for h in ex.map(_ping, hosts) if h]
    else: alive = []
    arp = read_arp()
    for ip in arp:                                   # devices that answered ARP even if they ignore ping
        if ipaddress.ip_address(ip) in net and ip not in alive: alive.append(ip)
    rows = []
    for ip in sorted(set(alive), key=lambda x: ipaddress.ip_address(x)):
        try: name = socket.gethostbyaddr(ip)[0]
        except OSError: name = "-"
        mac = arp.get(ip)
        rows.append({"ip": ip, "mac": mac or "unavailable", "vendor": vendor(mac) if mac else "n/a", "hostname": name})
    return rows

def run():
    from core import terminal_ui as ui
    ui.header("06 · AUTHORIZED DEVICE INVENTORY")
    default = default_cidr()
    ui.warn("Only scan a network you own or are explicitly authorized to audit.")
    if not ui.confirm("Do you own / have permission to scan this network?"): ui.info("Cancelled."); return
    net, e = check_cidr(ui.prompt(f"Network to scan [{default}]:") or (default or ""))
    if e: ui.err(e); return
    if not ui.confirm(f"Active scan of {net} ({net.num_addresses} addresses). Continue?"): ui.info("Cancelled."); return
    with ui.spinner("Discovering devices..."): rows = sweep(net)
    if not rows: ui.warn("No devices responded."); return
    config.SESSION["inventory"] = {"network": str(net), "time": time.strftime("%Y-%m-%d %H:%M:%S"), "devices": rows}
    ui.table(f"{len(rows)} devices on {net}", ["IP", "MAC", "Vendor", "Hostname"], [[r["ip"], r["mac"], r["vendor"], r["hostname"]] for r in rows])
    if any(r["mac"] == "unavailable" for r in rows):
        ui.warn("MAC addresses are unavailable for some devices (Android 10+ and non-root users cannot read the ARP table; run on Kali with sudo for full detail).")
    if not os.path.exists(OUI_FILES[0]) and not os.path.exists(OUI_FILES[2]): ui.info("Install `ieee-data` (apt) for full vendor names; a small built-in list is used now.")
    if ui.confirm("Export inventory to JSON?"):
        p = os.path.join(config.REPORTS, f"inventory_{time.strftime('%Y%m%d_%H%M%S')}.json"); 
        with open(p, "w") as f: json.dump(config.SESSION["inventory"], f, indent=2)
        ui.ok("Saved: " + p)
