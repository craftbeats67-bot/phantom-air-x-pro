"""MODULE 07 - Router security audit of YOUR gateway: exposed management services and visible configuration indicators."""
import re, socket, struct
from concurrent.futures import ThreadPoolExecutor
from core import config, system_check as sc

PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP admin", 443: "HTTPS admin", 8080: "HTTP alt admin",
         8443: "HTTPS alt admin", 7547: "TR-069 (ISP management)", 5555: "ADB / debug"}

def gateway():
    try:
        for line in open("/proc/net/route").read().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000": return socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
    except (OSError, IndexError, ValueError): pass
    if sc.have("ip"):
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", sc.run(["ip", "route"])[1])
        if m: return m.group(1)
    if sc.platform_name() == "termux":
        import json
        rc, out, _ = sc.run(["termux-wifi-dhcpinfo"])
        try: return json.loads(out).get("gateway")
        except ValueError: pass
    return None

def _probe(args):
    ip, port = args
    try: socket.create_connection((ip, port), timeout=1.5).close(); return port
    except OSError: return None

def open_ports(ip):
    with ThreadPoolExecutor(max_workers=10) as ex: return sorted(p for p in ex.map(_probe, [(ip, p) for p in PORTS]) if p)

def http_info(ip, port):
    try:
        s = socket.create_connection((ip, port), timeout=3); s.settimeout(3)
        s.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()); data = s.recv(2048).decode(errors="ignore"); s.close()
    except OSError: return {}
    h = dict(re.findall(r"^([A-Za-z\-]+):\s*(.+?)\r?$", data, re.M))
    return {"status": data.split("\r\n")[0], "server": h.get("Server"), "location": h.get("Location"), "www_auth": h.get("WWW-Authenticate")}

def upnp_enabled(ip):
    msg = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
    try:
        s.sendto(msg, (ip, 1900)); data, _ = s.recvfrom(2048); return data.decode(errors="ignore")
    except OSError: return None
    finally: s.close()

def build_findings(ports, http80=None, http_redirects_tls=False, upnp=None, wifi_security=None):
    f = []
    add = lambda sev, issue, fix: f.append({"severity": sev, "issue": issue, "recommendation": fix})
    if 23 in ports: add("CRITICAL", "Telnet is open on the router (unencrypted remote login).", "Disable Telnet; use HTTPS or SSH only on the LAN.")
    if 21 in ports: add("HIGH", "FTP is open on the router.", "Disable FTP/USB sharing unless you need it, and use strong credentials.")
    if 5555 in ports: add("HIGH", "ADB/debug port is open.", "Disable debug services in the router settings or firmware.")
    if 7547 in ports: add("MEDIUM", "TR-069 management port is reachable from the LAN.", "Normal for some ISPs; ensure firmware is current and remote management is limited to the ISP.")
    if 80 in ports and 443 not in ports: add("MEDIUM", "Admin page is served over HTTP only (credentials sent unencrypted).", "Enable HTTPS admin access if supported, or use a wired connection to administer.")
    if 80 in ports and 443 in ports and not http_redirects_tls: add("LOW", "HTTP admin page does not redirect to HTTPS.", "Enable 'force HTTPS' for administration if available.")
    if 22 in ports: add("LOW", "SSH is enabled on the router.", "Disable it if unused; otherwise use key-based login.")
    if upnp: add("MEDIUM", "UPnP responded: devices can open ports automatically.", "Disable UPnP unless an application needs it.")
    if http80 and http80.get("server"): add("INFO", f"Router banner reveals: {http80['server']}. Check the vendor site for a newer firmware.", "Firmware version cannot be read without logging in; verify it in the admin page.")
    if wifi_security in ("OPEN", "WEP", "WPA"): add("HIGH", f"Your Wi-Fi uses {wifi_security}.", "Switch to WPA3 or WPA2-AES.")
    if not f: add("OK", "No risky exposed services found from this vantage point.", "Keep firmware updated and use a strong admin password.")
    f.append({"severity": "INFO", "issue": "Not checked: default admin password, WPS state, firmware version (need your login).", "recommendation": "Review these in the router's admin page: change default credentials and disable WPS."})
    return f

def run():
    from core import terminal_ui as ui
    from modules import signal_analyzer, wifi_scanner
    ui.header("07 · ROUTER SECURITY AUDIT")
    ui.warn("Only audit a router you own or are authorized to test. This opens connections to the router.")
    gw = gateway()
    if not gw: ui.err("Could not determine the default gateway. Are you connected to Wi-Fi/LAN?"); return
    ui.info(f"Gateway: {gw}")
    if not ui.confirm("Probe this gateway (about 10 TCP ports + UPnP query)?"): ui.info("Cancelled."); return
    with ui.spinner("Auditing router..."):
        ports = open_ports(gw); h80 = http_info(gw, 80) if 80 in ports else None
        redirects = bool(h80 and h80.get("location", "") and str(h80["location"]).startswith("https"))
        up = upnp_enabled(gw); link, _ = signal_analyzer.current_link(); sec = None
        if link:
            nets, _, _e = wifi_scanner.scan(config.get("backend"))
            sec = next((n["security"] for n in nets if n["bssid"] == (link.get("bssid") or "").lower()), None)
    ui.table("Open management ports", ["Port", "Service"], [[p, PORTS[p]] for p in ports] or [["-", "none found"]])
    findings = build_findings(ports, h80, redirects, up, sec)
    config.SESSION["router"] = {"gateway": gw, "open_ports": ports, "wifi_security": sec, "findings": findings}
    ui.table("Findings", ["Severity", "Issue", "Recommendation"], [[ui.sev(x["severity"]), x["issue"], x["recommendation"]] for x in findings])
