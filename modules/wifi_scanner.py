"""MODULE 02 - Wi-Fi scanner. Uses the system's normal scan (like a phone's Wi-Fi list): no monitor mode, no injection."""
import csv, json, os, re, time
from core import config, system_check as sc

def freq_to_channel(f):
    if f is None: return None
    if f == 2484: return 14
    if 2412 <= f <= 2472: return (f - 2407) // 5
    if 5000 <= f < 5925: return (f - 5000) // 5
    if 5955 <= f <= 7115: return (f - 5950) // 5
    return None

def band(f):
    return "?" if f is None else "2.4 GHz" if f < 3000 else "5 GHz" if f < 5925 else "6 GHz"

def classify(tokens, privacy=None, tkip=False):
    """Normalize security descriptions from any backend into one label."""
    t = " ".join(tokens).upper()
    if not t.strip() or t.strip() == "--":
        return ("OPEN" if privacy in (None, False) else "WEP"), tkip
    if "OWE" in t: return "OWE", tkip
    ent = "802.1X" in t or "EAP" in t
    w3, w2 = "WPA3" in t or "SAE" in t, "WPA2" in t or "RSN" in t
    w1 = bool(re.search(r"WPA1|\bWPA\b|WPA-", t))
    if ent: return "WPA2-Enterprise" if not w3 else "WPA3-Enterprise", tkip
    if w3 and (w2 or "PSK" in t): return "WPA2/WPA3", tkip
    if w3: return "WPA3", tkip
    if w2 and w1: return "WPA/WPA2", tkip
    if w2: return "WPA2", tkip
    if w1: return "WPA", tkip
    if "WEP" in t: return "WEP", tkip
    return "UNKNOWN", tkip

def _net(ssid, bssid, freq, signal_dbm, security, tkip=False, channel=None, signal_pct=None, in_use=False):
    ch = channel or freq_to_channel(freq)
    return {"ssid": ssid or "", "hidden": not ssid, "bssid": (bssid or "").lower(), "freq": freq, "channel": ch, "band": band(freq),
            "signal_dbm": signal_dbm, "signal_pct": signal_pct, "security": security, "tkip": tkip, "in_use": in_use}

def dbm_pct(dbm): return max(0, min(100, int(2 * (dbm + 100))))
def pct_dbm(pct): return int(pct / 2 - 100)

def parse_nmcli(text):
    nets = []
    for line in text.splitlines():
        parts = [p.replace("\\:", ":").replace("\\\\", "\\") for p in re.split(r"(?<!\\):", line)]
        if len(parts) < 7: continue
        use, ssid, bssid, chan, freq, sig, sec = parts[:7]
        try: f = int(re.sub(r"\D", "", freq)) if freq else None; pct = int(sig)
        except ValueError: continue
        label, tk = classify(sec.split(), privacy=False)
        nets.append(_net(ssid, bssid, f, pct_dbm(pct), label, tk, int(chan) if chan.isdigit() else None, pct, use.strip() == "*"))
    return nets

def parse_iw(text):
    nets, cur = [], None
    for raw in text.splitlines():
        m = re.match(r"^BSS ([0-9a-fA-F:]{17})", raw)
        if m:
            cur = {"bssid": m.group(1), "ssid": "", "freq": None, "sig": None, "ch": None, "rsn": False, "wpa": False, "akm": [], "priv": False, "tkip": False}
            nets.append(cur); continue
        if cur is None: continue
        s = raw.strip()
        if s.startswith("freq:"): cur["freq"] = int(float(s.split()[1]))
        elif s.startswith("signal:"): cur["sig"] = float(s.split()[1])
        elif s.startswith("SSID:"): cur["ssid"] = s[5:].strip()
        elif s.startswith("DS Parameter set: channel"): cur["ch"] = int(s.split()[-1])
        elif s.startswith("capability:") and "Privacy" in s: cur["priv"] = True
        elif s.startswith("RSN:"): cur["rsn"] = True
        elif s.startswith("WPA:"): cur["wpa"] = True
        elif "Authentication suites:" in s: cur["akm"] += s.split(":", 1)[1].split()
        elif "Pairwise ciphers:" in s and "TKIP" in s: cur["tkip"] = True
    out = []
    for c in nets:
        toks = list(c["akm"])
        if c["rsn"] and (not toks or "PSK" in toks): toks += ["WPA2"] + ([] if toks else ["PSK"])
        if c["wpa"]: toks.append("WPA")
        if not toks and c["priv"]: toks = ["WEP"]
        label, tk = classify(toks, privacy=c["priv"], tkip=c["tkip"])
        out.append(_net(c["ssid"], c["bssid"], c["freq"], c["sig"], label, tk, c["ch"], dbm_pct(c["sig"]) if c["sig"] is not None else None))
    return out

def parse_termux(text):
    data = json.loads(text)
    if isinstance(data, dict): raise ValueError(data.get("API_ERROR") or data.get("error") or "Termux:API returned an error")
    nets = []
    for e in data:
        caps = e.get("capabilities")
        if caps is None: label, tk = "UNKNOWN", False
        elif not re.search("WPA|RSN|WEP|SAE|OWE|EAP|PSK", caps.upper()): label, tk = "OPEN", False
        else: label, tk = classify(re.findall(r"\[([^\]]+)\]", caps), privacy=False)
        rssi = e.get("rssi")
        nets.append(_net(e.get("ssid"), e.get("bssid"), e.get("frequency_mhz"), rssi, label, "TKIP" in (caps or "").upper(),
                         signal_pct=dbm_pct(rssi) if rssi is not None else None))
    return nets

def pick_backend(pref="auto"):
    if pref != "auto": return pref
    if sc.platform_name() == "termux" and sc.have("termux-wifi-scaninfo"): return "termux"
    if sc.have("nmcli"): return "nmcli"
    if sc.have("iw"): return "iw"
    return None

def scan(pref="auto"):
    """Returns (networks, backend, error)."""
    b = pick_backend(pref)
    if b is None: return [], None, "No scan backend found. Install NetworkManager (nmcli), iw (needs root) or Termux:API."
    if b == "termux":
        rc, out, e = sc.run(["termux-wifi-scaninfo"], 30)
        if rc != 0: return [], b, e or "termux-wifi-scaninfo failed. Install the Termux:API app, grant Location permission and turn Location on."
        try:
            nets = parse_termux(out)
            if not nets: return [], b, "Android returned no networks. Turn Wi-Fi ON, give the Termux:API app Location permission, and turn Location ON."
            return nets, b, None
        except ValueError as ex: return [], b, f"{ex} (grant Location permission to Termux:API and enable Location)"
    if b == "nmcli":
        rc, out, e = sc.run(["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "yes"], 40)
        if rc != 0: return [], b, (e.strip() or "nmcli failed") + " (is a Wi-Fi adapter present and NetworkManager running?)"
        return parse_nmcli(out), b, None
    from modules import interface_manager as im
    ifs = im.list_wireless()
    if not ifs: return [], b, "No wireless interface found."
    rc, out, e = sc.run(["iw", "dev", ifs[0], "scan"], 40)
    if rc != 0: return [], b, (e.strip() or "iw scan failed") + (" - run with sudo" if "permitted" in e.lower() or not sc.is_root() else "")
    return parse_iw(out), b, None

def export(nets, fmt="json"):
    os.makedirs(config.REPORTS, exist_ok=True)
    p = os.path.join(config.REPORTS, f"wifi_scan_{time.strftime('%Y%m%d_%H%M%S')}.{fmt}")
    if fmt == "json":
        with open(p, "w") as f: json.dump(nets, f, indent=2)
    else:
        with open(p, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(nets[0].keys())); w.writeheader(); w.writerows(nets)
    return p

def run():
    from core import terminal_ui as ui
    ui.header("02 · WI-FI NETWORK SCANNER")
    ui.info("Standard scan only (like your phone's Wi-Fi list). No monitor mode, no packet injection, no interference.")
    with ui.spinner("Scanning nearby networks..."): nets, backend, e = scan(config.get("backend"))
    if e: ui.err(e); return
    if not nets: ui.warn("Scan worked but no networks were reported."); return
    config.SESSION["scan"] = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "backend": backend, "networks": nets}
    nets = sorted(nets, key=lambda n: -(n["signal_dbm"] if n["signal_dbm"] is not None else -999))
    rows = [[n["ssid"] or "<hidden>", n["bssid"], n["channel"] or "?", n["band"], f"{n['signal_dbm']} dBm" if n["signal_dbm"] is not None else "?",
             ui.Text(n["security"], style="r") if n["security"] in ("OPEN", "WEP") else n["security"]] for n in nets]
    ui.table(f"{len(nets)} networks (backend: {backend})", ["SSID", "BSSID", "Ch", "Band", "Signal", "Security"], rows)
    open_n = sum(1 for n in nets if n["security"] == "OPEN")
    ui.info(f"{open_n} open network(s) found." if open_n else "No open networks found.")
    if any(n["security"] == "UNKNOWN" for n in nets): ui.warn("Some networks report no security details on this platform (shown as UNKNOWN).")
    if ui.confirm("Export results?"):
        fmt = ui.prompt("Format [json/csv]:").lower() or "json"
        ui.ok("Saved: " + export(nets, fmt if fmt in ("json", "csv") else "json"))
