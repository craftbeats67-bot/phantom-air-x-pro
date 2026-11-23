"""MODULE 01 - Wireless interface manager: detection, status and capabilities (read-only)."""
import json, os, re
from core import system_check as sc

SYS = "/sys/class/net"

def _read(path):
    try: return open(path).read().strip()
    except OSError: return None

def list_wireless():
    names = []
    try:
        for n in sorted(os.listdir(SYS)):
            if os.path.isdir(f"{SYS}/{n}/wireless") or os.path.isdir(f"{SYS}/{n}/phy80211"): names.append(n)
    except OSError: pass
    if not names and sc.have("iw"):
        names = re.findall(r"Interface (\S+)", sc.run(["iw", "dev"])[1])
    return names

def parse_phy(text):
    """Parse `iw phy <phy> info`: supported modes, bands and standards that are actually reported."""
    modes = re.findall(r"^\s+\* (\w[\w\-/ ]*)$", text.split("Supported interface modes:")[1].split("Band")[0], re.M) if "Supported interface modes:" in text else []
    freqs = [int(f) for f in re.findall(r"\* (\d{4}) MHz \[\d+\]", text) if "disabled" not in text.split(f"* {f} MHz")[1].split("\n")[0]]
    bands = sorted({"2.4 GHz" if f < 3000 else "5 GHz" if f < 5925 else "6 GHz" for f in freqs})
    std = ["802.11n (HT)"] if "HT Capabilities" in text else []
    if "VHT Capabilities" in text: std.append("802.11ac (VHT)")
    if "HE Iftypes" in text or "HE MAC Capabilities" in text: std.append("802.11ax (HE)")
    return {"modes": [m.strip() for m in modes], "bands": bands, "standards": std}

def chipset(iface):
    drv = os.path.basename(os.path.realpath(f"{SYS}/{iface}/device/driver")) if os.path.exists(f"{SYS}/{iface}/device/driver") else None
    ven, dev = _read(f"{SYS}/{iface}/device/vendor"), _read(f"{SYS}/{iface}/device/device")
    name = None
    if ven and dev and sc.have("lspci"):
        slot = os.path.basename(os.path.realpath(f"{SYS}/{iface}/device"))
        out = sc.run(["lspci", "-s", slot])[1].strip()
        name = out.split(": ", 1)[-1] if out else None
    if not name:
        vid, pid = (_read(f"{SYS}/{iface}/device/../{x}") for x in ("idVendor", "idProduct"))
        if vid and pid and sc.have("lsusb"):
            out = sc.run(["lsusb", "-d", f"{vid}:{pid}"])[1].strip()
            name = out.split("ID ", 1)[-1] if out else None
    return {"driver": drv, "chipset": name or (f"{ven}:{dev}" if ven and dev else None)}

def details(iface):
    d = {"name": iface, "state": _read(f"{SYS}/{iface}/operstate") or "unknown", "mac": _read(f"{SYS}/{iface}/address"), **chipset(iface)}
    phy = _read(f"{SYS}/{iface}/phy80211/name")
    if phy and sc.have("iw"):
        rc, out, _ = sc.run(["iw", "phy", phy, "info"])
        if rc == 0: d.update(parse_phy(out))
    return d

def termux_info():
    rc, out, err = sc.run(["termux-wifi-connectioninfo"])
    if rc != 0: return None, err or "termux-wifi-connectioninfo failed (install Termux:API app + `pkg install termux-api`)"
    try: return json.loads(out), None
    except ValueError: return None, "Unexpected output from termux-wifi-connectioninfo"

def run():
    from core import terminal_ui as ui
    ui.header("01 · WIRELESS INTERFACE MANAGER")
    ifaces = list_wireless()
    if ifaces:
        rows = []
        for n in ifaces:
            d = details(n)
            rows.append([n, d["state"], d["mac"] or "-", d["driver"] or "-", d["chipset"] or "-", ", ".join(d.get("bands", [])) or "n/a",
                         ", ".join(d.get("standards", [])) or "n/a"])
        ui.table("Wireless interfaces", ["Interface", "State", "MAC", "Driver", "Chipset", "Bands", "Standards"], rows)
        for n in ifaces:
            m = details(n).get("modes")
            if m: ui.info(f"{n} supported modes (as reported by the driver): {', '.join(m)}")
        if not sc.have("iw"): ui.warn("`iw` is not installed, so bands/standards/modes cannot be read.")
        return
    if sc.platform_name() == "termux":
        info, e = termux_info()
        if info:
            ui.table("Android Wi-Fi connection", ["Field", "Value"], [[k, v] for k, v in info.items() if k in ("ssid", "bssid", "rssi", "frequency_mhz", "link_speed_mbps", "ip")])
        else: ui.warn(e)
        ui.info("Android does not expose raw interface details to Termux without root.")
    else:
        ui.err("No wireless interface found. Plug in a Wi-Fi adapter (or pass it through to the VM) and try again.")
