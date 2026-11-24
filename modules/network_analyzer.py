"""MODULE 03 - Network security analyzer: judges only what a scan can actually show."""
import re
ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "OK", "INFO"]
DEFAULT_SSID = re.compile(r"^(TP-?LINK|NETGEAR|DLINK|D-LINK|LINKSYS|ASUS|HUAWEI|ZTE|JIO|AIRTEL|ACT|BSNL|TENDA|MI_?ROUTER)[-_ ]?[0-9A-F]{3,}", re.I)

RULES = {
    "OPEN": ("HIGH", "No encryption: anyone nearby can read the traffic.", "Enable WPA3 (or WPA2-AES) with a strong passphrase. For guests use a separate isolated network."),
    "WEP": ("CRITICAL", "WEP is broken and offers almost no protection.", "Replace with WPA3 or WPA2-AES immediately; replace hardware that cannot do it."),
    "WPA": ("HIGH", "WPA (v1/TKIP) is outdated and weak.", "Switch to WPA2-AES or WPA3."),
    "WPA/WPA2": ("MEDIUM", "Mixed WPA/WPA2 lets old, weak clients connect.", "Disable WPA1/TKIP and use WPA2-AES or WPA3 only."),
    "WPA2": ("LOW", "WPA2 is acceptable if the passphrase is strong.", "Use a passphrase of 14+ characters and move to WPA3 when all devices support it."),
    "WPA2/WPA3": ("OK", "WPA3 transition mode: modern clients are well protected.", "Move to WPA3-only when every device supports it, to stop downgrades."),
    "WPA3": ("OK", "WPA3 is the strongest personal-network mode.", "Keep firmware updated."),
    "WPA2-Enterprise": ("OK", "Enterprise (802.1X) authentication.", "Make sure clients validate the RADIUS server certificate."),
    "WPA3-Enterprise": ("OK", "Enterprise (802.1X) authentication with WPA3.", "Keep RADIUS and firmware updated."),
    "OWE": ("LOW", "Enhanced Open encrypts traffic but does not authenticate users.", "Fine for guest Wi-Fi; use WPA3 for private networks."),
    "UNKNOWN": ("INFO", "Security type is not reported on this platform.", "Scan with nmcli or iw on Linux for full details."),
}

def analyze_network(n):
    sev, issue, rec = RULES.get(n["security"], RULES["UNKNOWN"])
    notes = []
    if n.get("tkip") and n["security"] not in ("OPEN", "WEP"):
        sev = sev if ORDER.index(sev) <= ORDER.index("MEDIUM") else "MEDIUM"
        notes.append("TKIP cipher advertised: disable it and use AES (CCMP).")
    if n.get("hidden"): notes.append("Hidden SSID is not a security control; it is still discoverable.")
    if n.get("ssid") and DEFAULT_SSID.match(n["ssid"]): notes.append("SSID looks like a factory default: change it and the admin password.")
    return {"ssid": n["ssid"] or "<hidden>", "bssid": n["bssid"], "security": n["security"], "severity": sev, "issue": issue,
            "recommendation": rec, "notes": notes}

def assess(networks):
    results = sorted((analyze_network(n) for n in networks), key=lambda r: ORDER.index(r["severity"]))
    counts = {s: sum(1 for r in results if r["severity"] == s) for s in ORDER}
    worst = next((s for s in ORDER if counts[s]), "INFO")
    return {"results": results, "counts": counts, "overall": worst}

def run():
    from core import config, terminal_ui as ui
    from modules import wifi_scanner
    ui.header("03 · NETWORK SECURITY ANALYZER")
    nets = config.SESSION.get("scan", {}).get("networks")
    if not nets or ui.confirm("Run a fresh scan first?"):
        with ui.spinner("Scanning..."): nets, _, e = wifi_scanner.scan(config.get("backend"))
        if e: ui.err(e); return
        if not nets: ui.warn("No networks were reported."); return
        config.SESSION["scan"] = {"networks": nets}
    a = assess(nets); config.SESSION["analysis"] = a
    ui.table("Findings", ["SSID", "Security", "Severity", "Issue"], [[r["ssid"], r["security"], ui.sev(r["severity"]), r["issue"]] for r in a["results"]])
    ui.info("Counts: " + ", ".join(f"{k}={v}" for k, v in a["counts"].items() if v))
    for r in a["results"]:
        if r["severity"] in ("CRITICAL", "HIGH", "MEDIUM") or r["notes"]:
            ui.console.print(f"\n[c]{r['ssid']}[/c] ({r['bssid']})")
            ui.console.print(f"  Fix: {r['recommendation']}")
            for n in r["notes"]: ui.console.print(f"  Note: {n}")
    ui.info(f"Overall worst finding in range: {a['overall']}. Only networks you own are yours to fix; others are shown for awareness.")
