"""MODULE 10 - TXT and JSON security reports built only from data gathered in this session."""
import json, os, time
from core import config
from modules import network_analyzer

def collect():
    s = config.SESSION
    nets = s.get("scan", {}).get("networks")
    analysis = s.get("analysis") or (network_analyzer.assess(nets) if nets else None)
    worst = [analysis["overall"]] if analysis else []
    worst += [f["severity"] for f in s.get("router", {}).get("findings", []) if f["severity"] != "INFO"]
    order = network_analyzer.ORDER
    overall = min(worst, key=order.index) if worst else "INFO"
    recs = []
    if analysis: recs += [f"{r['ssid']}: {r['recommendation']}" for r in analysis["results"] if r["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]
    recs += [f"Router: {f['recommendation']}" for f in s.get("router", {}).get("findings", []) if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]
    return {"tool": "PHANTOM AIR X PRO v1.0", "by": "PHANTOM TEAM / KRRISH / @mahisec_13", "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "risk_assessment": {"overall": overall, "wifi_counts": analysis["counts"] if analysis else None},
            "wifi_scan": s.get("scan"), "wifi_security": analysis["results"] if analysis else None, "channels": s.get("channels"),
            "signal": s.get("signal"), "device_inventory": s.get("inventory"), "router_audit": s.get("router"),
            "password_check": s.get("password_check"), "recommendations": sorted(set(recs))}

def to_text(r):
    L = ["PHANTOM AIR X PRO - SECURITY REPORT", "POWERED BY PHANTOM TEAM · DEVELOPED BY KRRISH · @mahisec_13", f"Generated: {r['generated']}", "",
         f"OVERALL RISK: {r['risk_assessment']['overall']}", ""]
    if r["wifi_security"]:
        L.append("WI-FI SECURITY")
        L += [f"  [{x['severity']}] {x['ssid']} ({x['security']}) - {x['issue']}" for x in r["wifi_security"]]
        L.append("")
    if r["device_inventory"]:
        inv = r["device_inventory"]; L.append(f"DEVICE INVENTORY ({inv['network']}, {len(inv['devices'])} devices)")
        L += [f"  {d['ip']:<16}{d['mac']:<19}{d['vendor']:<28}{d['hostname']}" for d in inv["devices"]]; L.append("")
    if r["router_audit"]:
        L.append(f"ROUTER AUDIT (gateway {r['router_audit']['gateway']})")
        L += [f"  [{f['severity']}] {f['issue']}" for f in r["router_audit"]["findings"]]; L.append("")
    if r["signal"]: L += ["SIGNAL", f"  {r['signal']}", ""]
    if r["password_check"]: L += ["PASSWORD CHECK", f"  Rating: {r['password_check']['rating']} ({r['password_check']['score']}/100)", ""]
    L.append("RECOMMENDATIONS"); L += [f"  - {x}" for x in r["recommendations"]] or ["  - No urgent actions from the data collected."]
    L += ["", "Limits: results reflect only what was observed in this session; no scan can prove a network is fully secure."]
    return "\n".join(L) + "\n"

def write(r=None, fmts=("txt", "json")):
    r = r or collect(); os.makedirs(config.REPORTS, exist_ok=True); stamp = time.strftime("%Y%m%d_%H%M%S"); paths = []
    if "txt" in fmts:
        p = os.path.join(config.REPORTS, f"report_{stamp}.txt")
        with open(p, "w") as f: f.write(to_text(r))
        paths.append(p)
    if "json" in fmts:
        p = os.path.join(config.REPORTS, f"report_{stamp}.json")
        with open(p, "w") as f: json.dump(r, f, indent=2, default=str)
        paths.append(p)
    return paths

def run():
    from core import terminal_ui as ui
    ui.header("10 · SECURITY REPORT GENERATOR")
    r = collect()
    have = [k for k in ("wifi_scan", "wifi_security", "device_inventory", "router_audit", "signal", "password_check") if r.get(k)]
    if not have: ui.warn("No data collected yet this session. Run a scan (02), analysis (03), inventory (06) or router audit (07) first."); return
    ui.info("Included sections: " + ", ".join(have))
    for p in write(r): ui.ok("Saved: " + p)
