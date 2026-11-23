"""MODULE 04 - Signal analyzer: live signal of the connected network, with stability statistics."""
import json, re, statistics, time
from core import config, system_check as sc
from modules import wifi_scanner as ws, interface_manager as im

def quality(dbm):
    if dbm is None: return "Unknown"
    return "Excellent" if dbm >= -50 else "Good" if dbm >= -60 else "Fair" if dbm >= -70 else "Weak" if dbm >= -80 else "Very weak"

def parse_iw_link(text):
    if "Not connected" in text or not text.strip(): return None
    g = lambda pat: (re.search(pat, text) or [None, None])[1]
    sig, freq = g(r"signal:\s*(-?\d+)"), g(r"freq:\s*(\d+)")
    return {"ssid": g(r"SSID:\s*(.+)"), "bssid": g(r"Connected to ([0-9a-f:]{17})"), "signal_dbm": int(sig) if sig else None,
            "freq": int(freq) if freq else None, "channel": ws.freq_to_channel(int(freq)) if freq else None, "bitrate": g(r"tx bitrate:\s*([\d.]+ \S+)")}

def current_link():
    """(link dict | None, error | None) using iw, nmcli or Termux:API, whichever exists."""
    if sc.platform_name() == "termux":
        info, e = im.termux_info()
        if not info: return None, e
        f = info.get("frequency_mhz")
        return {"ssid": info.get("ssid"), "bssid": info.get("bssid"), "signal_dbm": info.get("rssi"), "freq": f, "channel": ws.freq_to_channel(f),
                "bitrate": f"{info.get('link_speed_mbps')} Mbps"}, None
    if sc.have("iw"):
        for n in im.list_wireless():
            rc, out, _ = sc.run(["iw", "dev", n, "link"])
            l = parse_iw_link(out) if rc == 0 else None
            if l: return l, None
    if sc.have("nmcli"):
        rc, out, e = sc.run(["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY", "dev", "wifi", "list"])
        for n in ws.parse_nmcli(out) if rc == 0 else []:
            if n["in_use"]: return {"ssid": n["ssid"], "bssid": n["bssid"], "signal_dbm": n["signal_dbm"], "freq": n["freq"], "channel": n["channel"], "bitrate": "-"}, None
    return None, "Not connected to a Wi-Fi network (or no supported tool found)."

def stats(samples):
    v = [s for s in samples if s is not None]
    if not v: return {}
    sd = statistics.pstdev(v) if len(v) > 1 else 0.0
    return {"samples": len(v), "min": min(v), "max": max(v), "avg": round(sum(v) / len(v), 1), "stdev": round(sd, 1),
            "stability": "Stable" if sd < 3 else "Variable" if sd < 7 else "Unstable"}

def spark(vals):
    bars = "▁▂▃▄▅▆▇█"; v = [x for x in vals if x is not None][-40:]
    if not v: return ""
    lo, hi = min(v), max(v)
    return "".join(bars[0 if hi == lo else int((x - lo) / (hi - lo) * 7)] for x in v)

def run():
    from core import terminal_ui as ui
    from rich.panel import Panel
    ui.header("04 · SIGNAL ANALYZER")
    link, e = current_link()
    if not link: ui.err(e); return
    ui.info("Live monitor. Press Ctrl+C to stop.")
    samples, interval = [], max(1, int(config.get("signal_interval")))
    try:
        with ui.Live(refresh_per_second=4, console=ui.console) as live:
            while True:
                link, e = current_link()
                samples.append(link["signal_dbm"] if link else None)
                if link:
                    s = stats(samples)
                    body = (f"[g]{link['ssid']}[/g]  {link['bssid']}\nChannel {link['channel']}  ·  {ws.band(link['freq'])}  ·  rate {link['bitrate']}\n"
                            f"Signal [c]{link['signal_dbm']} dBm[/c] ({quality(link['signal_dbm'])})\n[p]{spark(samples)}[/p]\n"
                            f"min {s.get('min')}  avg {s.get('avg')}  max {s.get('max')}  stdev {s.get('stdev')}  → {s.get('stability')}")
                else: body = f"[r]Disconnected[/r] ({e})"
                live.update(Panel(body, title="Signal", border_style="p"))
                time.sleep(interval)
    except KeyboardInterrupt: pass
    config.SESSION["signal"] = stats(samples)
    ui.info(f"Session summary: {config.SESSION['signal'] or 'no samples'}")
