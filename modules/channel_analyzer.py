"""MODULE 05 - Channel information and congestion, computed from real scan results."""
from collections import Counter

def congestion_24(networks):
    """Weight each 2.4 GHz network onto the channels it overlaps (channels within +-4 interfere)."""
    load = {c: 0.0 for c in range(1, 14)}
    for n in networks:
        ch = n.get("channel")
        if n.get("band") != "2.4 GHz" or not ch: continue
        w = 1 + max(0, (n.get("signal_pct") or 0)) / 100          # stronger neighbours hurt more
        for c in load:
            d = abs(c - ch)
            if d <= 4: load[c] += w * (1 - d / 5)
    return load

def recommend_24(load):
    best = min((1, 6, 11), key=lambda c: load[c]); return best

def summarize(networks):
    per = Counter((n["band"], n["channel"]) for n in networks if n.get("channel"))
    load = congestion_24(networks)
    return {"per_channel": {f"{b}|{c}": v for (b, c), v in sorted(per.items(), key=lambda x: (x[0][0], x[0][1]))},
            "load_24": load, "recommended_24": recommend_24(load)}

def run():
    from core import config, terminal_ui as ui
    from modules import wifi_scanner
    ui.header("05 · CHANNEL INFORMATION")
    with ui.spinner("Scanning..."): nets, _, e = wifi_scanner.scan(config.get("backend"))
    if e: ui.err(e); return
    if not nets: ui.warn("No networks were reported."); return
    s = summarize(nets); config.SESSION["channels"] = s
    rows = [[b, c, v, "█" * min(30, v)] for (b, c), v in sorted(((tuple(k.split("|")), v) for k, v in s["per_channel"].items()), key=lambda x: (x[0][0], int(x[0][1])))]
    ui.table("Networks per channel", ["Band", "Channel", "Networks", "Usage"], rows)
    if any(n["band"] == "2.4 GHz" for n in nets):
        ui.table("2.4 GHz interference score (lower is better)", ["Channel", "Score"], [[c, f"{s['load_24'][c]:.1f}"] for c in (1, 6, 11)])
        ui.ok(f"Least congested non-overlapping 2.4 GHz channel here: {s['recommended_24']}")
    ui.info("Prefer 5 GHz where range allows; it has more non-overlapping channels.")
