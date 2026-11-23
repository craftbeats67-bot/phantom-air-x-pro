"""MODULE 09 - Live interface statistics (traffic rates, errors, drops, link state)."""
import os, time

def counters():
    """{iface: (rx_bytes, tx_bytes, rx_err, tx_err, rx_drop, tx_drop)} from psutil or /proc/net/dev."""
    try:
        import psutil
        return {k: (v.bytes_recv, v.bytes_sent, v.errin, v.errout, v.dropin, v.dropout) for k, v in psutil.net_io_counters(pernic=True).items()}
    except Exception: pass
    out = {}
    try:
        for line in open("/proc/net/dev").read().splitlines()[2:]:
            name, rest = line.split(":", 1); f = rest.split()
            out[name.strip()] = (int(f[0]), int(f[8]), int(f[2]), int(f[10]), int(f[3]), int(f[11]))
    except (OSError, IndexError, ValueError): pass
    return out

def state(iface):
    try: return open(f"/sys/class/net/{iface}/operstate").read().strip()
    except OSError: return "n/a"

def human(n):
    for u in ("B/s", "KB/s", "MB/s", "GB/s"):
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB/s"

def rates(prev, cur, dt):
    return {k: ((cur[k][0] - prev[k][0]) / dt, (cur[k][1] - prev[k][1]) / dt) for k in cur if k in prev and dt > 0}

def run():
    from core import terminal_ui as ui
    from rich.table import Table
    ui.header("09 · NETWORK MONITORING")
    prev = counters()
    if not prev: ui.err("Interface statistics are not readable on this system (Android may restrict /proc/net)."); return
    ui.info("Live view. Press Ctrl+C to stop."); t0 = time.time()
    try:
        with ui.Live(refresh_per_second=2, console=ui.console) as live:
            while True:
                time.sleep(1); cur = counters(); t1 = time.time(); r = rates(prev, cur, t1 - t0); prev, t0 = cur, t1
                t = Table(title="Interfaces", header_style="g", border_style="p")
                for c in ("Interface", "State", "Down", "Up", "RX err", "TX err", "RX drop", "TX drop"): t.add_column(c)
                for k, v in sorted(cur.items()):
                    d, u = r.get(k, (0, 0)); t.add_row(k, state(k), human(d), human(u), str(v[2]), str(v[3]), str(v[4]), str(v[5]))
                live.update(t)
    except KeyboardInterrupt: pass
