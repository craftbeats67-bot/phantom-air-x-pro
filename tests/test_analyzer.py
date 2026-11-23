import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules import network_analyzer as na, channel_analyzer as ca, password_analyzer as pa, router_audit as ra, network_monitor as nm

def net(ssid, sec, ch=6, band="2.4 GHz", pct=70, **k): return {"ssid": ssid, "bssid": "aa:bb:cc:dd:ee:ff", "security": sec, "channel": ch, "band": band, "signal_pct": pct, "hidden": not ssid, "tkip": k.get("tkip", False)}

class Analyzer(unittest.TestCase):
    def test_severity(self):
        want = {"OPEN": "HIGH", "WEP": "CRITICAL", "WPA": "HIGH", "WPA/WPA2": "MEDIUM", "WPA2": "LOW", "WPA2/WPA3": "OK", "WPA3": "OK", "UNKNOWN": "INFO"}
        for sec, sev in want.items(): self.assertEqual(na.analyze_network(net("x", sec))["severity"], sev, sec)

    def test_assess_overall_and_notes(self):
        a = na.assess([net("TP-LINK_A1B2", "WPA2"), net("Guest", "OPEN"), net("", "WPA3")])
        self.assertEqual(a["overall"], "HIGH"); self.assertEqual(a["counts"]["OK"], 1)
        r = {x["ssid"]: x for x in a["results"]}
        self.assertTrue(any("default" in n for n in r["TP-LINK_A1B2"]["notes"])); self.assertTrue(any("Hidden" in n for n in r["<hidden>"]["notes"]))

    def test_channels(self):
        nets = [net("a", "WPA2", 1), net("b", "WPA2", 1), net("c", "WPA2", 6), net("d", "WPA2", 36, "5 GHz")]
        s = ca.summarize(nets); self.assertEqual(s["recommended_24"], 11); self.assertEqual(s["per_channel"]["2.4 GHz|1"], 2)

class Passwords(unittest.TestCase):
    def test_ratings(self):
        self.assertIn(pa.analyze("12345678")["rating"], ("Very weak", "Weak")); self.assertTrue(pa.analyze("password")["issues"])
        self.assertLess(pa.analyze("Summer2020")["score"], 65)
        s = pa.analyze("correct-horse-battery-staple-9!")
        self.assertIn(s["rating"], ("Strong", "Very strong")); self.assertEqual(s["issues"], [])
        self.assertTrue(any("sequence" in i for i in pa.analyze("abcd9Xq!zz")["issues"]))
        self.assertEqual(pa.analyze("")["entropy_bits"], 0.0)

class Router(unittest.TestCase):
    def test_findings(self):
        sev = lambda ports, **k: {f["severity"] for f in ra.build_findings(ports, **k)}
        self.assertIn("CRITICAL", sev([23, 80])); self.assertIn("MEDIUM", sev([80])); self.assertIn("MEDIUM", sev([443], upnp="HTTP/1.1 200"))
        self.assertIn("OK", sev([443], http_redirects_tls=True)); self.assertIn("HIGH", sev([443], wifi_security="WEP"))
        self.assertEqual(ra.build_findings([443])[-1]["severity"], "INFO")      # honest "not checked" note is always present

class Monitor(unittest.TestCase):
    def test_rates_human(self):
        r = nm.rates({"w": (0, 0, 0, 0, 0, 0)}, {"w": (2048, 1024, 0, 0, 0, 0)}, 2.0)
        self.assertEqual(r["w"], (1024.0, 512.0)); self.assertEqual(nm.human(1536), "1.5 KB/s"); self.assertIsInstance(nm.counters(), dict)

if __name__ == "__main__": unittest.main()
