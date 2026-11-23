import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import config
from modules import report_generator as rg, network_analyzer as na

class Reports(unittest.TestCase):
    def setUp(self):
        config.REPORTS = tempfile.mkdtemp(); config.SESSION.clear()
        config.SESSION["scan"] = {"networks": [{"ssid": "Guest", "bssid": "aa:bb:cc:dd:ee:01", "security": "OPEN", "channel": 6, "band": "2.4 GHz", "hidden": False, "tkip": False}]}
        config.SESSION["router"] = {"gateway": "192.168.1.1", "findings": [{"severity": "CRITICAL", "issue": "Telnet open", "recommendation": "Disable Telnet"}]}
        config.SESSION["password_check"] = {"rating": "Weak", "score": 30}

    def test_collect(self):
        r = rg.collect(); self.assertEqual(r["risk_assessment"]["overall"], "CRITICAL")
        self.assertTrue(any("Disable Telnet" in x for x in r["recommendations"])); self.assertNotIn("password", json.dumps(r).replace("password_check", ""))

    def test_files(self):
        paths = rg.write(); self.assertEqual(len(paths), 2)
        txt = open([p for p in paths if p.endswith(".txt")][0]).read()
        self.assertIn("PHANTOM AIR X PRO", txt); self.assertIn("OVERALL RISK: CRITICAL", txt); self.assertIn("@mahisec_13", txt)
        self.assertEqual(json.load(open([p for p in paths if p.endswith(".json")][0]))["router_audit"]["gateway"], "192.168.1.1")

    def test_empty_session(self):
        config.SESSION.clear(); r = rg.collect(); self.assertEqual(r["risk_assessment"]["overall"], "INFO"); self.assertIn("No urgent actions", rg.to_text(r))

if __name__ == "__main__": unittest.main()
