import json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules import wifi_scanner as ws, signal_analyzer as sa, interface_manager as im, device_inventory as di

NMCLI = """ :HomeNet:AA\\:BB\\:CC\\:DD\\:EE\\:01:6:2437 MHz:80:WPA2
*:Office 5G:AA\\:BB\\:CC\\:DD\\:EE\\:02:36:5180 MHz:62:WPA2 WPA3
 :CafeFree:AA\\:BB\\:CC\\:DD\\:EE\\:03:11:2462 MHz:40:--
 ::AA\\:BB\\:CC\\:DD\\:EE\\:04:1:2412 MHz:30:WPA1 WPA2
"""
IW = """BSS aa:bb:cc:dd:ee:10(on wlan0)
\tfreq: 2412.0
\tsignal: -45.00 dBm
\tSSID: Lab-WPA3
\tcapability: ESS Privacy ShortSlotTime (0x0411)
\tRSN:\t * Version: 1
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: SAE
BSS aa:bb:cc:dd:ee:11(on wlan0)
\tfreq: 5180
\tsignal: -70.00 dBm
\tSSID: OldWEP
\tcapability: ESS Privacy (0x0011)
BSS aa:bb:cc:dd:ee:12(on wlan0)
\tfreq: 2437
\tsignal: -60.00 dBm
\tSSID: Guest
\tcapability: ESS (0x0401)
BSS aa:bb:cc:dd:ee:13(on wlan0)
\tfreq: 2462
\tsignal: -55.00 dBm
\tSSID: Mixed
\tcapability: ESS Privacy (0x0411)
\tWPA:\t * Version: 1
\t\t * Pairwise ciphers: TKIP
\t\t * Authentication suites: PSK
\tRSN:\t * Version: 1
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: PSK
"""

class Scanner(unittest.TestCase):
    def test_channel_mapping(self):
        self.assertEqual([ws.freq_to_channel(f) for f in (2412, 2437, 2484, 5180, 5955)], [1, 6, 14, 36, 1])
        self.assertEqual(ws.band(5180), "5 GHz")

    def test_nmcli(self):
        n = ws.parse_nmcli(NMCLI)
        self.assertEqual(len(n), 4)
        self.assertEqual(n[0]["bssid"], "aa:bb:cc:dd:ee:01"); self.assertEqual(n[0]["security"], "WPA2")
        self.assertEqual(n[1]["security"], "WPA2/WPA3"); self.assertTrue(n[1]["in_use"]); self.assertEqual(n[1]["channel"], 36)
        self.assertEqual(n[2]["security"], "OPEN"); self.assertTrue(n[3]["hidden"]); self.assertEqual(n[3]["security"], "WPA/WPA2")

    def test_iw(self):
        n = {x["ssid"]: x for x in ws.parse_iw(IW)}
        self.assertEqual(n["Lab-WPA3"]["security"], "WPA3"); self.assertEqual(n["OldWEP"]["security"], "WEP")
        self.assertEqual(n["Guest"]["security"], "OPEN"); self.assertEqual(n["Mixed"]["security"], "WPA/WPA2")
        self.assertTrue(n["Mixed"]["tkip"]); self.assertEqual(n["Lab-WPA3"]["channel"], 1); self.assertEqual(n["Lab-WPA3"]["signal_dbm"], -45.0)

    def test_termux(self):
        data = json.dumps([{"ssid": "A", "bssid": "AA:BB:CC:DD:EE:20", "frequency_mhz": 2412, "rssi": -50, "capabilities": "[WPA2-PSK-CCMP][RSN-PSK-CCMP][ESS]"},
                           {"ssid": "B", "bssid": "AA:BB:CC:DD:EE:21", "frequency_mhz": 5180, "rssi": -60, "capabilities": "[ESS]"},
                           {"ssid": "C", "bssid": "AA:BB:CC:DD:EE:22", "frequency_mhz": 2437, "rssi": -65}])
        n = ws.parse_termux(data)
        self.assertEqual([x["security"] for x in n], ["WPA2", "OPEN", "UNKNOWN"])
        with self.assertRaises(ValueError): ws.parse_termux(json.dumps({"API_ERROR": "no permission"}))

    def test_export(self):
        import tempfile
        from core import config
        config.REPORTS = tempfile.mkdtemp()
        p = ws.export(ws.parse_nmcli(NMCLI), "json"); self.assertEqual(len(json.load(open(p))), 4)
        p = ws.export(ws.parse_nmcli(NMCLI), "csv"); self.assertIn("ssid", open(p).readline())

class Signal(unittest.TestCase):
    def test_quality_and_stats(self):
        self.assertEqual(sa.quality(-45), "Excellent"); self.assertEqual(sa.quality(-85), "Very weak")
        self.assertEqual(sa.stats([-50, -50, -51, None])["stability"], "Stable")
        self.assertEqual(sa.stats([-40, -80, -45, -75])["stability"], "Unstable"); self.assertEqual(sa.stats([None]), {})

    def test_iw_link(self):
        t = "Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n\tSSID: Home\n\tfreq: 5180\n\tsignal: -52 dBm\n\ttx bitrate: 866.7 MBit/s\n"
        l = sa.parse_iw_link(t); self.assertEqual((l["ssid"], l["signal_dbm"], l["channel"]), ("Home", -52, 36))
        self.assertIsNone(sa.parse_iw_link("Not connected."))

class Inventory(unittest.TestCase):
    def test_cidr_rules(self):
        self.assertIsNotNone(di.check_cidr("192.168.1.0/24")[0])
        for bad in ("8.8.8.0/24", "10.0.0.0/8", "abc"): self.assertIsNone(di.check_cidr(bad)[0])

    def test_arp_and_vendor(self):
        a = di.parse_arp("IP address HW type Flags HW address Mask Device\n192.168.1.1 0x1 0x2 b8:27:eb:11:22:33 * wlan0\n192.168.1.9 0x1 0x0 00:00:00:00:00:00 * wlan0\n")
        self.assertEqual(a, {"192.168.1.1": "b8:27:eb:11:22:33"})
        self.assertEqual(di.parse_arp("192.168.1.5 dev wlan0 lladdr aa:bb:cc:00:11:22 REACHABLE")["192.168.1.5"], "aa:bb:cc:00:11:22")
        self.assertEqual(di.vendor("b8:27:eb:11:22:33"), "Raspberry Pi"); self.assertEqual(di.vendor("da:a1:19:00:00:01"), "Randomized/private MAC")

class Iface(unittest.TestCase):
    def test_phy(self):
        t = ("\tSupported interface modes:\n\t\t * IBSS\n\t\t * managed\n\t\t * AP\n\t\t * monitor\n\tBand 1:\n\t\tHT Capabilities: 0x19ef\n\t\tFrequencies:\n"
             "\t\t\t* 2412 MHz [1] (20.0 dBm)\n\tBand 2:\n\t\tVHT Capabilities (0x338):\n\t\tFrequencies:\n\t\t\t* 5180 MHz [36] (23.0 dBm)\n")
        d = im.parse_phy(t); self.assertEqual(d["bands"], ["2.4 GHz", "5 GHz"]); self.assertIn("monitor", d["modes"])
        self.assertEqual(d["standards"], ["802.11n (HT)", "802.11ac (VHT)"])

if __name__ == "__main__": unittest.main()
