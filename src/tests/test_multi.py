"""Tests: multiple armed MACs, passive 'seen' list, netif, oui. No real network.

Run: python -m unittest discover -s tests   (from src/)
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
import bootp  # noqa: E402
import netif  # noqa: E402
import oui  # noqa: E402
import server  # noqa: E402
from test_bootp import request, MAC, OTHER, SRV, MASK, GW  # noqa: E402


class TestMulti(unittest.TestCase):
    def setUp(self):
        self.r = server.Responder(SRV)

    def test_passive_records_seen(self):
        data, _, _ = self.r.handle(request())
        self.assertIsNone(data)
        seen, armed = self.r.snapshot()
        self.assertEqual([s.mac for s in seen], [MAC])
        self.assertEqual(seen[0].kind, "BOOTP")
        self.assertEqual(seen[0].count, 1)
        self.assertEqual(armed, {})

    def test_seen_counts_repeats(self):
        for _ in range(3):
            self.r.handle(request())
        self.assertEqual(self.r.snapshot()[0][0].count, 3)

    def test_arm_after_seen_then_reply(self):
        self.r.handle(request())
        self.r.arm(MAC, "192.0.2.10", MASK, GW)
        data, _, _ = self.r.handle(request())
        self.assertEqual(bootp.parse(data).yiaddr, "192.0.2.10")
        self.assertEqual(self.r.snapshot()[0][0].status, "BOOTP replied")

    def test_two_devices_different_ips(self):
        self.r.arm(MAC, "192.0.2.10", MASK)
        self.r.arm(OTHER, "192.0.2.11", MASK)
        a, _, _ = self.r.handle(request(mac=MAC))
        b, _, _ = self.r.handle(request(mac=OTHER))
        self.assertEqual(bootp.parse(a).yiaddr, "192.0.2.10")
        self.assertEqual(bootp.parse(b).yiaddr, "192.0.2.11")

    def test_disarm_stops_replies(self):
        self.r.arm(MAC, "192.0.2.10", MASK)
        self.r.disarm(MAC)
        data, _, _ = self.r.handle(request())
        self.assertIsNone(data)

    def test_arm_normalizes_mac(self):
        self.r.arm("00-00-5e-00-53-10", "192.0.2.10", MASK)
        self.assertIn(MAC, self.r.armed)

    def test_status_ack_and_nak(self):
        self.r.arm(MAC, "192.0.2.10", MASK)
        self.r.handle(request(msg_type=bootp.DHCPREQUEST,
                              extra={bootp.OPT_REQUESTED_IP: bytes((192, 0, 2, 99))}))
        self.assertEqual(self.r.snapshot()[0][0].status, "NAK")
        self.r.handle(request(msg_type=bootp.DHCPREQUEST,
                              extra={bootp.OPT_REQUESTED_IP: bytes((192, 0, 2, 10))}))
        self.assertEqual(self.r.snapshot()[0][0].status, "ACK")


class TestNetifOui(unittest.TestCase):
    def test_iface_math(self):
        i = netif.Iface("Eth", "x", "192.0.2.19", 24, "00:00:00:00:00:00")
        self.assertEqual(i.mask, "255.255.255.0")
        self.assertIn(__import__("ipaddress").ip_address("192.0.2.50"), i.network)

    def test_usable_filters(self):
        L = [netif.Iface("a", "", "10.0.0.1", 24, ""),
             netif.Iface("b", "", "100.1.1.1", 32, ""),
             netif.Iface("c", "", "10.0.1.1", 24, "", up=False),
             netif.Iface("d", "", "0.0.0.0", 0, "")]
        self.assertEqual([i.name for i in netif.usable(L)], ["a"])

    @unittest.skipUnless(sys.platform == "win32", "solo Windows")
    def test_list_windows_runs(self):
        for i in netif.list_interfaces():
            self.assertRegex(i.ip, r"^\d+\.\d+\.\d+\.\d+$")
            self.assertTrue(0 <= i.prefix <= 32)

    def test_oui(self):
        self.assertEqual(oui.vendor("00:15:7b:aa:bb:cc"), "Leuze electronic GmbH + Co. KG")
        self.assertEqual(oui.vendor("00-00-bc-01-02-03"), "Rockwell Automation")
        self.assertEqual(oui.vendor("02:00:00:00:00:01"), "")


if __name__ == "__main__":
    unittest.main()
