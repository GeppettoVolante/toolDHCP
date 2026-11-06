"""GUI tests: pure validation + Tk smoke test on loopback (no packets on the network).

The smoke test does NOT send datagrams: it feeds the Responder directly.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
import netif  # noqa: E402
import gui  # noqa: E402
from test_bootp import request, MAC  # noqa: E402

IF = netif.Iface("Eth", "x", "192.0.2.19", 24, "00:00:00:00:00:00")


class TestValidate(unittest.TestCase):
    def v(self, ip, mask="255.255.255.0", gw="", mac=MAC):
        return gui.validate_assignment(IF, mac, ip, mask, gw)

    def test_ok(self):
        e, w, vals = self.v("192.0.2.50")
        self.assertEqual((e, w), ([], []))
        self.assertEqual(vals, (MAC, "192.0.2.50", "255.255.255.0", None))

    def test_bad_ip(self):
        self.assertTrue(self.v("192.0.2.")[0])
        self.assertTrue(self.v("300.1.1.1")[0])

    def test_bad_mask(self):
        self.assertTrue(self.v("192.0.2.50", "255.0.255.0")[0])
        self.assertTrue(self.v("192.0.2.50", "0.0.0.0")[0])

    def test_bad_mac(self):
        self.assertTrue(self.v("192.0.2.50", mac="zz")[0])

    def test_same_as_pc(self):
        self.assertTrue(self.v("192.0.2.19")[0])

    def test_network_broadcast(self):
        self.assertTrue(self.v("192.0.2.0")[0])
        self.assertTrue(self.v("192.0.2.255")[0])

    def test_outside_subnet_warns(self):
        e, w, _ = self.v("10.0.0.5")
        self.assertEqual(e, [])
        self.assertEqual(len(w), 1)

    def test_gateway_outside_warns(self):
        e, w, _ = self.v("192.0.2.50", gw="10.0.0.1")
        self.assertEqual(e, [])
        self.assertTrue(w)


@unittest.skipUnless(sys.platform == "win32", "Tk smoke test on Windows only")
class TestSmoke(unittest.TestCase):
    def test_start_and_tree(self):
        try:
            app = gui.App()
        except Exception as e:  # no display
            self.skipTest(f"Tk not available: {e}")
        app.withdraw()
        try:
            lo = netif.Iface("lo", "loopback", "127.0.0.1", 8, "")
            app.ifaces = [lo]
            app.cmb["values"] = [lo.label()]
            app.cmb.current(0)
            app.start()
            self.assertIsNotNone(app.resp)
            app.resp.handle(request())
            app.v_mac.set(MAC)
            app.refresh_tree()
            self.assertIn(MAC, app.tree.get_children())
            app.resp.arm(MAC, "127.0.0.5", "255.0.0.0")
            app.refresh_tree()
            self.assertEqual(app.tree.set(MAC, "ip"), "127.0.0.5")
            app.update()
            app.change_iface()
            self.assertIsNone(app.resp)
        finally:
            app.stop_server()
            app.destroy()


if __name__ == "__main__":
    unittest.main()
