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
            app.set_ifaces([lo])
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

    def test_auto_permanent_flow(self):
        import time
        import cip
        calls = []

        def fake(cur, ip, mask, gw, **kw):
            calls.append((cur, ip, kw.get("expect_mac")))
            return cip.Result(ok=True, verified=True, messages=["fake"])

        real, cip.make_static = cip.make_static, fake
        try:
            app = gui.App()
        except Exception as e:
            cip.make_static = real
            self.skipTest(f"Tk not available: {e}")
        app.withdraw()
        try:
            app.set_ifaces([netif.Iface("lo", "loopback", "127.0.0.1", 8, "")])
            app.start()
            app.v_mac.set(MAC)
            app.v_ip.set("127.0.0.5")
            app.v_mask.set("255.0.0.0")
            app.v_perm.set(True)
            app.arm()
            self.assertEqual(app.perm[MAC]["state"], "pending")
            app.check_permanent()                      # not seen yet: nothing happens
            self.assertEqual(calls, [])
            app.resp.handle(request())                 # BOOTP reply generated -> status 'BOOTP replied'
            app.check_permanent()                      # too early (< 2 s after the reply)
            self.assertEqual(calls, [])
            app.resp.seen[MAC].last -= 5
            app.perm[MAC]["armed_at"] -= 20
            app.check_permanent()
            self.assertEqual(app.perm[MAC]["state"], "running")
            for _ in range(50):
                try:
                    app.on_event(app.evq.get(timeout=0.1))
                    break
                except Exception:
                    pass
            self.assertEqual(calls, [("127.0.0.5", "127.0.0.5", MAC)])
            self.assertEqual(app.perm[MAC]["state"], "ok")
            app.refresh_tree()
            self.assertIn("STATIC", app.tree.set(MAC, "static"))
        finally:
            cip.make_static = real
            app.stop_server()
            app.destroy()

    def test_sweep_flow_updates_devices(self):
        import cip
        import subnetscan
        ident = cip.Identity("10.20.30.40", 1, 12, 9, "3.001", 77, "Dev", "", via="10.20.30.250")
        real = subnetscan.sweep
        subnetscan.sweep = lambda iface, nets, **kw: (kw["progress"](1, 1, 1), [ident])[1]
        try:
            app = gui.App()
        except Exception as e:
            subnetscan.sweep = real
            self.skipTest(f"Tk not available: {e}")
        app.withdraw()
        try:
            app.set_ifaces([netif.Iface("lo", "loopback", "127.0.0.1", 8, "")])
            app.start()
            nets, _ = subnetscan.parse_nets("10.20.30.0/24")
            app.start_sweep(nets)
            for _ in range(50):
                try:
                    ev = app.evq.get(timeout=0.1)
                except Exception:
                    continue
                app.on_event(ev)
                if ev[0] == "sweep_done":
                    break
            self.assertIn("10.20.30.40", app.found)
            self.assertEqual(app.dtree.set("10.20.30.40", "reach"), "alias 10.20.30.250")
            self.assertFalse(app.sweeping)
        finally:
            subnetscan.sweep = real
            app.stop_server()
            app.destroy()

    def test_manual_mac_pasted_without_separators(self):
        try:
            app = gui.App()
        except Exception as e:
            self.skipTest(f"Tk not available: {e}")
        app.withdraw()
        try:
            app.set_ifaces([netif.Iface("lo", "loopback", "127.0.0.1", 8, "")])
            app.start()
            app.v_mac.set("00157baabbcc")
            app.v_ip.set("127.0.0.9")
            app.v_mask.set("255.0.0.0")
            app.v_perm.set(False)
            app.arm()
            self.assertIn("00:15:7B:AA:BB:CC", app.resp.armed)
            self.assertEqual(app.v_mac.get(), "00:15:7B:AA:BB:CC")
            app.refresh_tree()
            self.assertEqual(app.tree.set("00:15:7B:AA:BB:CC", "stato"), "waiting")
        finally:
            app.stop_server()
            app.destroy()


if __name__ == "__main__":
    unittest.main()
