"""Tests for the unknown-subnet search (no network, no admin: aliases are faked)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
import cip  # noqa: E402
import netif  # noqa: E402
import subnetscan as ss  # noqa: E402
from test_cip import SimDevice  # noqa: E402

IF = netif.Iface("Eth", "x", "192.0.2.19", 24, "00:00:00:00:00:00", if_index=7)


class TestParse(unittest.TestCase):
    def test_single_ip_is_its_24(self):
        nets, err = ss.parse_nets("10.20.30.7")
        self.assertEqual([str(n) for n in nets], ["10.20.30.0/24"])
        self.assertEqual(err, [])

    def test_16_expands_to_256(self):
        nets, _ = ss.parse_nets("", presets=["192.168.x.x"])
        self.assertEqual(len(nets), 256)
        self.assertEqual(str(nets[0]), "192.168.0.0/24")

    def test_custom_first_and_dedup(self):
        nets, _ = ss.parse_nets("192.168.5.9, 10.1.0.0/24", presets=["192.168.x.x"])
        self.assertEqual(str(nets[0]), "192.168.5.0/24")
        self.assertEqual(len(nets), 257)

    def test_errors(self):
        _, err = ss.parse_nets("abc, 10.0.0.0/8")
        self.assertEqual(len(err), 2)

    def test_limit(self):
        _, err = ss.parse_nets("", presets=list(ss.PRESETS) * 1 + [])
        self.assertEqual(err, [])
        nets, err = ss.parse_nets("10.0.0.0/16,10.1.0.0/16,10.2.0.0/16,10.3.0.0/16,10.4.0.0/16,"
                                  "10.5.0.0/16,10.6.0.0/16,10.7.0.0/16,10.8.0.0/16")
        self.assertTrue(err)
        self.assertEqual(len(nets), ss.MAX_NETS)


class TestSweep(unittest.TestCase):
    def run_sweep(self, nets, hit_alias=None, admin_error=False):
        added, removed, progress = [], [], []

        def add(idx, ip, mask):
            if admin_error:
                raise OSError("AddIPAddress failed, code 5 (administrator needed)")
            self.assertEqual(idx, 7)
            added.append(ip)

        def scan(jobs, timeout, stop):
            hits = []
            for local, _t in jobs:
                if local == hit_alias:
                    i = cip.Identity("192.168.5.20", 1, 12, 3, "1.001", 9, "Dev")
                    i.via = local
                    hits.append(i)
            return hits, []

        res = ss.sweep(IF, nets, log=lambda m: None, progress=lambda d, t, f: progress.append((d, t, f)),
                       batch=2, add=add, remove=removed.append, wait=lambda idx, ips, t: set(ips),
                       scan=scan)
        return res, added, removed, progress

    def test_keeps_only_alias_with_device(self):
        nets, _ = ss.parse_nets("192.168.4.0/24, 192.168.5.0/24, 192.168.6.0/24")
        res, added, removed, progress = self.run_sweep(nets, "192.168.5.250")
        self.assertEqual([r.ip for r in res], ["192.168.5.20"])
        self.assertEqual(res[0].via, "192.168.5.250")
        self.assertEqual(sorted(added), ["192.168.4.250", "192.168.5.250", "192.168.6.250"])
        self.assertEqual(sorted(removed), ["192.168.4.250", "192.168.6.250"])
        self.assertEqual(progress[-1], (3, 3, 1))

    def test_skips_own_subnet(self):
        nets, _ = ss.parse_nets("192.0.2.0/24, 192.0.3.0/24")
        _, added, _, _ = self.run_sweep(nets)
        self.assertEqual(added, ["192.0.3.250"])

    def test_admin_error_propagates_and_cleans(self):
        nets, _ = ss.parse_nets("192.168.4.0/24")
        with self.assertRaises(OSError):
            self.run_sweep(nets, admin_error=True)

    def test_stop(self):
        nets, _ = ss.parse_nets("192.168.4.0/24, 192.168.5.0/24, 192.168.6.0/24")
        added = []
        n = {"c": 0}

        def stop():
            n["c"] += 1
            return n["c"] > 1          # allow the first batch only

        ss.sweep(IF, nets, log=lambda m: None, stop=stop, batch=1,
                 add=lambda i, ip, m: added.append(ip), remove=lambda ip: None,
                 wait=lambda i, ips, t: set(ips), scan=lambda j, timeout, stop: ([], []))
        self.assertLess(len(added), 3)


class TestMulti(unittest.TestCase):
    def test_list_identity_multi_loopback(self):
        dev = SimDevice()
        self.addCleanup(dev.close)
        found, failed = cip.list_identity_multi([("127.0.0.1", ["127.0.0.1"])], timeout=0.6,
                                                port=dev.udp_port)
        self.assertEqual(failed, [])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].via, "127.0.0.1")

    def test_bind_failure_is_reported(self):
        found, failed = cip.list_identity_multi([("203.0.113.9", ["127.0.0.1"])], timeout=0.2)
        self.assertEqual(failed, ["203.0.113.9"])


if __name__ == "__main__":
    unittest.main()
