"""CIP client tests against an in-process simulated EtherNet/IP device (loopback only)."""
import os
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cip  # noqa: E402


class SimDevice:
    """Tiny EtherNet/IP device: TCP/IP Interface + Ethernet Link + ListIdentity."""

    def __init__(self, mac="00:00:5E:00:53:AA", ctrl=cip.CFG_BOOTP, ip="192.0.2.77",
                 refuse_set5=False, drop_after_set5=False):
        self.mac = bytes(int(x, 16) for x in mac.split(":"))
        self.ctrl = ctrl
        self.cfg = bytearray(cip.ip_to_udint(ip) + cip.ip_to_udint("255.255.255.0")
                             + cip.ip_to_udint("0.0.0.0") + cip.ip_to_udint("8.8.8.8")
                             + cip.ip_to_udint("0.0.0.0") + struct.pack("<H", 0))
        self.refuse_set5 = refuse_set5
        self.drop_after_set5 = drop_after_set5
        self.writes = []
        self.tcp = socket.socket()
        self.tcp.bind(("0.0.0.0", 0))
        self.tcp.listen(5)
        self.port = self.tcp.getsockname()[1]
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.udp_port = self.udp.getsockname()[1]
        self.alive = True
        threading.Thread(target=self._accept, daemon=True).start()
        threading.Thread(target=self._udp, daemon=True).start()

    def close(self):
        self.alive = False
        self.tcp.close()
        self.udp.close()

    # --- UDP ListIdentity ---
    def _udp(self):
        while self.alive:
            try:
                data, src = self.udp.recvfrom(512)
            except OSError:
                return
            cmd, *_ = struct.unpack("<HH", data[:4])
            if cmd != cip.CMD_LIST_IDENTITY:
                continue
            name = b"SimDevice"
            sa = struct.pack(">HH4s8s", 2, cip.PORT, socket.inet_aton("192.0.2.77"), b"\0" * 8)
            body = struct.pack("<H", 1) + sa + struct.pack("<HHHBBHI", 1, 12, 345, 2, 7, 0, 0xCAFE) \
                + bytes([len(name)]) + name + b"\x03"
            item = struct.pack("<HH", 0x000C, len(body)) + body
            self.udp.sendto(cip.header(cip.CMD_LIST_IDENTITY, struct.pack("<H", 1) + item), src)

    # --- TCP ---
    def _accept(self):
        while self.alive:
            try:
                c, _ = self.tcp.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            while True:
                h = self._rx(c, 24)
                cmd, length, sess, _st = cip.parse_header(h)
                payload = self._rx(c, length) if length else b""
                if cmd == cip.CMD_REGISTER_SESSION:
                    c.sendall(cip.header(cmd, payload, 0x1234))
                elif cmd == cip.CMD_SEND_RR_DATA:
                    req = payload[16:]          # skip handle/timeout/count + null item + data item header
                    reply, drop = self._cip(req)
                    item = struct.pack("<HHHH", 0, 0, 0x00B2, len(reply)) + reply
                    c.sendall(cip.header(cmd, struct.pack("<IHH", 0, 0, 2) + item, sess))
                    if drop:
                        c.close()
                        return
        except (OSError, cip.CipError):
            pass
        finally:
            c.close()

    @staticmethod
    def _rx(c, n):
        buf = b""
        while len(buf) < n:
            ch = c.recv(n - len(buf))
            if not ch:
                raise cip.CipError("closed")
            buf += ch
        return buf

    def _cip(self, req):
        svc, words = req[0], req[1]
        path = req[2:2 + words * 2]
        data = req[2 + words * 2:]
        cls, attr = path[1], path[5] if len(path) >= 6 else None
        ok = lambda d=b"": bytes([svc | 0x80, 0, 0, 0]) + d       # noqa: E731
        err = lambda s: bytes([svc | 0x80, 0, s, 0])               # noqa: E731
        if svc == cip.SVC_GET_ATTR_SINGLE:
            if cls == cip.CLASS_TCPIP and attr == 1:
                return ok(struct.pack("<I", 0x34)), False
            if cls == cip.CLASS_TCPIP and attr == 3:
                return ok(struct.pack("<I", self.ctrl)), False
            if cls == cip.CLASS_TCPIP and attr == 5:
                return ok(bytes(self.cfg)), False
            if cls == cip.CLASS_ETHLINK and attr == 3:
                return ok(self.mac), False
            return err(0x14), False
        if svc == cip.SVC_SET_ATTR_SINGLE:
            self.writes.append((cls, attr))
            if cls == cip.CLASS_TCPIP and attr == 3:
                self.ctrl = struct.unpack("<I", data[:4])[0]
                return ok(), False
            if cls == cip.CLASS_TCPIP and attr == 5:
                if self.refuse_set5:
                    return err(0x0E), False
                if self.ctrl != cip.CFG_STATIC:
                    return err(0x10), False
                self.cfg = bytearray(data)
                return ok(), self.drop_after_set5
            return err(0x14), False
        return err(0x08), False


class CipTest(unittest.TestCase):
    def setUp(self):
        self.dev = SimDevice()
        self.addCleanup(self.dev.close)

    def test_list_identity(self):
        res = cip.list_identity("127.0.0.1", ["127.0.0.1"], timeout=0.5, port=self.dev.udp_port)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].product_name, "SimDevice")
        self.assertEqual(res[0].serial, 0xCAFE)
        self.assertEqual(res[0].revision, "2.007")

    def test_read_mac_and_control(self):
        with cip.Client("127.0.0.1", port=self.dev.port) as c:
            self.assertEqual(c.read_mac(), "00:00:5E:00:53:AA")
            self.assertEqual(c.read_config_control(), cip.CFG_BOOTP)

    def test_make_static_same_ip(self):
        r = cip.make_static("127.0.0.1", "192.0.2.77", "255.255.255.0", None,
                            expect_mac="00:00:5E:00:53:AA", port=self.dev.port)
        self.assertTrue(r.ok, r.messages)
        self.assertTrue(r.verified, r.messages)
        self.assertEqual(self.dev.ctrl, cip.CFG_STATIC)
        self.assertEqual(self.dev.writes[0], (cip.CLASS_TCPIP, 3))   # control first
        self.assertEqual(bytes(self.dev.cfg[12:16]), cip.ip_to_udint("8.8.8.8"))  # DNS kept

    def test_wrong_mac_aborts_without_writing(self):
        r = cip.make_static("127.0.0.1", "192.0.2.77", "255.255.255.0", None,
                            expect_mac="00:00:5E:00:53:BB", port=self.dev.port)
        self.assertFalse(r.ok)
        self.assertEqual(self.dev.writes, [])
        self.assertEqual(self.dev.ctrl, cip.CFG_BOOTP)

    def test_change_ip_with_session_drop(self):
        self.dev.drop_after_set5 = True
        r = cip.make_static("127.0.0.1", "127.0.0.2", "255.255.255.0", "127.0.0.254",
                            port=self.dev.port, settle=2.0)
        self.assertTrue(r.ok, r.messages)
        self.assertTrue(r.verified, r.messages)
        self.assertEqual(cip.udint_to_ip(bytes(self.dev.cfg[0:4])), "127.0.0.2")

    def test_refused_write_is_reported(self):
        self.dev.refuse_set5 = True
        r = cip.make_static("127.0.0.1", "192.0.2.80", "255.255.255.0", None, port=self.dev.port)
        self.assertFalse(r.ok)
        self.assertIn("0x0E", " ".join(r.messages))

    def test_connection_refused(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        r = cip.make_static("127.0.0.1", "192.0.2.80", "255.255.255.0", None, port=port, timeout=1)
        self.assertFalse(r.ok)

    def test_encoding(self):
        self.assertEqual(cip.ip_to_udint("192.168.1.10"), bytes([10, 1, 168, 192]))
        self.assertEqual(cip.epath(0xF5, 1, 3), bytes([0x20, 0xF5, 0x24, 1, 0x30, 3]))


if __name__ == "__main__":
    unittest.main()
