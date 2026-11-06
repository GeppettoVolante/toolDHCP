"""Unit + loopback tests (127.0.0.1, ephemeral ports). No packets on the real network.

Run: python -m unittest discover -s tests   (from src/)
"""
import os
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import bootp  # noqa: E402
import server  # noqa: E402

MAC = "00:00:5E:00:53:10"
OTHER = "00:00:5E:00:53:99"
SRV, IP, MASK, GW = "192.0.2.1", "192.0.2.10", "255.255.255.0", "192.0.2.1"


def request(mac=MAC, xid=0x1234ABCD, msg_type=None, extra=None, flags=0x8000, ciaddr="0.0.0.0"):
    p = bootp.Packet(op=bootp.BOOTREQUEST, xid=xid, flags=flags, ciaddr=ciaddr,
                     chaddr=bootp.mac_to_bytes(mac).ljust(16, b"\0"))
    if msg_type is not None:
        p.has_cookie = True
        p.options[bootp.OPT_MSG_TYPE] = bytes((msg_type,))
        p.options.update(extra or {})
    return bootp.build(p)


class TestParseBuild(unittest.TestCase):
    def test_roundtrip_bootp(self):
        pkt = bootp.parse(request())
        self.assertEqual(pkt.op, bootp.BOOTREQUEST)
        self.assertEqual(pkt.mac, MAC)
        self.assertEqual(pkt.xid, 0x1234ABCD)
        self.assertFalse(pkt.is_dhcp)
        self.assertTrue(pkt.broadcast_flag)

    def test_length_300(self):
        self.assertEqual(len(request()), 300)

    def test_dhcp_options(self):
        pkt = bootp.parse(request(msg_type=bootp.DHCPDISCOVER))
        self.assertEqual(pkt.msg_type, bootp.DHCPDISCOVER)
        self.assertTrue(pkt.has_cookie)

    def test_offsets(self):
        raw = request(msg_type=1)
        self.assertEqual(raw[0], 1)
        self.assertEqual(struct.unpack("!I", raw[4:8])[0], 0x1234ABCD)
        self.assertEqual(raw[28:34], bootp.mac_to_bytes(MAC))
        self.assertEqual(raw[236:240], bytes((99, 130, 83, 99)))

    def test_too_short(self):
        with self.assertRaises(bootp.PacketError):
            bootp.parse(b"\x01" * 100)

    def test_truncated_option(self):
        raw = request(msg_type=1)[:240] + bytes((53, 5, 1))
        with self.assertRaises(bootp.PacketError):
            bootp.parse(raw)

    def test_bad_op(self):
        raw = bytearray(request())
        raw[0] = 9
        with self.assertRaises(bootp.PacketError):
            bootp.parse(bytes(raw))

    def test_pad_skipped(self):
        raw = request()[:236] + bootp.MAGIC_COOKIE + bytes((0, 0, 53, 1, 1, 255))
        self.assertEqual(bootp.parse(raw).msg_type, 1)

    def test_reply_fields(self):
        req = bootp.parse(request(msg_type=1))
        rep = bootp.build_reply(req, IP, SRV, MASK, GW, bootp.DHCPOFFER)
        back = bootp.parse(bootp.build(rep))
        self.assertEqual(back.op, bootp.BOOTREPLY)
        self.assertEqual(back.xid, req.xid)
        self.assertEqual(back.yiaddr, IP)
        self.assertEqual(back.options[bootp.OPT_SUBNET_MASK], bytes((255, 255, 255, 0)))
        self.assertEqual(back.options[bootp.OPT_ROUTER], bytes((192, 0, 2, 1)))
        self.assertEqual(back.options[bootp.OPT_SERVER_ID], bytes((192, 0, 2, 1)))
        self.assertEqual(back.options[bootp.OPT_LEASE_TIME], b"\xff\xff\xff\xff")
        self.assertEqual(back.msg_type, bootp.DHCPOFFER)

    def test_reply_no_gateway(self):
        req = bootp.parse(request())
        rep = bootp.build_reply(req, IP, SRV, MASK, None, None)
        self.assertNotIn(bootp.OPT_ROUTER, rep.options)


class TestResponder(unittest.TestCase):
    def setUp(self):
        self.r = server.Responder(SRV, MAC, IP, MASK, GW)

    def test_bootp(self):
        data, dest, _ = self.r.handle(request())
        rep = bootp.parse(data)
        self.assertEqual(rep.yiaddr, IP)
        self.assertFalse(rep.is_dhcp)
        self.assertEqual(rep.options[bootp.OPT_SUBNET_MASK], bytes((255, 255, 255, 0)))
        self.assertEqual(dest, ("255.255.255.255", 68))
        self.assertEqual((self.r.requests, self.r.replies), (1, 1))

    def test_discover_offer(self):
        data, _, _ = self.r.handle(request(msg_type=bootp.DHCPDISCOVER))
        self.assertEqual(bootp.parse(data).msg_type, bootp.DHCPOFFER)

    def test_request_ack(self):
        ext = {bootp.OPT_REQUESTED_IP: bytes((192, 0, 2, 10)),
               bootp.OPT_SERVER_ID: bytes((192, 0, 2, 1))}
        data, _, _ = self.r.handle(request(msg_type=bootp.DHCPREQUEST, extra=ext))
        self.assertEqual(bootp.parse(data).msg_type, bootp.DHCPACK)

    def test_request_wrong_ip_nak(self):
        ext = {bootp.OPT_REQUESTED_IP: bytes((192, 0, 2, 77))}
        data, _, _ = self.r.handle(request(msg_type=bootp.DHCPREQUEST, extra=ext))
        rep = bootp.parse(data)
        self.assertEqual(rep.msg_type, bootp.DHCPNAK)
        self.assertEqual(rep.yiaddr, "0.0.0.0")

    def test_request_other_server_ignored(self):
        ext = {bootp.OPT_SERVER_ID: bytes((192, 0, 2, 200))}
        data, _, _ = self.r.handle(request(msg_type=bootp.DHCPREQUEST, extra=ext))
        self.assertIsNone(data)

    def test_other_mac_ignored(self):
        data, _, _ = self.r.handle(request(mac=OTHER))
        self.assertIsNone(data)
        self.assertEqual((self.r.requests, self.r.replies, self.r.ignored), (1, 0, 1))

    def test_garbage(self):
        data, _, _ = self.r.handle(b"abc")
        self.assertIsNone(data)
        self.assertEqual(self.r.malformed, 1)

    def test_giaddr_dest(self):
        p = bootp.parse(request())
        p.giaddr = "192.0.2.250"
        data, dest, _ = self.r.handle(bootp.build(p))
        self.assertEqual(dest, ("192.0.2.250", 67))
        self.assertEqual(bootp.parse(data).giaddr, "192.0.2.250")


class TestLoopback(unittest.TestCase):
    def test_roundtrip_udp(self):
        resp = server.Responder("127.0.0.1", MAC, IP, MASK, GW)
        ssock = server.open_socket("127.0.0.1", port=0)
        sport = ssock.getsockname()[1]
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.1", 0))
        client.settimeout(3)
        override = ("127.0.0.1", client.getsockname()[1])
        stop = threading.Event()
        t = threading.Thread(target=server.serve, args=(ssock, resp),
                             kwargs=dict(dest_override=override, stop=stop.is_set,
                                         log=lambda *_: None, timeout=0.1))
        t.start()
        try:
            client.sendto(request(msg_type=bootp.DHCPDISCOVER), ("127.0.0.1", sport))
            offer = bootp.parse(client.recvfrom(2048)[0])
            self.assertEqual(offer.msg_type, bootp.DHCPOFFER)
            self.assertEqual(offer.xid, 0x1234ABCD)
            client.sendto(request(msg_type=bootp.DHCPREQUEST,
                                  extra={bootp.OPT_REQUESTED_IP: bytes((192, 0, 2, 10))}),
                          ("127.0.0.1", sport))
            self.assertEqual(bootp.parse(client.recvfrom(2048)[0]).msg_type, bootp.DHCPACK)
            client.sendto(request(), ("127.0.0.1", sport))
            self.assertEqual(bootp.parse(client.recvfrom(2048)[0]).yiaddr, IP)
        finally:
            stop.set()
            t.join()
            ssock.close()
            client.close()
        self.assertEqual((resp.requests, resp.replies), (3, 3))

    def test_port_busy_message(self):
        a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        a.bind(("127.0.0.1", 0))
        try:
            with self.assertRaises(SystemExit) as cm:
                server.open_socket("127.0.0.1", port=a.getsockname()[1])
            self.assertIn("in use",str(cm.exception))
        finally:
            a.close()


if __name__ == "__main__":
    unittest.main()
