"""Minimal EtherNet/IP (CIP) client, stdlib only.

Used for two things:
  * discover devices that already have an IP (ListIdentity, UDP 44818);
  * make an IP permanent / change it: write the TCP/IP Interface Object
    (class 0xF5, instance 1): Configuration Control (attr 3) = static and
    Interface Configuration (attr 5) = IP, mask, gateway.
    This is what the vendor "Disable BOOTP/DHCP" button does.

Transport: encapsulation (ODVA, CIP Vol.2) over TCP 44818, unconnected
messages (RegisterSession + SendRRData). All integers are little endian,
except the socket address inside the ListIdentity item (big endian).

NOTE: only tested against the simulator in tests/test_cip.py. Real devices may
differ (order of writes, reset needed): see the Result messages.
"""
import ipaddress
import select
import socket
import struct
import time
from dataclasses import dataclass, field

PORT = 44818

CMD_LIST_IDENTITY = 0x0063
CMD_REGISTER_SESSION = 0x0065
CMD_SEND_RR_DATA = 0x006F

SVC_GET_ATTR_SINGLE = 0x0E
SVC_SET_ATTR_SINGLE = 0x10

CLASS_TCPIP = 0xF5
CLASS_ETHLINK = 0xF6
ATTR_TCPIP_STATUS = 1
ATTR_TCPIP_CONFIG_CTRL = 3
ATTR_TCPIP_IFACE_CFG = 5
ATTR_ETHLINK_MAC = 3

CFG_STATIC = 0
CFG_BOOTP = 1
CFG_DHCP = 2
CFG_NAMES = {0: "static", 1: "BOOTP", 2: "DHCP"}

STATUS_TEXT = {
    0x01: "connection failure", 0x04: "path segment error", 0x05: "path destination unknown",
    0x08: "service not supported", 0x09: "invalid attribute value", 0x0E: "attribute not settable",
    0x0F: "privilege violation", 0x10: "device state conflict", 0x13: "not enough data",
    0x14: "attribute not supported", 0x15: "too much data", 0x1F: "vendor specific error",
}


class CipError(Exception):
    """Protocol or transport error."""


class CipStatus(CipError):
    """The device answered with a CIP general status != 0."""

    def __init__(self, status, extra=b""):
        self.status = status
        self.extra = extra
        super().__init__(f"CIP status 0x{status:02X} ({STATUS_TEXT.get(status, 'unknown')})")


# ---------------- encoding helpers ----------------
def ip_to_udint(ip):
    return struct.pack("<I", int(ipaddress.IPv4Address(ip)))


def udint_to_ip(b):
    return str(ipaddress.IPv4Address(struct.unpack("<I", b)[0]))


def header(command, data=b"", session=0, context=b"toolDHCP"):
    return struct.pack("<HHII8sI", command, len(data), session, 0, context[:8].ljust(8, b"\0"), 0) + data


def parse_header(b):
    if len(b) < 24:
        raise CipError("encapsulation header too short")
    cmd, length, session, status, _ctx, _opt = struct.unpack("<HHII8sI", b[:24])
    return cmd, length, session, status


def epath(cls, inst, attr=None):
    p = bytes([0x20, cls, 0x24, inst])
    if attr is not None:
        p += bytes([0x30, attr])
    return p


def cip_request(service, path, data=b""):
    return bytes([service, len(path) // 2]) + path + data


def parse_cip_reply(b):
    """Return the data of a CIP reply; raise CipStatus if general status != 0."""
    if len(b) < 4:
        raise CipError("CIP reply too short")
    status, addl = b[2], b[3]
    if status != 0:
        raise CipStatus(status, b[4:4 + addl * 2])
    return b[4 + addl * 2:]


# ---------------- discovery ----------------
@dataclass
class Identity:
    ip: str
    vendor_id: int
    device_type: int
    product_code: int
    revision: str
    serial: int
    product_name: str
    mac: str = ""          # filled in later through the Ethernet Link object
    via: str = ""          # local IP the reply came back to (alias used to reach it), "" = normal scan


def parse_list_identity(payload, src_ip=None):
    """Parse the data of a ListIdentity reply into a list of Identity."""
    out = []
    if len(payload) < 2:
        return out
    count = struct.unpack_from("<H", payload, 0)[0]
    off = 2
    for _ in range(count):
        if off + 4 > len(payload):
            break
        itype, ilen = struct.unpack_from("<HH", payload, off)
        body = payload[off + 4: off + 4 + ilen]
        off += 4 + ilen
        if itype != 0x000C or len(body) < 33:
            continue
        # version(2) sockaddr(16, big endian) vendor(2) type(2) code(2) rev(2) status(2) serial(4) name
        ip = str(ipaddress.IPv4Address(body[6:10]))
        vendor, dtype, code, rmaj, rmin, _st, serial = struct.unpack_from("<HHHBBHI", body, 18)
        nlen = body[32]
        name = body[33:33 + nlen].decode("latin-1", "replace")
        out.append(Identity(src_ip or ip, vendor, dtype, code, f"{rmaj}.{rmin:03d}", serial, name))
    return out


def list_identity(bind_ip, targets, timeout=1.5, port=PORT):
    """Broadcast ListIdentity from bind_ip and collect replies for `timeout` seconds."""
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind((bind_ip, 0))
        pkt = header(CMD_LIST_IDENTITY)
        for t in targets:
            try:
                s.sendto(pkt, (t, port))
            except OSError:
                pass
        end = time.time() + timeout
        while True:
            left = end - time.time()
            if left <= 0:
                break
            s.settimeout(left)
            try:
                data, src = s.recvfrom(2048)
            except socket.timeout:
                break
            except OSError as e:
                if getattr(e, "winerror", 0) == 10054:
                    continue
                break
            try:
                cmd, length, _sess, status = parse_header(data)
            except CipError:
                continue
            if cmd != CMD_LIST_IDENTITY or status != 0:
                continue
            for ident in parse_list_identity(data[24:24 + length], src[0]):
                found[ident.ip] = ident
    finally:
        s.close()
    return sorted(found.values(), key=lambda i: tuple(map(int, i.ip.split("."))))


def list_identity_multi(jobs, timeout=2.0, port=PORT, stop=lambda: False):
    """ListIdentity from many local IPs at once. jobs = [(local_ip, [targets])].
    One socket per local IP; replies are matched to the socket they arrive on, so
    Identity.via tells which local (alias) IP reached the device. Returns (found, failed_ips)."""
    socks, failed = {}, []
    found = {}
    try:
        for local, targets in jobs:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.bind((local, 0))
            except OSError:
                s.close()
                failed.append(local)
                continue
            socks[s] = local
            pkt = header(CMD_LIST_IDENTITY)
            for t in targets:
                try:
                    s.sendto(pkt, (t, port))
                except OSError:
                    pass
        end = time.time() + timeout
        while socks and time.time() < end and not stop():
            try:
                ready, _, _ = select.select(list(socks), [], [], min(0.2, max(end - time.time(), 0)))
            except (OSError, ValueError):
                break
            for s in ready:
                try:
                    data, src = s.recvfrom(2048)
                except OSError:
                    continue
                try:
                    cmd, length, _sess, status = parse_header(data)
                except CipError:
                    continue
                if cmd != CMD_LIST_IDENTITY or status != 0:
                    continue
                for ident in parse_list_identity(data[24:24 + length], src[0]):
                    ident.via = socks[s]
                    found.setdefault(ident.ip, ident)
    finally:
        for s in socks:
            s.close()
    return list(found.values()), failed


# ---------------- TCP client ----------------
class Client:
    def __init__(self, ip, bind_ip=None, port=PORT, timeout=3.0):
        self.ip, self.port, self.timeout = ip, port, timeout
        self.bind_ip = bind_ip
        self.sock = None
        self.session = 0

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *_):
        self.close()

    def open(self):
        src = (self.bind_ip, 0) if self.bind_ip else None
        try:
            self.sock = socket.create_connection((self.ip, self.port), self.timeout, source_address=src)
        except OSError as e:
            raise CipError(f"cannot connect to {self.ip}:{self.port} ({e})")
        self.sock.settimeout(self.timeout)
        _, _, sess, status = self._exchange(CMD_REGISTER_SESSION, struct.pack("<HH", 1, 0))[:4]
        if status != 0:
            raise CipError(f"RegisterSession refused (status 0x{status:X})")
        self.session = sess

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise CipError("connection closed by the device")
            buf += chunk
        return buf

    def _exchange(self, command, data):
        try:
            self.sock.sendall(header(command, data, self.session))
            h = self._recv_exact(24)
            cmd, length, sess, status = parse_header(h)
            payload = self._recv_exact(length) if length else b""
        except socket.timeout:
            raise CipError("timeout waiting for the device")
        except OSError as e:
            raise CipError(f"network error ({e})")
        return cmd, length, sess, status, payload

    def request(self, cip):
        """Send an unconnected CIP request and return the reply data."""
        item = struct.pack("<HHHH", 0, 0, 0x00B2, len(cip)) + cip
        data = struct.pack("<IHH", 0, 10, 2) + item
        _, _, _, status, payload = self._exchange(CMD_SEND_RR_DATA, data)
        if status != 0:
            raise CipError(f"SendRRData refused (status 0x{status:X})")
        # interface handle(4) timeout(2) item count(2) then items
        if len(payload) < 8:
            raise CipError("SendRRData reply too short")
        count = struct.unpack_from("<H", payload, 6)[0]
        off = 8
        for _ in range(count):
            if off + 4 > len(payload):
                break
            itype, ilen = struct.unpack_from("<HH", payload, off)
            body = payload[off + 4: off + 4 + ilen]
            off += 4 + ilen
            if itype == 0x00B2:
                return parse_cip_reply(body)
        raise CipError("no data item in the reply")

    def get_attr(self, cls, inst, attr):
        return self.request(cip_request(SVC_GET_ATTR_SINGLE, epath(cls, inst, attr)))

    def set_attr(self, cls, inst, attr, value):
        return self.request(cip_request(SVC_SET_ATTR_SINGLE, epath(cls, inst, attr), value))

    # --- high level reads ---
    def read_config_control(self):
        return struct.unpack("<I", self.get_attr(CLASS_TCPIP, 1, ATTR_TCPIP_CONFIG_CTRL)[:4])[0] & 0xF

    def read_iface_cfg(self):
        """Raw attr 5 bytes: ip, mask, gw, dns1, dns2 (5 UDINT) + domain name string."""
        raw = self.get_attr(CLASS_TCPIP, 1, ATTR_TCPIP_IFACE_CFG)
        if len(raw) < 20:
            raise CipError("Interface Configuration shorter than expected")
        return raw

    def read_mac(self):
        raw = self.get_attr(CLASS_ETHLINK, 1, ATTR_ETHLINK_MAC)
        if len(raw) < 6:
            raise CipError("MAC address shorter than expected")
        return ":".join(f"{b:02X}" for b in raw[:6])

    def read_status(self):
        return struct.unpack("<I", self.get_attr(CLASS_TCPIP, 1, ATTR_TCPIP_STATUS)[:4])[0]


# ---------------- make permanent / change IP ----------------
@dataclass
class Result:
    ok: bool = False
    verified: bool = False
    reset_needed: bool = False
    retryable: bool = False   # network-level failure (device not up yet): worth retrying
    messages: list = field(default_factory=list)

    def say(self, m):
        self.messages.append(m)


def parse_cfg(raw):
    return (udint_to_ip(raw[0:4]), udint_to_ip(raw[4:8]), udint_to_ip(raw[8:12]))


def make_static(cur_ip, ip, mask, gateway=None, expect_mac=None, bind_ip=None,
                port=PORT, timeout=3.0, settle=4.0, verify_bind_ip=None):
    """Switch the device at `cur_ip` to a static configuration (ip, mask, gateway).

    Order: (1) check the MAC (if given), (2) Configuration Control = static
    (the IP is unchanged, so the session survives), (3) Interface Configuration
    = new values (name servers/domain kept), (4) read back. `bind_ip` is the local IP used
    to reach the device (an alias when it is on another subnet); `verify_bind_ip` the one
    used to find it again on the new IP (normally the PC's real interface IP). If the IP changes the
    device may drop the session: then verify with a new session on the new IP.
    """
    r = Result()
    gw = gateway or "0.0.0.0"
    try:
        with Client(cur_ip, bind_ip, port, timeout) as c:
            if expect_mac:
                mac = c.read_mac()
                if mac.upper() != expect_mac.upper():
                    r.say(f"ABORTED: the device at {cur_ip} has MAC {mac}, expected {expect_mac}.")
                    return r
                r.say(f"MAC confirmed: {mac}")
            try:
                before = CFG_NAMES.get(c.read_config_control(), "?")
                r.say(f"Configuration Control before: {before}")
            except CipError as e:
                r.say(f"Configuration Control not readable ({e}): continuing")
            old = c.read_iface_cfg()
            c.set_attr(CLASS_TCPIP, 1, ATTR_TCPIP_CONFIG_CTRL, struct.pack("<I", CFG_STATIC))
            r.say("Configuration Control = static: written")
            new = ip_to_udint(ip) + ip_to_udint(mask) + ip_to_udint(gw) + old[12:]
            try:
                c.set_attr(CLASS_TCPIP, 1, ATTR_TCPIP_IFACE_CFG, new)
                r.say(f"Interface Configuration = {ip} / {mask} gw {gateway or '-'}: written")
            except CipError as e:
                if isinstance(e, CipStatus):
                    raise
                r.say(f"Session lost right after the write ({e}): normal if the IP changed")
            else:
                try:
                    st = c.read_status()
                    if st & 0x10:   # Interface Configuration Pending
                        r.reset_needed = True
                        r.say("The device reports 'configuration pending': power cycle or reset needed")
                    cc = c.read_config_control()
                    cfg = parse_cfg(c.read_iface_cfg())
                    if cc == CFG_STATIC and cfg == (ip, mask, gw):
                        r.verified = True
                        r.say("Read-back OK: static, values match")
                    else:
                        r.say(f"Read-back: control={CFG_NAMES.get(cc, cc)} cfg={cfg}")
                except CipError as e:
                    r.say(f"Read-back not possible ({e})")
            r.ok = True
    except CipStatus as e:
        r.say(f"The device refused: {e}")
        r.ok = False
        return r
    except CipError as e:
        r.say(f"Error: {e}")
        r.ok = False
        r.retryable = True
        return r

    if not r.verified and ip != cur_ip and not r.reset_needed:
        end = time.time() + settle
        while time.time() < end:
            try:
                with Client(ip, verify_bind_ip or bind_ip, port, timeout) as c2:
                    cc = c2.read_config_control()
                    cfg = parse_cfg(c2.read_iface_cfg())
                    if cc == CFG_STATIC and cfg[0] == ip:
                        r.verified = True
                        r.say(f"Verified on the new IP {ip}: static")
                    else:
                        r.say(f"On {ip}: control={CFG_NAMES.get(cc, cc)} cfg={cfg}")
                    break
            except CipError:
                time.sleep(0.5)
        if not r.verified:
            r.say(f"Not verified on {ip} (different subnet, or reset needed): check by hand")
    return r
