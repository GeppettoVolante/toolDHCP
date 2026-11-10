"""Parse/build of BOOTP (RFC 951) and DHCP (RFC 2131/2132) packets.

Standard library only, no network access: everything is unit-testable.

Layout (RFC 951 / 2131): fixed 236-byte header, then
  - plain BOOTP: 'vend' field (64 bytes, 300 total)
  - DHCP: magic cookie 99.130.83.99 + options, terminated by End (255)
"""
import re
import struct
import ipaddress
from dataclasses import dataclass, field

BOOTREQUEST = 1
BOOTREPLY = 2

MAGIC_COOKIE = bytes((99, 130, 83, 99))
HEADER_LEN = 236
BOOTP_MIN_LEN = 300  # 236 + vend 64 (RFC 951)

# Option codes (RFC 2132)
OPT_PAD = 0
OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_LEASE_TIME = 51
OPT_MSG_TYPE = 53
OPT_SERVER_ID = 54
OPT_REQUESTED_IP = 50
OPT_END = 255

# DHCP message types (RFC 2132 par. 9.6)
DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPDECLINE = 4
DHCPACK = 5
DHCPNAK = 6
DHCPRELEASE = 7
DHCPINFORM = 8

MSG_NAMES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
             5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}

# "Infinite" lease: 0xFFFFFFFF (RFC 2131 sec. 3.3)
LEASE_INFINITE = 0xFFFFFFFF

FLAG_BROADCAST = 0x8000

ZERO_IP = "0.0.0.0"


class PacketError(ValueError):
    pass


def mac_to_bytes(mac: str) -> bytes:
    """Parse a MAC typed or pasted by hand. Accepted: AA:BB:CC:DD:EE:FF, AA-BB-..., aabbccddeeff,
    AABB.CCDD.EEFF (Cisco), with or without spaces, upper or lower case."""
    s = mac.strip()
    parts = s.replace("-", ":").split(":")
    if len(parts) == 6 and all(1 <= len(p) <= 2 for p in parts):
        return bytes(int(p, 16) for p in parts)
    compact = re.sub(r"[.\s:\-]", "", s)
    if len(compact) == 12 and all(c in "0123456789abcdefABCDEF" for c in compact):
        return bytes.fromhex(compact)
    raise ValueError(f"invalid MAC address: {mac!r}")


def mac_to_str(b: bytes) -> str:
    return ":".join(f"{x:02X}" for x in b)


def _ip(b: bytes) -> str:
    return str(ipaddress.IPv4Address(b))


def _ipb(s: str) -> bytes:
    return ipaddress.IPv4Address(s).packed


@dataclass
class Packet:
    op: int = BOOTREQUEST
    htype: int = 1
    hlen: int = 6
    hops: int = 0
    xid: int = 0
    secs: int = 0
    flags: int = 0
    ciaddr: str = ZERO_IP
    yiaddr: str = ZERO_IP
    siaddr: str = ZERO_IP
    giaddr: str = ZERO_IP
    chaddr: bytes = b"\x00" * 16
    sname: bytes = b""
    file: bytes = b""
    has_cookie: bool = False          # True => DHCP-style options present
    options: dict = field(default_factory=dict)  # code -> bytes

    @property
    def mac(self) -> str:
        return mac_to_str(self.chaddr[:self.hlen])

    @property
    def msg_type(self):
        v = self.options.get(OPT_MSG_TYPE)
        return v[0] if v else None

    @property
    def is_dhcp(self) -> bool:
        return self.msg_type is not None

    @property
    def broadcast_flag(self) -> bool:
        return bool(self.flags & FLAG_BROADCAST)


def parse(data: bytes) -> Packet:
    """Decode a BOOTP/DHCP datagram. Raises PacketError if malformed."""
    if len(data) < HEADER_LEN:
        raise PacketError(f"packet too short ({len(data)} bytes)")
    (op, htype, hlen, hops, xid, secs, flags,
     ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file_) = struct.unpack(
        "!BBBBIHH4s4s4s4s16s64s128s", data[:HEADER_LEN])
    if op not in (BOOTREQUEST, BOOTREPLY):
        raise PacketError(f"invalid op: {op}")
    if hlen > 16:
        raise PacketError(f"invalid hlen: {hlen}")
    pkt = Packet(op, htype, hlen, hops, xid, secs, flags,
                 _ip(ciaddr), _ip(yiaddr), _ip(siaddr), _ip(giaddr),
                 chaddr, sname.rstrip(b"\x00"), file_.rstrip(b"\x00"))
    rest = data[HEADER_LEN:]
    if rest[:4] == MAGIC_COOKIE:
        pkt.has_cookie = True
        pkt.options = _parse_options(rest[4:])
    return pkt


def _parse_options(buf: bytes) -> dict:
    opts = {}
    i = 0
    while i < len(buf):
        code = buf[i]
        i += 1
        if code == OPT_PAD:
            continue
        if code == OPT_END:
            break
        if i >= len(buf):
            raise PacketError("truncated option (length missing)")
        ln = buf[i]
        i += 1
        if i + ln > len(buf):
            raise PacketError(f"option {code} truncated")
        opts[code] = buf[i:i + ln]
        i += ln
    # NB: option overload (52, sname/file used for options) is not handled.
    return opts


def build(pkt: Packet) -> bytes:
    """Serialize the packet, padded to 300 bytes (BOOTP format, RFC 951)."""
    head = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        pkt.op, pkt.htype, pkt.hlen, pkt.hops, pkt.xid, pkt.secs, pkt.flags,
        _ipb(pkt.ciaddr), _ipb(pkt.yiaddr), _ipb(pkt.siaddr), _ipb(pkt.giaddr),
        pkt.chaddr.ljust(16, b"\x00")[:16],
        pkt.sname.ljust(64, b"\x00")[:64],
        pkt.file.ljust(128, b"\x00")[:128])
    body = b""
    if pkt.has_cookie:
        body = MAGIC_COOKIE
        # message type first (convention), then the rest in code order
        order = sorted(pkt.options, key=lambda c: (c != OPT_MSG_TYPE, c))
        for code in order:
            val = pkt.options[code]
            if len(val) > 255:
                raise ValueError(f"option {code} too long")
            body += bytes((code, len(val))) + val
        body += bytes((OPT_END,))
    out = head + body
    return out.ljust(BOOTP_MIN_LEN, b"\x00")


def build_reply(req: Packet, yiaddr: str, server_ip: str, mask: str,
                gateway: str | None, dhcp_type: int | None,
                lease: int = LEASE_INFINITE) -> Packet:
    """Build the reply (BOOTREPLY) to a request.

    dhcp_type None  => plain BOOTP reply (options in vend, no DHCP type)
    dhcp_type 2/5/6 => OFFER/ACK/NAK
    Fields copied from the client: xid, flags, giaddr, chaddr, htype, hlen (RFC 2131 table 3).
    """
    rep = Packet(op=BOOTREPLY, htype=req.htype, hlen=req.hlen, hops=0,
                 xid=req.xid, secs=0, flags=req.flags,
                 ciaddr=ZERO_IP, yiaddr=yiaddr, siaddr=server_ip,
                 giaddr=req.giaddr, chaddr=req.chaddr, has_cookie=True)
    if dhcp_type == DHCPNAK:
        rep.yiaddr = ZERO_IP
        rep.siaddr = ZERO_IP
        rep.options[OPT_MSG_TYPE] = bytes((DHCPNAK,))
        rep.options[OPT_SERVER_ID] = _ipb(server_ip)
        return rep
    if dhcp_type is not None:
        rep.options[OPT_MSG_TYPE] = bytes((dhcp_type,))
        if dhcp_type == DHCPACK:
            rep.ciaddr = req.ciaddr  # copied from REQUEST (RFC 2131 table 3)
        rep.options[OPT_SERVER_ID] = _ipb(server_ip)
        rep.options[OPT_LEASE_TIME] = struct.pack("!I", lease)
    rep.options[OPT_SUBNET_MASK] = _ipb(mask)
    if gateway:
        rep.options[OPT_ROUTER] = _ipb(gateway)
    return rep
