"""BOOTP/DHCP listener (port 67) for "factory-fresh" devices.

Replies ONLY to the MAC(s) armed. No silent defaults:
--bind (the interface IP) is mandatory.

Example (dummy values):
  python server.py --bind 192.0.2.1 --mac 00:00:5E:00:53:10 \
      --ip 192.0.2.10 --mask 255.255.255.0 --gateway 192.0.2.1

Replies are broadcast to 255.255.255.255:68 (the client has no IP yet and
cannot answer ARP: RFC 951 broadcast; RFC 2131 sec. 4.1).
If giaddr != 0 the reply goes to giaddr:67 (relay agent), per RFC 2131 sec. 4.1.
"""
import argparse
import errno
import ipaddress
import socket
import sys
import threading
import time
from dataclasses import dataclass

import bootp

SERVER_PORT = 67
CLIENT_PORT = 68
BCAST = "255.255.255.255"


@dataclass
class Assignment:
    ip: str
    mask: str
    gateway: str | None = None


@dataclass
class Seen:
    """A MAC seen on the network asking for an IP (for the passive 'scan' list)."""
    mac: str
    kind: str = ""
    count: int = 0
    first: float = 0.0
    last: float = 0.0
    status: str = "seen"


class Responder:
    """Pure logic: given a datagram, decide the reply. No sockets involved.

    Passive: records every MAC asking for an IP in `seen`.
    Active: replies (always, while armed) to the MACs in `armed`. Thread-safe.
    """

    def __init__(self, server_ip, mac=None, ip=None, mask=None, gateway=None,
                 lease=bootp.LEASE_INFINITE):
        self.server_ip = server_ip
        self.lease = lease
        self.armed = {}         # mac -> Assignment
        self.seen = {}          # mac -> Seen
        self._lock = threading.RLock()
        self.requests = 0       # valid BOOTREQUESTs received
        self.replies = 0        # replies generated
        self.ignored = 0        # requests ignored (other MAC, unhandled type...)
        self.malformed = 0
        if mac:
            self.arm(mac, ip, mask, gateway)

    def arm(self, mac, ip, mask, gateway=None):
        mac = bootp.mac_to_str(bootp.mac_to_bytes(mac))
        with self._lock:
            self.armed[mac] = Assignment(ip, mask, gateway)
        return mac

    def disarm(self, mac):
        with self._lock:
            self.armed.pop(bootp.mac_to_str(bootp.mac_to_bytes(mac)), None)

    def snapshot(self):
        """Copy of (seen, armed) for the GUI."""
        with self._lock:
            return ([Seen(**vars(v)) for v in self.seen.values()], dict(self.armed))

    def _note(self, mac, kind, status):
        now = time.time()
        sn = self.seen.get(mac)
        if sn is None:
            sn = self.seen[mac] = Seen(mac, first=now)
        sn.kind, sn.last, sn.status = kind, now, status
        sn.count += 1

    def handle(self, data):
        """Return (reply_bytes|None, dest|None, description)."""
        with self._lock:
            return self._handle(data)

    def _handle(self, data):
        try:
            req = bootp.parse(data)
        except bootp.PacketError as e:
            self.malformed += 1
            return None, None, f"packet dropped: {e}"
        if req.op != bootp.BOOTREQUEST:
            self.ignored += 1
            return None, None, "not a BOOTREQUEST, ignored"
        self.requests += 1
        kind = "DHCP-" + bootp.MSG_NAMES.get(req.msg_type, str(req.msg_type))             if req.is_dhcp else "BOOTP"
        desc = f"{kind} mac={req.mac} xid=0x{req.xid:08X} flags=0x{req.flags:04X}"
        a = self.armed.get(req.mac)
        if a is None:
            self.ignored += 1
            self._note(req.mac, kind, "seen, not armed")
            return None, None, desc + " -> MAC not armed, ignored"

        if not req.is_dhcp:
            rep = bootp.build_reply(req, a.ip, self.server_ip, a.mask, a.gateway, None)
            action = "BOOTP reply"
            status = "BOOTP replied"
        elif req.msg_type == bootp.DHCPDISCOVER:
            rep = bootp.build_reply(req, a.ip, self.server_ip, a.mask,
                                    a.gateway, bootp.DHCPOFFER, self.lease)
            action = status = "OFFER"
        elif req.msg_type == bootp.DHCPREQUEST:
            sid = req.options.get(bootp.OPT_SERVER_ID)
            if sid and bootp._ip(sid) != self.server_ip:
                self.ignored += 1
                self._note(req.mac, kind, "REQUEST for another server")
                return None, None, desc + " -> REQUEST for another server, ignored"
            rq = req.options.get(bootp.OPT_REQUESTED_IP)
            wanted = bootp._ip(rq) if rq else req.ciaddr
            if wanted != a.ip:
                rep = bootp.build_reply(req, bootp.ZERO_IP, self.server_ip, a.mask,
                                        None, bootp.DHCPNAK)
                action = f"NAK (requested {wanted}, armed {a.ip})"
                status = "NAK"
            else:
                rep = bootp.build_reply(req, a.ip, self.server_ip, a.mask,
                                        a.gateway, bootp.DHCPACK, self.lease)
                action = status = "ACK"
        else:
            self.ignored += 1
            self._note(req.mac, kind, "unhandled type")
            return None, None, desc + " -> unhandled type, ignored"

        self.replies += 1
        self._note(req.mac, kind, status)
        dest = (req.giaddr, SERVER_PORT) if req.giaddr != bootp.ZERO_IP             else (BCAST, CLIENT_PORT)
        return bootp.build(rep), dest, f"{desc} -> {action} yiaddr={rep.yiaddr} dest={dest[0]}:{dest[1]}"


def open_socket(bind_ip, port=SERVER_PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        s.bind((bind_ip, port))
    except OSError as e:
        s.close()
        busy = {errno.EADDRINUSE, 10048, 10013}  # 10048/10013 = WSAEADDRINUSE/WSAEACCES
        if e.errno in busy:
            raise SystemExit(
                f"ERROR: UDP port {port} on {bind_ip} is in use or not accessible ({e}).\n"
                "Probably another DHCP/BOOTP server on this PC (DHCP Server service, ICS/"
                "Internet Connection Sharing, another tool, a previous instance).\n"
                "Stop it and try again.")
        if e.errno == errno.EADDRNOTAVAIL or getattr(e, "winerror", 0) == 10049:
            raise SystemExit(f"ERROR: {bind_ip} is not an IP address of this PC ({e}).")
        raise
    return s


def serve(sock, resp, dest_override=None, stop=lambda: False, log=print, timeout=1.0):
    """Service loop. dest_override=(ip,port) is for loopback tests only."""
    sock.settimeout(timeout)
    while not stop():
        try:
            data, src = sock.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError as e:
            # Windows: WSAECONNRESET (10054) on UDP after an ICMP 'port unreachable'
            # answering one of our sends: not a fatal error.
            if getattr(e, "winerror", 0) == 10054:
                continue
            log(f"[{time.strftime('%H:%M:%S')}] receive error: {e}")
            if stop():
                break
            time.sleep(0.2)
            continue
        reply, dest, desc = resp.handle(data)
        log(f"[{time.strftime('%H:%M:%S')}] from {src[0]}:{src[1]} {desc}")
        if reply:
            try:
                sock.sendto(reply, dest_override or dest)
            except OSError as e:
                log(f"[{time.strftime('%H:%M:%S')}] SEND ERROR to {dest}: {e}")


def _ipv4(s):
    try:
        return str(ipaddress.IPv4Address(s))
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid IPv4 address: {s}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Command-line BOOTP/DHCP server for one armed MAC")
    ap.add_argument("--bind", required=True, type=_ipv4,
                    help="IP of the PC interface to listen on (also used as server-id)")
    ap.add_argument("--mac", required=True, help="armed MAC, e.g. 00:00:5E:00:53:10")
    ap.add_argument("--ip", required=True, type=_ipv4, help="IP address to assign")
    ap.add_argument("--mask", required=True, type=_ipv4, help="subnet mask to assign")
    ap.add_argument("--gateway", type=_ipv4, help="gateway (optional)")
    a = ap.parse_args(argv)
    try:
        bootp.mac_to_bytes(a.mac)
    except ValueError as e:
        ap.error(str(e))

    resp = Responder(a.bind, a.mac, a.ip, a.mask, a.gateway)
    sock = open_socket(a.bind)
    print(f"Listening on {a.bind}:{SERVER_PORT}. Armed: {', '.join(resp.armed)} -> {a.ip} / {a.mask}"
          f" gw={a.gateway or '-'}. Press Ctrl+C to stop.")
    try:
        serve(sock, resp)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        print(f"\nRequests: {resp.requests}  Replies: {resp.replies}  "
              f"Ignored: {resp.ignored}  Dropped: {resp.malformed}")


if __name__ == "__main__":
    sys.exit(main())
