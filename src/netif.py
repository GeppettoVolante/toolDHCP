"""List of the PC's IPv4 network interfaces, stdlib only.

Windows: ctypes + GetAdaptersAddresses (iphlpapi), no external dependencies.
Other OSes: minimal fallback (development/testing only, not a target).
"""
import ctypes
import ipaddress
import socket
import sys
from dataclasses import dataclass

IF_TYPE_LOOPBACK = 24
IF_TYPE_TUNNEL = 131
OPER_UP = 1


@dataclass
class Iface:
    name: str          # friendly name (e.g. "Ethernet 2")
    description: str   # adapter description (e.g. "Realtek USB GbE")
    ip: str
    prefix: int
    mac: str
    up: bool = True
    if_index: int = 0
    dad: int = 4       # 3 = tentative, 4 = preferred (usable), 1 = duplicate

    @property
    def mask(self) -> str:
        return str(ipaddress.IPv4Network(f"{self.ip}/{self.prefix}", strict=False).netmask)

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(f"{self.ip}/{self.prefix}", strict=False)

    @property
    def link_local(self) -> bool:
        return self.ip.startswith("169.254.")

    def label(self) -> str:
        extra = " [link-local, no static IP?]" if self.link_local else ""
        return f"{self.name} - {self.ip}/{self.prefix} ({self.description}){extra}"


def list_interfaces() -> list:
    if sys.platform == "win32":
        return _list_windows()
    return _list_fallback()


def _list_fallback():
    out = []
    try:
        for ip in sorted(set(socket.gethostbyname_ex(socket.gethostname())[2])):
            if not ip.startswith("127."):
                out.append(Iface(ip, "", ip, 24, "00:00:00:00:00:00"))
    except OSError:
        pass
    return out


def _list_windows():
    from ctypes import wintypes as w

    class SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int)]

    class UNICAST(ctypes.Structure):
        pass

    UNICAST._fields_ = [
        ("Length", w.ULONG), ("Flags", w.DWORD),
        ("Next", ctypes.POINTER(UNICAST)),
        ("Address", SOCKET_ADDRESS),
        ("PrefixOrigin", ctypes.c_int), ("SuffixOrigin", ctypes.c_int),
        ("DadState", ctypes.c_int),
        ("ValidLifetime", w.ULONG), ("PreferredLifetime", w.ULONG),
        ("LeaseLifetime", w.ULONG),
        ("OnLinkPrefixLength", ctypes.c_ubyte),
    ]

    class ADAPTER(ctypes.Structure):
        pass

    ADAPTER._fields_ = [
        ("Length", w.ULONG), ("IfIndex", w.DWORD),
        ("Next", ctypes.POINTER(ADAPTER)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.POINTER(UNICAST)),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", w.LPWSTR), ("Description", w.LPWSTR), ("FriendlyName", w.LPWSTR),
        ("PhysicalAddress", ctypes.c_ubyte * 8), ("PhysicalAddressLength", w.ULONG),
        ("Flags", w.ULONG), ("Mtu", w.ULONG), ("IfType", w.ULONG), ("OperStatus", ctypes.c_int),
    ]

    gaa = ctypes.windll.iphlpapi.GetAdaptersAddresses
    gaa.argtypes = [w.ULONG, w.ULONG, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(w.ULONG)]
    gaa.restype = w.ULONG
    AF_INET = 2
    FLAGS = 0x2 | 0x4 | 0x8  # skip anycast, multicast, dns server
    size = w.ULONG(15000)
    for _ in range(5):
        buf = ctypes.create_string_buffer(size.value)
        rc = gaa(AF_INET, FLAGS, None, buf, ctypes.byref(size))
        if rc != 111:  # ERROR_BUFFER_OVERFLOW => retry with the updated size
            break
    if rc != 0:
        raise OSError(f"GetAdaptersAddresses fallita (codice {rc})")

    out = []
    ad = ctypes.cast(buf, ctypes.POINTER(ADAPTER))
    while ad:
        a = ad.contents
        if a.IfType not in (IF_TYPE_LOOPBACK, IF_TYPE_TUNNEL):
            mac = ":".join(f"{b:02X}" for b in a.PhysicalAddress[:a.PhysicalAddressLength])
            ua = a.FirstUnicastAddress
            while ua:
                u = ua.contents
                raw = ctypes.string_at(u.Address.lpSockaddr, 8) if u.Address.lpSockaddr else b""
                if len(raw) == 8 and int.from_bytes(raw[:2], "little") == AF_INET:
                    out.append(Iface(a.FriendlyName or "?", a.Description or "",
                                     str(ipaddress.IPv4Address(raw[4:8])),
                                     u.OnLinkPrefixLength, mac,
                                     a.OperStatus == OPER_UP, a.IfIndex, u.DadState))
                ua = u.Next
        ad = a.Next
    return out


def usable(ifaces):
    """Only interfaces that are up, have an IP and a real subnet (no VPN-style /32)."""
    return [i for i in ifaces if i.up and i.ip != "0.0.0.0" and i.prefix < 32]


# ---------------- temporary IP aliases (Windows, administrator needed) ----------------
_aliases = {}      # ip -> NTE context, for everything this process added


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def add_alias(if_index, ip, mask="255.255.255.0"):
    """Add a NON-persistent IPv4 address to an adapter (AddIPAddress). Returns the NTE context.
    It disappears at reboot/adapter reset; remove_alias() / remove_all_aliases() delete it."""
    fn = ctypes.windll.iphlpapi.AddIPAddress
    fn.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
                   ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
    fn.restype = ctypes.c_ulong
    ctx, inst = ctypes.c_ulong(0), ctypes.c_ulong(0)
    rc = fn(int.from_bytes(socket.inet_aton(ip), "little"),
            int.from_bytes(socket.inet_aton(mask), "little"), if_index,
            ctypes.byref(ctx), ctypes.byref(inst))
    if rc != 0:
        raise OSError(f"AddIPAddress({ip}) failed, code {rc}" + (" (administrator needed)" if rc == 5 else ""))
    _aliases[ip] = ctx.value
    return ctx.value


def remove_alias(ip):
    ctx = _aliases.pop(ip, None)
    if ctx is None:
        return
    fn = ctypes.windll.iphlpapi.DeleteIPAddress
    fn.argtypes = [ctypes.c_ulong]
    fn.restype = ctypes.c_ulong
    fn(ctx)


def remove_all_aliases(keep=()):
    for ip in list(_aliases):
        if ip not in keep:
            remove_alias(ip)


def aliases():
    return list(_aliases)


def wait_preferred(if_index, ips, timeout=6.0):
    """Wait until the given addresses leave the DAD (tentative) state. Returns the set that is usable."""
    import time
    want, ok = set(ips), set()
    end = time.time() + timeout
    while True:
        for i in list_interfaces():
            if i.if_index == if_index and i.ip in want and i.dad == 4:
                ok.add(i.ip)
        if ok >= want or time.time() >= end:
            return ok
        time.sleep(0.3)


if __name__ == "__main__":
    for i in list_interfaces():
        print(("UP   " if i.up else "DOWN ") + i.label(), i.mac)
