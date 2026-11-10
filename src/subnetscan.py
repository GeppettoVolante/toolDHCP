"""Find EtherNet/IP devices on an UNKNOWN subnet.

Problem: a device with a static IP in a subnet the PC is not in cannot answer us
(it has no route back). Fix: temporarily add to the PC adapter an extra IP in the
candidate subnet (x.y.z.250/24, non-persistent), send ListIdentity from it, and
see who answers. Many candidates are probed in parallel: all the aliases of a batch
are added first, DAD is awaited once, then one socket per alias sends and listens.

Needs administrator rights (AddIPAddress). Aliases of subnets where a device was
found are kept (so the CIP write can go through); everything else is removed.
"""
import ipaddress

import cip
import netif

ALIAS_HOST = 250
PRESETS = {
    "192.168.x.x": "192.168.0.0/16",
    "10.0.x.x": "10.0.0.0/16",
    "172.16.x.x": "172.16.0.0/16",
    "169.254.x.x (link-local)": "169.254.0.0/16",
}
MAX_NETS = 2048


def parse_nets(text, presets=()):
    """Expand presets and a free-text list ('10.20.0.0/16, 192.168.50.7') into /24 networks.
    Custom entries come first. A single IP means its /24; a /16 or larger is expanded to
    its /24s (up to MAX_NETS in total). Returns (nets, errors)."""
    items = [t.strip() for t in text.replace(";", ",").replace("\n", ",").split(",") if t.strip()]
    items += [PRESETS[p] for p in presets if p in PRESETS]
    nets, seen, errors = [], set(), []
    for it in items:
        try:
            n = ipaddress.IPv4Network(it if "/" in it else f"{it}/24", strict=False)
        except ValueError:
            errors.append(f"Invalid network: {it}")
            continue
        if n.prefixlen < 16:
            errors.append(f"{it}: too large (use /16 or smaller)")
            continue
        subs = [n] if n.prefixlen >= 24 else list(n.subnets(new_prefix=24))
        if n.prefixlen > 24:
            subs = [ipaddress.IPv4Network(f"{n.network_address}/24", strict=False)]
        for sn in subs:
            if sn not in seen:
                seen.add(sn)
                nets.append(sn)
    if len(nets) > MAX_NETS:
        errors.append(f"{len(nets)} subnets requested, limit is {MAX_NETS}: narrow the list")
        nets = nets[:MAX_NETS]
    return nets, errors


def alias_ip(net):
    return str(net.network_address + ALIAS_HOST)


def sweep(iface, nets, log=print, progress=lambda done, total, found: None,
          stop=lambda: False, batch=96, listen=2.0,
          add=netif.add_alias, remove=netif.remove_alias, wait=netif.wait_preferred,
          scan=cip.list_identity_multi):
    """Probe `nets` from aliases on `iface`. Returns the list of cip.Identity found
    (each with .via = alias IP to use to reach it). Aliases of subnets with devices are kept."""
    own = {i.ip for i in netif.list_interfaces()} if add is netif.add_alias else set()
    todo = [n for n in nets if ipaddress.IPv4Address(iface.ip) not in n and alias_ip(n) not in own]
    found, done = [], 0
    for start in range(0, len(todo), batch):
        if stop():
            break
        chunk = todo[start:start + batch]
        added = {}
        for n in chunk:
            ip = alias_ip(n)
            try:
                add(iface.if_index, ip, "255.255.255.0")
                added[ip] = n
            except OSError as e:
                log(f"alias {ip}: {e}")
                if "administrator" in str(e):
                    for k in added:
                        remove(k)
                    raise
        usable = wait(iface.if_index, list(added), 6.0) if added else set()
        jobs = [(ip, [str(added[ip].broadcast_address), "255.255.255.255"]) for ip in added if ip in usable]
        hits = []
        if jobs and not stop():
            hits, _failed = scan(jobs, timeout=listen, stop=stop)
        keep = {h.via for h in hits}
        for ip in added:
            if ip not in keep:
                remove(ip)
        for h in hits:
            log(f"found {h.ip} ({h.product_name}) via alias {h.via}")
        found += hits
        done += len(chunk)
        progress(done, len(todo), len(found))
    progress(len(todo), len(todo), len(found))
    return found
