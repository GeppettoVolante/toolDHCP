# toolDHCP

Small Windows tool that hands out an IP address to **factory-fresh network devices** (no IP configured) answering their BOOTP/DHCP request. Handy on the bench when you have to commission industrial devices (sensors, drives, I/O modules...) that ship without an address and you don't want to install a full DHCP server or an old vendor utility.

- **Status:** v2.0, tested by the author on real EtherNet/IP devices on the bench (permanent static IP, scan and re-address, search on an unknown subnet)
- **Platform:** Windows, Python 3.11+. The core (BOOTP/DHCP, CIP) is standard library only; the GUI needs `customtkinter` and `pillow`
- **License:** MIT

## How it works
1. Pick the network interface at startup (IPv4 only; /32 and link-local are filtered out).
2. The tool **listens passively** and lists every MAC that asks for an address, with the vendor resolved from the official IEEE OUI registry.
3. Select a MAC, type the IP (and optionally mask/gateway), click **Arm**. From then on the tool answers every BOOTP or DHCP request from that MAC until you disarm it. Several MACs can be armed at once.

Lease is infinite (`0xFFFFFFFF`, RFC 2131 sec. 3.3).

**Make permanent (v2.0).** A device left in BOOTP/DHCP mode asks again after a power cycle (or when the tool is closed and its request times out) and loses the address. With *Make permanent* ticked, once the device has taken the IP the tool opens an EtherNet/IP session (TCP 44818) and writes the TCP/IP Interface Object (class 0xF5): Configuration Control = static, then Interface Configuration = IP/mask/gateway (the MAC is checked first; name servers are kept). It then reads the values back. This is what the vendor "Disable BOOTP/DHCP" button does.

**Devices on network (v2.0).** *Scan network* sends a ListIdentity broadcast (UDP 44818) and lists the devices that already have an IP; select one and *Set static IP* to re-address it (same CIP write, with a confirmation dialog). Devices on the same subnet are found directly.

**Device on an unknown subnet (v2.0).** A device with a static IP in a subnet the PC is not in cannot answer (no route back). *Find on other subnet...* temporarily adds to the adapter an extra IP `x.y.z.250/24` (non-persistent, `AddIPAddress`) for every candidate subnet (presets 192.168.x.x, 10.0.x.x, 172.16.x.x, 169.254.x.x and/or typed hints), probes them in parallel with ListIdentity and removes the aliases again. The alias of a subnet where a device is found stays, so the CIP write can reach it, and is removed after the write or when the tool is closed. **Needs administrator rights**: the tool offers to restart itself elevated (UAC prompt). Aliases are not saved: a reboot clears them even if the tool crashes. Limit: 2048 subnets per search.

## Usage
- **Portable build:** download the `.zip` from the [Releases](../../releases) page (check the SHA-256 in the notes), extract it and run `toolDHCP.exe`. It is a folder build (PyInstaller onedir: nothing is unpacked to `%TEMP%`, which antivirus products like better), but it is not code-signed, so SmartScreen/antivirus may still complain.
- **From source:** `pip install customtkinter pillow`, then `python src\gui.py`
- **CLI (single MAC):** `python src\server.py --bind <PC IP> --mac <MAC> --ip <IP> --mask <mask>`
- **Tests:** from `src\`: `python -m unittest discover -s tests`
- **Build the exe:** `pip install pyinstaller`, then `.\build_exe.ps1` (output in `build-out\dist\`)
- **Refresh the vendor table:** `python tools\update_oui.py`

## Requirements and gotchas
- The PC needs a **static IP** on the selected interface (it is also used as DHCP server-id).
- On first start Windows asks for a firewall exception for UDP 67: allow it on private networks.
- Stop any other BOOTP/DHCP server first (vendor BOOTP utilities, Internet Connection Sharing, the DHCP Server service), otherwise port 67 is busy.

## Layout
- `src/bootp.py` packet parse/build · `src/server.py` responder + socket loop · `src/netif.py` interfaces via ctypes · `src/oui.py` + `src/oui_data.py` vendor lookup (generated) · `src/cip.py` EtherNet/IP client (ListIdentity, make static) · `src/gui.py` CustomTkinter GUI · `assets/` logo and icons · `src/tests/` unit tests
- `tools/update_oui.py` regenerates `oui_data.py` from the IEEE MA-L registry

## Ideas / contributions welcome
Open points: configurable finite lease, manual MAC entry, re-addressing devices on another subnet, other protocols (not planned).

Protocol references: RFC 951 (BOOTP), RFC 2131 (DHCP), RFC 2132 (options), RFC 1542 (BOOTP/DHCP interoperability); ODVA CIP/EtherNet/IP specification (TCP/IP Interface Object).
