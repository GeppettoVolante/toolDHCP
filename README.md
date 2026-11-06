# toolDHCP

Small Windows tool that hands out an IP address to **factory-fresh network devices** (no IP configured) answering their BOOTP/DHCP request. Handy on the bench when you have to commission industrial devices (sensors, drives, I/O modules...) that ship without an address and you don't want to install a full DHCP server or an old vendor utility.

- **Status:** working, tested on a real bench (v1.0)
- **Platform:** Windows, Python 3.11+ (standard library only, no dependencies)
- **License:** MIT

## How it works
1. Pick the network interface at startup (IPv4 only; /32 and link-local are filtered out).
2. The tool **listens passively** and lists every MAC that asks for an address, with the vendor resolved from the official IEEE OUI registry.
3. Select a MAC, type the IP (and optionally mask/gateway), click **Arm**. From then on the tool answers every BOOTP or DHCP request from that MAC until you disarm it. Several MACs can be armed at once.

Lease is infinite (`0xFFFFFFFF`, RFC 2131 sec. 3.3). Only devices without an IP are handled for now.

## Usage
- **Portable exe:** download `toolDHCP.exe` from the [Releases](../../releases) page (check the SHA-256 in the notes). The exe is not code-signed, so SmartScreen/antivirus may complain.
- **From source:** `python src\gui.py`
- **CLI (single MAC):** `python src\server.py --bind <PC IP> --mac <MAC> --ip <IP> --mask <mask>`
- **Tests:** from `src\`: `python -m unittest discover -s tests`
- **Build the exe:** `pip install pyinstaller`, then `.\build_exe.ps1` (output in `build-out\dist\`)
- **Refresh the vendor table:** `python tools\update_oui.py`

## Requirements and gotchas
- The PC needs a **static IP** on the selected interface (it is also used as DHCP server-id).
- On first start Windows asks for a firewall exception for UDP 67: allow it on private networks.
- Stop any other BOOTP/DHCP server first (vendor BOOTP utilities, Internet Connection Sharing, the DHCP Server service), otherwise port 67 is busy.

## Layout
- `src/bootp.py` packet parse/build · `src/server.py` responder + socket loop · `src/netif.py` interfaces via ctypes · `src/oui.py` + `src/oui_data.py` vendor lookup (generated) · `src/gui.py` Tkinter GUI · `src/tests/` unit tests
- `tools/update_oui.py` regenerates `oui_data.py` from the IEEE MA-L registry

## Ideas / contributions welcome
See `todo.md` (Italian working notes). Open points: configurable finite lease, re-addressing devices that already have an IP (e.g. via CIP), manual MAC entry.

Protocol references: RFC 951 (BOOTP), RFC 2131 (DHCP), RFC 2132 (options), RFC 1542 (BOOTP/DHCP interoperability).
