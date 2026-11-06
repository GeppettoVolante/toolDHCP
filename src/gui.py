"""toolDHCP - Tkinter GUI (stdlib only). Alternative to BootDHCP.

Flow: pick interface -> passive list of MACs asking for an IP ->
select one, type an IP -> "Arma" (arm): from then on the tool answers every
request from that MAC (BOOTP or DHCP) until it is disarmed or the app is closed.
"""
import ipaddress
import queue
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

import bootp
import netif
import oui
import server

APP = "toolDHCP"


def validate_assignment(iface, mac, ip, mask, gw):
    """Return (errors, warnings, normalized_values). Pure function, unit-testable."""
    errors, warnings = [], []
    try:
        mac = bootp.mac_to_str(bootp.mac_to_bytes(mac))
    except ValueError:
        errors.append("Invalid MAC address")
    try:
        ipa = ipaddress.IPv4Address(ip.strip())
    except ValueError:
        errors.append("Invalid IP address")
        ipa = None
    try:
        mk = ipaddress.IPv4Address(mask.strip())
        bits = bin(int(mk))[2:].zfill(32)
        if "01" in bits or int(mk) == 0:
            errors.append("Invalid subnet mask")
    except ValueError:
        errors.append("Invalid subnet mask")
        mk = None
    gwa = None
    if gw.strip():
        try:
            gwa = ipaddress.IPv4Address(gw.strip())
        except ValueError:
            errors.append("Invalid gateway address")
    if ipa is not None and not errors:
        if str(ipa) == iface.ip:
            errors.append("The assigned IP is the same as the PC's IP")
        net = ipaddress.IPv4Network(f"{ipa}/{mk}", strict=False)
        if ipa == net.network_address or ipa == net.broadcast_address:
            errors.append("The IP is the network or broadcast address")
        if ipa not in iface.network:
            warnings.append(f"{ipa} is outside the interface subnet ({iface.network}): "
                            "the device will not be reachable from the PC without routing.")
        if gwa is not None and gwa not in net:
            warnings.append(f"The gateway {gwa} is outside the assigned subnet.")
    vals = (mac, str(ipa) if ipa else "", str(mk) if mk else "", str(gwa) if gwa else None)
    return errors, warnings, vals


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP)
        self.geometry("860x560")
        self.minsize(720, 460)
        self.iface = None
        self.resp = None
        self.sock = None
        self.thread = None
        self.stop_ev = threading.Event()
        self.logq = queue.Queue()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.frame = None
        self.show_select()

    # ---------- screen 1: interface selection ----------
    def _swap(self):
        if self.frame is not None:
            self.frame.destroy()
        self.frame = ttk.Frame(self, padding=14)
        self.frame.pack(fill="both", expand=True)
        return self.frame

    def show_select(self):
        f = self._swap()
        ttk.Label(f, text="Select the network interface connected to the devices",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(f, text="The PC needs a static IP on this adapter: "
                          "it will also be the BOOTP/DHCP server IP.").pack(anchor="w", pady=(2, 10))
        self.cmb = ttk.Combobox(f, state="readonly", width=100)
        self.cmb.pack(fill="x")
        self.msg = ttk.Label(f, foreground="#a00")
        self.msg.pack(anchor="w", pady=6)
        row = ttk.Frame(f)
        row.pack(anchor="w", pady=8)
        ttk.Button(row, text="Refresh list", command=self.refresh_ifaces).pack(side="left")
        ttk.Button(row, text="Start", command=self.start).pack(side="left", padx=8)
        self.refresh_ifaces()

    def refresh_ifaces(self):
        try:
            self.ifaces = netif.usable(netif.list_interfaces())
        except OSError as e:
            self.ifaces = []
            self.msg.config(text=f"Error reading interfaces: {e}")
        # non-link-local first
        self.ifaces.sort(key=lambda i: i.link_local)
        self.cmb["values"] = [i.label() for i in self.ifaces]
        if self.ifaces:
            self.cmb.current(0)
            if not self.msg.cget("text").startswith("Error"):
                self.msg.config(text="")
        else:
            self.cmb.set("")
            if not self.msg.cget("text"):
                self.msg.config(text="No active interface with an IP address found.")

    def start(self):
        idx = self.cmb.current()
        if idx < 0:
            self.msg.config(text="Select an interface.")
            return
        iface = self.ifaces[idx]
        if iface.link_local and not messagebox.askyesno(
                APP, "The interface has a link-local IP (169.254.x.x): the static IP "
                     "is probably missing. Continue anyway?"):
            return
        try:
            sock = server.open_socket(iface.ip)
        except SystemExit as e:
            self.msg.config(text=str(e))
            return
        except OSError as e:
            self.msg.config(text=f"Error opening socket: {e}")
            return
        self.iface, self.sock = iface, sock
        self.resp = server.Responder(iface.ip)
        self.stop_ev.clear()
        self.thread = threading.Thread(
            target=server.serve, args=(sock, self.resp),
            kwargs=dict(stop=self.stop_ev.is_set, log=self.logq.put, timeout=0.3),
            daemon=True)
        self.thread.start()
        self.show_main()

    # ---------- screen 2: MAC list and assignment ----------
    def show_main(self):
        f = self._swap()
        top = ttk.Frame(f)
        top.pack(fill="x")
        ttk.Label(top, text=f"Listening on {self.iface.name} - {self.iface.ip}:67",
                  font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Button(top, text="Change interface", command=self.change_iface).pack(side="right")

        cols = ("mac", "vendor", "tipo", "n", "ultima", "stato", "ip")
        heads = ("MAC", "Vendor", "Type", "Requests", "Last", "Status", "Armed IP")
        widths = (140, 140, 90, 70, 70, 130, 110)
        self.tree = ttk.Treeview(f, columns=cols, show="headings", height=9, selectmode="browse")
        for c, h, w in zip(cols, heads, widths):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, pady=8)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        form = ttk.LabelFrame(f, text="Assignment for the selected MAC", padding=8)
        form.pack(fill="x")
        self.v_mac = tk.StringVar()
        self.v_ip = tk.StringVar(value=".".join(self.iface.ip.split(".")[:3]) + ".")
        self.v_mask = tk.StringVar(value=self.iface.mask)
        self.v_gw = tk.StringVar()
        for col, (lbl, var, w) in enumerate((("MAC", self.v_mac, 18), ("IP", self.v_ip, 15),
                                             ("Subnet mask", self.v_mask, 15),
                                             ("Gateway (opt.)", self.v_gw, 15))):
            ttk.Label(form, text=lbl).grid(row=0, column=col, sticky="w", padx=4)
            ttk.Entry(form, textvariable=var, width=w).grid(row=1, column=col, padx=4)
        ttk.Button(form, text="Arm", command=self.arm).grid(row=1, column=4, padx=(12, 4))
        ttk.Button(form, text="Disarm", command=self.disarm).grid(row=1, column=5, padx=4)
        ttk.Label(form, text="Armed = the tool answers every request from that MAC until you "
                             "disarm it.", foreground="#555").grid(row=2, column=0, columnspan=6,
                                                                     sticky="w", padx=4, pady=(6, 0))

        self.log = tk.Text(f, height=7, state="disabled", font=("Consolas", 9))
        self.log.pack(fill="both", expand=True, pady=(8, 0))
        self._tick_id = self.after(300, self.tick)

    def on_select(self, _evt=None):
        sel = self.tree.selection()
        if sel:
            self.v_mac.set(sel[0])

    def arm(self):
        errors, warnings, vals = validate_assignment(
            self.iface, self.v_mac.get(), self.v_ip.get(), self.v_mask.get(), self.v_gw.get())
        if errors:
            messagebox.showerror(APP, "\n".join(errors))
            return
        if warnings and not messagebox.askyesno(APP, "\n\n".join(warnings) + "\n\nArm anyway?"):
            return
        mac, ip, mask, gw = vals
        # same IP already given to another armed MAC?
        _, armed = self.resp.snapshot()
        for m, a in armed.items():
            if a.ip == ip and m != mac:
                messagebox.showerror(APP, f"IP {ip} is already armed for {m}.")
                return
        self.resp.arm(mac, ip, mask, gw)
        self.append_log(f"[{time.strftime('%H:%M:%S')}] ARMED {mac} -> {ip} / {mask}"
                        f" gw={gw or '-'}")
        self.refresh_tree()

    def disarm(self):
        try:
            mac = bootp.mac_to_str(bootp.mac_to_bytes(self.v_mac.get()))
        except ValueError:
            messagebox.showerror(APP, "Invalid MAC address")
            return
        self.resp.disarm(mac)
        self.append_log(f"[{time.strftime('%H:%M:%S')}] DISARMED {mac}")
        self.refresh_tree()

    def append_log(self, line):
        self.log.config(state="normal")
        self.log.insert("end", line + "\n")
        self.log.see("end")
        self.log.config(state="disabled")

    def refresh_tree(self):
        seen, armed = self.resp.snapshot()
        rows = {s.mac: s for s in seen}
        for m in armed:                       # armed but not seen yet
            rows.setdefault(m, server.Seen(m, status="waiting"))
        sel = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        for mac, s in sorted(rows.items()):
            a = armed.get(mac)
            last = time.strftime("%H:%M:%S", time.localtime(s.last)) if s.last else "-"
            self.tree.insert("", "end", iid=mac, values=(
                mac, oui.vendor(mac), s.kind or "-", s.count, last, s.status,
                a.ip if a else "-"))
        if sel and self.tree.exists(sel[0]):
            self.tree.selection_set(sel[0])

    def tick(self):
        if self.resp is None:
            return
        try:
            while True:
                self.append_log(self.logq.get_nowait())
        except queue.Empty:
            pass
        self.refresh_tree()
        self._tick_id = self.after(500, self.tick)

    # ---------- shutdown / interface change ----------
    def stop_server(self):
        if getattr(self, "_tick_id", None):
            self.after_cancel(self._tick_id)
            self._tick_id = None
        self.stop_ev.set()
        if self.thread is not None:
            self.thread.join(timeout=2)
        if self.sock is not None:
            self.sock.close()
        self.thread = self.sock = self.resp = None

    def change_iface(self):
        self.stop_server()
        self.show_select()

    def on_close(self):
        self.stop_server()
        self.destroy()


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
