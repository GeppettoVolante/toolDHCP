"""toolDHCP - GUI (CustomTkinter, dark theme). Alternative to BootDHCP.

Flow: pick interface -> passive list of MACs asking for an IP -> select one, type an
IP -> "Arm": from then on the tool answers every BOOTP/DHCP request from that MAC.
With "Make permanent" the tool then switches the device to a static IP over
EtherNet/IP (CIP), so it keeps the address after the tool is closed.
Second tab: scan for devices that already have an IP and re-address them (CIP).
"""
import atexit
import ctypes
import ipaddress
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk

import customtkinter as ctk
from PIL import Image

import bootp
import cip
import netif
import oui
import server
import subnetscan

APP = "toolDHCP"
VERSION = "2.0"

# ---- palette: black / blue ----
BG = "#090D16"
HEADER = "#0D1424"
CARD = "#111A2E"
CARD2 = "#0E1626"
LINE = "#1E2B47"
ACCENT = "#2563EB"
ACCENT_HI = "#3B82F6"
CYAN = "#22D3EE"
TEXT = "#E6EAF2"
MUTED = "#8A97B1"
GREEN = "#34D399"
AMBER = "#FBBF24"
RED = "#F87171"

PERM_TEXT = {"-": "-", "pending": "pending...", "running": "writing...", "ok": "STATIC ✓",
             "written": "written (?)", "failed": "failed"}


def resource(name):
    base = getattr(sys, "_MEIPASS", None) or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    return os.path.normpath(os.path.join(base, "assets", name))


def validate_assignment(iface, mac, ip, mask, gw):
    """Return (errors, warnings, normalized_values). Pure function, unit-testable.
    mac=None skips the MAC check (devices whose MAC is not known)."""
    errors, warnings = [], []
    if mac is not None:
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


# ---------------- small dark dialog ----------------
class Dialog(ctk.CTkToplevel):
    def __init__(self, master, title, text, buttons=(("OK", True),), accent=ACCENT):
        super().__init__(master, fg_color=BG)
        self.title(title)
        self.result = None
        self.resizable(False, False)
        ctk.CTkLabel(self, text=title, font=("Segoe UI", 15, "bold"), text_color=TEXT,
                     anchor="w").pack(fill="x", padx=22, pady=(18, 4))
        ctk.CTkLabel(self, text=text, font=("Segoe UI", 12), text_color=MUTED, justify="left",
                     wraplength=440, anchor="w").pack(fill="x", padx=22, pady=(0, 14))
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=22, pady=(0, 18))
        for i, (label, val) in enumerate(reversed(buttons)):
            primary = i == len(buttons) - 1 or len(buttons) == 1
            ctk.CTkButton(row, text=label, width=100, height=32,
                          fg_color=accent if primary else "transparent",
                          hover_color=ACCENT_HI if primary else LINE,
                          border_width=0 if primary else 1, border_color=LINE,
                          command=lambda v=val: self._close(v)).pack(side="right", padx=(8, 0))
        self.update_idletasks()
        w, h = max(self.winfo_reqwidth(), 420), self.winfo_reqheight()
        x = master.winfo_rootx() + (master.winfo_width() - w) // 2
        y = master.winfo_rooty() + (master.winfo_height() - h) // 3
        self.geometry(f"{w}x{h}+{max(x, 0)}+{max(y, 0)}")
        self.protocol("WM_DELETE_WINDOW", lambda: self._close(None))
        self.after(250, self._icon)
        self.transient(master)
        self.after(50, self.grab_set)

    def _icon(self):
        try:
            self.iconbitmap(resource("icon.ico"))
        except tk.TclError:
            pass

    def _close(self, v):
        self.result = v
        self.destroy()


def ask(master, title, text, yes="OK", no="Cancel"):
    d = Dialog(master, title, text, ((no, False), (yes, True)))
    master.wait_window(d)
    return bool(d.result)


def notify(master, title, text, bad=False):
    d = Dialog(master, title, text, (("Close", True),), accent=RED if bad else ACCENT)
    master.wait_window(d)


class SweepDialog(ctk.CTkToplevel):
    """Search for devices on an unknown subnet (temporary IP aliases, needs administrator)."""

    def __init__(self, app):
        super().__init__(app, fg_color=BG)
        self.app = app
        self.title("Find device on another subnet")
        self.resizable(False, False)
        self.transient(app)
        ctk.CTkLabel(self, text="Find a device on an unknown subnet", font=("Segoe UI", 16, "bold"),
                     text_color=TEXT, anchor="w").pack(fill="x", padx=22, pady=(18, 2))
        ctk.CTkLabel(self, text=(f"For each subnet probed the tool temporarily adds an extra IP "
                                 f"(x.y.z.{subnetscan.ALIAS_HOST}) to '{app.iface.name}', asks "
                                 "who is there over EtherNet/IP, then removes it. Aliases of subnets "
                                 "where a device is found stay until you close the tool or switch "
                                 "interface. They are not saved: a reboot clears them."),
                     font=("Segoe UI", 12), text_color=MUTED, justify="left", wraplength=500,
                     anchor="w").pack(fill="x", padx=22, pady=(0, 10))
        self.chk = {}
        for name in subnetscan.PRESETS:
            v = tk.BooleanVar(value=name.startswith("192.168"))
            self.chk[name] = v
            ctk.CTkCheckBox(self, text=name, variable=v, fg_color=ACCENT, hover_color=ACCENT_HI,
                            text_color=TEXT, border_color=ACCENT_HI).pack(anchor="w", padx=26, pady=2)
        ctk.CTkLabel(self, text="Hints (optional), e.g. 10.20.30.0/24, 192.168.50.7 - probed first",
                     font=("Segoe UI", 11), text_color=MUTED, anchor="w").pack(fill="x", padx=22, pady=(10, 2))
        self.custom = tk.StringVar()
        ctk.CTkEntry(self, textvariable=self.custom, width=500, height=32, fg_color=CARD2,
                     border_color=LINE, text_color=TEXT).pack(padx=22)
        self.bar = ctk.CTkProgressBar(self, width=500, progress_color=ACCENT, fg_color=CARD2)
        self.bar.set(0)
        self.bar.pack(padx=22, pady=(14, 4))
        self.lbl = ctk.CTkLabel(self, text="", font=("Segoe UI", 12), text_color=MUTED, anchor="w",
                                wraplength=500, justify="left")
        self.lbl.pack(fill="x", padx=22)
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=22, pady=(10, 18))
        app.btn(row, "Close", self.close, primary=False, width=100).pack(side="right")
        self.go = app.btn(row, "Start search", self.start, width=130)
        self.go.pack(side="right", padx=8)
        self.update_idletasks()
        x = app.winfo_rootx() + max((app.winfo_width() - self.winfo_reqwidth()) // 2, 0)
        self.geometry(f"+{x}+{app.winfo_rooty() + 60}")
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.after(250, self._icon)

    def _icon(self):
        try:
            self.iconbitmap(resource("icon.ico"))
        except tk.TclError:
            pass

    def start(self):
        nets, errors = subnetscan.parse_nets(self.custom.get(), [n for n, v in self.chk.items() if v.get()])
        if errors:
            notify(self, "Cannot start", "\n".join(errors), bad=True)
            return
        if not nets:
            notify(self, "Cannot start", "Select at least one range or type a hint.", bad=True)
            return
        if not ask(self, "Confirm", f"{len(nets)} subnet(s) will be probed with temporary IPs on "
                                    f"'{self.app.iface.name}'. Continue?", "Start", "Cancel"):
            return
        self.go.configure(state="disabled")
        self.bar.set(0)
        self.lbl.configure(text="Adding temporary IPs and probing...", text_color=MUTED)
        self.app.start_sweep(nets)

    def progress(self, done, total, found):
        self.bar.set(done / total if total else 1)
        self.lbl.configure(text=f"{done}/{total} subnets probed, {found} device(s) found")

    def finished(self, text, bad=False):
        self.go.configure(state="normal")
        self.lbl.configure(text=text, text_color=RED if bad else GREEN)

    def close(self):
        self.app.sweep_stop.set()
        self.app.sweep_dlg = None
        self.destroy()


class App(ctk.CTk):
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        try:   # own taskbar identity (icon is not grouped under python.exe)
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("GeppettoVolante.toolDHCP")
        except Exception:
            pass
        super().__init__(fg_color=BG)
        self.title(f"{APP} {VERSION}")
        self.geometry("1040x740")
        self.minsize(920, 660)
        self.after(250, self._icon)
        self.iface = None
        self.resp = None
        self.sock = None
        self.thread = None
        self.ifaces = []
        self.stop_ev = threading.Event()
        self.logq = queue.Queue()
        self.evq = queue.Queue()
        self.perm = {}              # mac -> dict(auto, state, tries, next, armed_at)
        self.found = {}             # ip -> cip.Identity
        self.sweep_dlg = None
        self.sweep_stop = threading.Event()
        self.sweeping = False
        self._tick_id = None
        self._style_tree()
        try:
            self.logo = ctk.CTkImage(Image.open(resource("logo.png")), size=(42, 42))
        except OSError:
            self.logo = None
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.header = ctk.CTkFrame(self, fg_color=HEADER, corner_radius=0, height=68)
        self.header.pack(fill="x")
        self.header.pack_propagate(False)
        if self.logo:
            ctk.CTkLabel(self.header, image=self.logo, text="").pack(side="left", padx=(18, 10))
        box = ctk.CTkFrame(self.header, fg_color="transparent")
        box.pack(side="left")
        ctk.CTkLabel(box, text="toolDHCP", font=("Segoe UI", 21, "bold"), text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(box, text="BOOTP · DHCP · EtherNet/IP commissioning",
                     font=("Segoe UI", 11), text_color=CYAN).pack(anchor="w")
        self.chip = ctk.CTkLabel(self.header, text="", font=("Segoe UI", 12, "bold"), text_color=TEXT,
                                 fg_color=CARD, corner_radius=14, padx=14, pady=5)
        ctk.CTkFrame(self, fg_color=ACCENT, height=2, corner_radius=0).pack(fill="x")
        self.frame = None
        self.show_select()

    def _icon(self):
        try:
            self.iconbitmap(resource("icon.ico"))
        except tk.TclError:
            pass

    def _style_tree(self):
        st = ttk.Style(self)
        st.theme_use("clam")
        try:
            sc = ctk.ScalingTracker.get_window_scaling(self)
        except Exception:
            sc = 1.0
        st.configure("Dark.Treeview", background=CARD2, fieldbackground=CARD2, foreground=TEXT,
                     rowheight=int(28 * sc), borderwidth=0, font=("Segoe UI", 10),
                     bordercolor=CARD2, lightcolor=CARD2, darkcolor=CARD2)
        st.configure("Dark.Treeview.Heading", background=HEADER, foreground=MUTED, relief="flat",
                     font=("Segoe UI", 9, "bold"), padding=(6, 6), borderwidth=0)
        st.map("Dark.Treeview", background=[("selected", ACCENT)], foreground=[("selected", "white")])
        st.map("Dark.Treeview.Heading", background=[("active", LINE)])

    # ---------- helpers ----------
    def _swap(self):
        if self.frame is not None:
            self.frame.destroy()
        self.frame = ctk.CTkFrame(self, fg_color="transparent")
        self.frame.pack(fill="both", expand=True, padx=18, pady=14)
        return self.frame

    def card(self, parent, title=None):
        c = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=12, border_width=1, border_color=LINE)
        if title:
            ctk.CTkLabel(c, text=title, font=("Segoe UI", 12, "bold"), text_color=TEXT,
                         anchor="w").pack(fill="x", padx=14, pady=(10, 2))
        return c

    def make_tree(self, parent, cols, heads, widths, height=8):
        wrap = ctk.CTkFrame(parent, fg_color=CARD2, corner_radius=8, border_width=1, border_color=LINE)
        tree = ttk.Treeview(wrap, columns=cols, show="headings", height=height,
                            selectmode="browse", style="Dark.Treeview")
        for c, h, w in zip(cols, heads, widths):
            tree.heading(c, text=h, anchor="w")
            tree.column(c, width=w, anchor="w")
        sb = ctk.CTkScrollbar(wrap, command=tree.yview, fg_color=CARD2)
        tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y", padx=(0, 2), pady=4)
        tree.pack(side="left", fill="both", expand=True, padx=(4, 0), pady=4)
        tree.tag_configure("ok", foreground=GREEN)
        tree.tag_configure("warn", foreground=AMBER)
        tree.tag_configure("bad", foreground=RED)
        tree.tag_configure("dim", foreground=MUTED)
        return wrap, tree

    def entry(self, parent, label, var, width, col):
        ctk.CTkLabel(parent, text=label, font=("Segoe UI", 11), text_color=MUTED,
                     anchor="w").grid(row=0, column=col, sticky="w", padx=6)
        e = ctk.CTkEntry(parent, textvariable=var, width=width, height=32, fg_color=CARD2,
                         border_color=LINE, text_color=TEXT)
        e.grid(row=1, column=col, padx=6, pady=(0, 2))
        return e

    def btn(self, parent, text, cmd, primary=True, width=110):
        return ctk.CTkButton(parent, text=text, command=cmd, width=width, height=34,
                             fg_color=ACCENT if primary else "transparent",
                             hover_color=ACCENT_HI if primary else LINE,
                             border_width=0 if primary else 1, border_color=ACCENT_HI,
                             text_color=TEXT, font=("Segoe UI", 12, "bold"))

    # ---------- screen 1: interface selection ----------
    def show_select(self):
        self.chip.pack_forget()
        f = self._swap()
        c = self.card(f)
        c.pack(pady=(40, 0), ipadx=10, ipady=6)
        ctk.CTkLabel(c, text="Select the network interface connected to the devices",
                     font=("Segoe UI", 16, "bold"), text_color=TEXT).pack(anchor="w", padx=20, pady=(18, 2))
        ctk.CTkLabel(c, text="The PC needs a static IP on this adapter: it will also be the "
                             "BOOTP/DHCP server IP.", font=("Segoe UI", 12), text_color=MUTED,
                     justify="left").pack(anchor="w", padx=20, pady=(0, 14))
        self.cmb = ctk.CTkComboBox(c, state="readonly", width=760, height=36, values=[""],
                                   fg_color=CARD2, border_color=LINE, button_color=ACCENT,
                                   button_hover_color=ACCENT_HI, dropdown_fg_color=CARD2,
                                   text_color=TEXT, font=("Segoe UI", 12))
        self.cmb.pack(padx=20)
        self.msg = ctk.CTkLabel(c, text="", text_color=RED, font=("Segoe UI", 12))
        self.msg.pack(anchor="w", padx=20, pady=6)
        row = ctk.CTkFrame(c, fg_color="transparent")
        row.pack(anchor="w", padx=20, pady=(4, 16))
        self.btn(row, "Refresh list", self.refresh_ifaces, primary=False).pack(side="left")
        self.btn(row, "Start", self.start).pack(side="left", padx=10)
        self.refresh_ifaces()

    def set_ifaces(self, ifaces):
        self.ifaces = list(ifaces)
        labels = [i.label() for i in self.ifaces]
        self.cmb.configure(values=labels or [""])
        self.cmb.set(labels[0] if labels else "")

    def refresh_ifaces(self):
        err = ""
        try:
            ifs = netif.usable(netif.list_interfaces())
        except OSError as e:
            ifs, err = [], f"Error reading interfaces: {e}"
        ifs.sort(key=lambda i: i.link_local)   # non-link-local first
        self.set_ifaces(ifs)
        self.msg.configure(text=err or ("" if ifs else "No active interface with an IP address found."))

    def selected_iface(self):
        label = self.cmb.get()
        for i in self.ifaces:
            if i.label() == label:
                return i
        return None

    def start(self):
        iface = self.selected_iface()
        if iface is None:
            self.msg.configure(text="Select an interface.")
            return
        if iface.link_local and not ask(
                self, APP, "The interface has a link-local IP (169.254.x.x): the static IP "
                           "is probably missing. Continue anyway?", "Continue", "Cancel"):
            return
        try:
            sock = server.open_socket(iface.ip)
        except SystemExit as e:
            self.msg.configure(text=str(e).replace("\n", " "), wraplength=760, justify="left")
            return
        except OSError as e:
            self.msg.configure(text=f"Error opening socket: {e}")
            return
        self.iface, self.sock = iface, sock
        self.resp = server.Responder(iface.ip)
        self.perm.clear()
        self.found.clear()
        self.stop_ev.clear()
        self.thread = threading.Thread(
            target=server.serve, args=(sock, self.resp),
            kwargs=dict(stop=self.stop_ev.is_set, log=self.logq.put, timeout=0.3),
            daemon=True)
        self.thread.start()
        self.show_main()

    # ---------- screen 2: tabs ----------
    def show_main(self):
        f = self._swap()
        self.chip.configure(text=f"●  {self.iface.name}  {self.iface.ip}:67")
        self.chip.pack(side="right", padx=18)
        top = ctk.CTkFrame(f, fg_color="transparent")
        top.pack(fill="x")
        self.btn(top, "Change interface", self.change_iface, primary=False, width=140).pack(side="right")
        self.tabs = ctk.CTkTabview(f, fg_color=CARD, segmented_button_fg_color=CARD2,
                                   segmented_button_selected_color=ACCENT,
                                   segmented_button_selected_hover_color=ACCENT_HI,
                                   segmented_button_unselected_color=CARD2,
                                   segmented_button_unselected_hover_color=LINE,
                                   text_color=TEXT, border_width=1, border_color=LINE, corner_radius=12)
        self.tabs.pack(fill="both", expand=True, pady=(0, 8))
        t1 = self.tabs.add("Requests (BOOTP/DHCP)")
        t2 = self.tabs.add("Devices on network (EtherNet/IP)")
        self._build_requests(t1)
        self._build_devices(t2)

        self.log = ctk.CTkTextbox(f, height=130, fg_color="#080C14", border_width=1, border_color=LINE,
                                  text_color=TEXT, font=("Consolas", 12), state="disabled")
        self.log.pack(fill="x")
        for tag, col in (("armed", CYAN), ("ok", GREEN), ("warn", AMBER), ("bad", RED)):
            self.log._textbox.tag_configure(tag, foreground=col)
        self._tick_id = self.after(300, self.tick)

    def _build_requests(self, p):
        cols = ("mac", "vendor", "tipo", "n", "ultima", "stato", "ip", "static")
        heads = ("MAC", "Vendor", "Type", "Requests", "Last", "Status", "Armed IP", "Static IP")
        widths = (140, 170, 90, 70, 70, 130, 110, 100)
        wrap, self.tree = self.make_tree(p, cols, heads, widths, height=8)
        wrap.pack(fill="both", expand=True, pady=(4, 8))
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        form = self.card(p, "Assignment for the selected MAC")
        form.pack(fill="x")
        self.v_mac = tk.StringVar()
        self.v_ip = tk.StringVar(value=".".join(self.iface.ip.split(".")[:3]) + ".")
        self.v_mask = tk.StringVar(value=self.iface.mask)
        self.v_gw = tk.StringVar()
        self.v_perm = tk.BooleanVar(value=True)
        g = ctk.CTkFrame(form, fg_color="transparent")
        g.pack(fill="x", padx=8, pady=(2, 4))
        for col, (lbl, var, w) in enumerate((("MAC", self.v_mac, 170), ("IP", self.v_ip, 140),
                                             ("Subnet mask", self.v_mask, 140),
                                             ("Gateway (optional)", self.v_gw, 140))):
            self.entry(g, lbl, var, w, col)
        r2 = ctk.CTkFrame(form, fg_color="transparent")
        r2.pack(fill="x", padx=14, pady=(2, 12))
        ctk.CTkCheckBox(r2, text="Make permanent (switch the device to a static IP over EtherNet/IP)",
                        variable=self.v_perm, fg_color=ACCENT, hover_color=ACCENT_HI,
                        text_color=TEXT, border_color=ACCENT_HI).pack(side="left")
        self.btn(r2, "Disarm", self.disarm, primary=False, width=90).pack(side="right")
        self.btn(r2, "Make permanent now", self.perm_now, primary=False, width=170).pack(side="right", padx=8)
        self.btn(r2, "Arm", self.arm, width=90).pack(side="right")

    def _build_devices(self, p):
        bar = ctk.CTkFrame(p, fg_color="transparent")
        bar.pack(fill="x", pady=(2, 6))
        self.btn(bar, "Scan network", self.scan, width=130).pack(side="left")
        self.btn(bar, "Find on other subnet...", self.open_sweep, primary=False, width=190).pack(side="left", padx=(8, 0))
        self.scan_lbl = ctk.CTkLabel(bar, text="Scan: this subnet. Other subnet: temporary IPs, needs admin.",
                                     text_color=MUTED, font=("Segoe UI", 11))
        self.scan_lbl.pack(side="left", padx=12)
        cols = ("ip", "mac", "reach", "vid", "product", "rev", "serial")
        heads = ("IP", "MAC", "Reached", "Vendor ID", "Product", "Revision", "Serial")
        widths = (120, 140, 150, 70, 220, 70, 90)
        wrap, self.dtree = self.make_tree(p, cols, heads, widths, height=8)
        wrap.pack(fill="both", expand=True, pady=(0, 8))
        self.dtree.bind("<<TreeviewSelect>>", self.on_dev_select)

        form = self.card(p, "Re-address the selected device (writes a static IP into it)")
        form.pack(fill="x")
        self.d_cur = tk.StringVar()
        self.d_ip = tk.StringVar()
        self.d_mask = tk.StringVar(value=self.iface.mask)
        self.d_gw = tk.StringVar()
        g = ctk.CTkFrame(form, fg_color="transparent")
        g.pack(fill="x", padx=8, pady=(2, 4))
        cur = self.entry(g, "Current IP", self.d_cur, 140, 0)
        cur.configure(state="readonly")
        for col, (lbl, var, w) in enumerate((("New IP", self.d_ip, 140), ("Subnet mask", self.d_mask, 140),
                                             ("Gateway (optional)", self.d_gw, 140)), start=1):
            self.entry(g, lbl, var, w, col)
        r2 = ctk.CTkFrame(form, fg_color="transparent")
        r2.pack(fill="x", padx=14, pady=(2, 12))
        ctk.CTkLabel(r2, text="Configuration Control is set to static and the IP is written.",
                     text_color=MUTED, font=("Segoe UI", 11)).pack(side="left")
        self.btn(r2, "Set static IP", self.set_device_ip, width=140).pack(side="right")

    # ---------- requests tab ----------
    def on_select(self, _evt=None):
        sel = self.tree.selection()
        if sel:
            self.v_mac.set(sel[0])

    def arm(self):
        errors, warnings, vals = validate_assignment(
            self.iface, self.v_mac.get(), self.v_ip.get(), self.v_mask.get(), self.v_gw.get())
        if errors:
            notify(self, "Cannot arm", "\n".join(errors), bad=True)
            return
        if warnings and not ask(self, APP, "\n\n".join(warnings) + "\n\nArm anyway?", "Arm anyway"):
            return
        mac, ip, mask, gw = vals
        _, armed = self.resp.snapshot()       # same IP already given to another armed MAC?
        for m, a in armed.items():
            if a.ip == ip and m != mac:
                notify(self, "Cannot arm", f"IP {ip} is already armed for {m}.", bad=True)
                return
        self.resp.arm(mac, ip, mask, gw)
        auto = bool(self.v_perm.get())
        self.perm[mac] = dict(auto=auto, state="pending" if auto else "-", tries=0, next=0.0,
                              armed_at=time.time())
        self.append_log(f"[{time.strftime('%H:%M:%S')}] ARMED {mac} -> {ip} / {mask} gw={gw or '-'}"
                        + ("  (will be made permanent)" if auto else ""), "armed")
        self.refresh_tree()

    def disarm(self):
        try:
            mac = bootp.mac_to_str(bootp.mac_to_bytes(self.v_mac.get()))
        except ValueError:
            notify(self, "Cannot disarm", "Invalid MAC address", bad=True)
            return
        self.resp.disarm(mac)
        self.perm.pop(mac, None)
        self.append_log(f"[{time.strftime('%H:%M:%S')}] DISARMED {mac}")
        self.refresh_tree()

    def perm_now(self):
        try:
            mac = bootp.mac_to_str(bootp.mac_to_bytes(self.v_mac.get()))
        except ValueError:
            notify(self, "Make permanent", "Select a MAC first.", bad=True)
            return
        seen, armed = self.resp.snapshot()
        st = {s.mac: s for s in seen}.get(mac)
        if mac not in armed or st is None or st.status not in ("BOOTP replied", "ACK"):
            notify(self, "Make permanent",
                   "The device must be armed and must already have taken the IP "
                   "(status 'BOOTP replied' or 'ACK').", bad=True)
            return
        p = self.perm.setdefault(mac, dict(auto=False, state="-", tries=0, next=0.0, armed_at=0.0))
        if p["state"] == "running":
            return
        p.update(auto=False, tries=0)
        self._start_perm(mac, armed[mac])

    def _start_perm(self, mac, a):
        p = self.perm[mac]
        p["state"] = "running"
        p["tries"] += 1
        self.logq.put(f"[{time.strftime('%H:%M:%S')}] {mac}: writing static IP over EtherNet/IP "
                      f"(attempt {p['tries']})...")
        bind = self.iface.ip

        def work():
            res = cip.make_static(a.ip, a.ip, a.mask, a.gateway, expect_mac=mac, bind_ip=bind)
            self.evq.put(("perm_done", mac, res))

        threading.Thread(target=work, daemon=True).start()

    def check_permanent(self):
        seen, armed = self.resp.snapshot()
        st = {s.mac: s for s in seen}
        now = time.time()
        for mac, p in list(self.perm.items()):
            a, s = armed.get(mac), st.get(mac)
            if not (p["auto"] and p["state"] == "pending" and a and s):
                continue
            if s.status in ("BOOTP replied", "ACK") and s.last > p["armed_at"] \
                    and now - s.last >= 2.0 and now >= p["next"]:
                self._start_perm(mac, a)

    def on_event(self, ev):
        kind = ev[0]
        if kind == "perm_done":
            _, mac, res = ev
            p = self.perm.get(mac)
            for m in res.messages:
                self.append_log(f"    {mac}: {m}", "ok" if res.ok else "warn")
            if p is None:
                return
            if res.ok:
                p["state"] = "ok" if res.verified else "written"
                self.append_log(f"[{time.strftime('%H:%M:%S')}] {mac}: STATIC IP written"
                                + (" and verified" if res.verified else " (not verified)"), "ok")
            elif res.retryable and p["auto"] and p["tries"] < 3:
                p["state"], p["next"] = "pending", time.time() + 3.0
            else:
                p["state"] = "failed"
                self.append_log(f"[{time.strftime('%H:%M:%S')}] {mac}: could not make it permanent", "bad")
        elif kind == "scan_done":
            _, items = ev
            self.found = {ip: d for ip, d in self.found.items() if d.via and d.via in netif.aliases()}
            self.found.update({i.ip: i for i in items})
            self.scan_lbl.configure(text=f"{len(items)} device(s) found on this subnet.")
            self.refresh_devices()
            for i in items:
                threading.Thread(target=self._read_mac, args=(i.ip,), daemon=True).start()
        elif kind == "sweep_progress":
            if self.sweep_dlg is not None:
                self.sweep_dlg.progress(*ev[1:])
        elif kind == "sweep_done":
            _, items, err = ev
            self.sweeping = False
            for i in items:
                self.found[i.ip] = i
            self.refresh_devices()
            for i in items:
                threading.Thread(target=self._read_mac, args=(i.ip,), daemon=True).start()
            msg = err or f"Search finished: {len(items)} device(s) found."
            if items:
                msg += " Select one below to re-address it."
            self.scan_lbl.configure(text=msg)
            if self.sweep_dlg is not None:
                self.sweep_dlg.finished(msg, bad=bool(err))
        elif kind == "mac":
            _, ip, mac = ev
            if ip in self.found:
                self.found[ip].mac = mac
                self.refresh_devices()
        elif kind == "set_done":
            _, ip, res = ev
            for m in res.messages:
                self.append_log(f"    {ip}: {m}", "ok" if res.ok else "warn")
            self.append_log(f"[{time.strftime('%H:%M:%S')}] {ip}: " +
                            ("static IP written" + (" and verified" if res.verified else " (not verified)")
                             if res.ok else "FAILED, nothing changed or device refused"),
                            "ok" if res.ok else "bad")

    def append_log(self, line, tag=None):
        if tag is None:
            low = line.lower()
            tag = "bad" if ("error" in low or "refused" in low) else None
        self.log.configure(state="normal")
        self.log.insert("end", line + "\n", tag) if tag else self.log.insert("end", line + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

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
            p = self.perm.get(mac, {"state": "-"})["state"]
            if p == "ok":
                tag = "ok"
            elif p in ("failed",) or s.status == "NAK":
                tag = "bad"
            elif p in ("pending", "running", "written") or s.status == "waiting":
                tag = "warn"
            elif a is None:
                tag = "dim"
            else:
                tag = "ok"
            self.tree.insert("", "end", iid=mac, tags=(tag,), values=(
                mac, oui.vendor(mac), s.kind or "-", s.count, last, s.status,
                a.ip if a else "-", PERM_TEXT.get(p, p)))
        if sel and self.tree.exists(sel[0]):
            self.tree.selection_set(sel[0])

    # ---------- devices tab ----------
    def scan(self):
        self.scan_lbl.configure(text="Scanning...")
        iface = self.iface
        targets = [str(iface.network.broadcast_address), "255.255.255.255"]

        def work():
            try:
                items = cip.list_identity(iface.ip, targets)
            except OSError:
                items = []
            self.evq.put(("scan_done", items))

        threading.Thread(target=work, daemon=True).start()

    def _read_mac(self, ip):
        try:
            via = self.found[ip].via if ip in self.found else ""
            with cip.Client(ip, via or self.iface.ip, timeout=2.0) as c:
                self.evq.put(("mac", ip, c.read_mac()))
        except (cip.CipError, AttributeError):
            pass

    def refresh_devices(self):
        sel = self.dtree.selection()
        self.dtree.delete(*self.dtree.get_children())
        for ip, i in self.found.items():
            self.dtree.insert("", "end", iid=ip, values=(
                ip, i.mac or "...", f"alias {i.via}" if i.via else "same subnet",
                i.vendor_id, i.product_name, i.revision, i.serial))
        if sel and self.dtree.exists(sel[0]):
            self.dtree.selection_set(sel[0])

    def on_dev_select(self, _evt=None):
        sel = self.dtree.selection()
        if sel:
            self.d_cur.set(sel[0])
            if not self.d_ip.get():
                self.d_ip.set(".".join(self.iface.ip.split(".")[:3]) + ".")

    def set_device_ip(self):
        cur = self.d_cur.get().strip()
        if not cur or cur not in self.found:
            notify(self, "Set static IP", "Scan the network and select a device first.", bad=True)
            return
        errors, warnings, vals = validate_assignment(
            self.iface, None, self.d_ip.get(), self.d_mask.get(), self.d_gw.get())
        if any(vals[1] == i for i in self.found if i != cur):
            errors.append(f"{vals[1]} is already used by another device found.")
        if errors:
            notify(self, "Set static IP", "\n".join(errors), bad=True)
            return
        _, ip, mask, gw = vals
        dev = self.found[cur]
        text = (f"Write a STATIC configuration into the device:\n\n"
                f"{dev.product_name}  (MAC {dev.mac or 'unknown'})\n"
                f"{cur}  ->  {ip} / {mask}  gw {gw or '-'}\n\n"
                + ("\n".join(warnings) + "\n\n" if warnings else "")
                + "The device stops using BOOTP/DHCP and keeps this address.")
        if not ask(self, "Confirm", text, "Write to device", "Cancel"):
            return
        real = self.iface.ip
        bind = dev.via or real
        mac = dev.mac or None
        self.append_log(f"[{time.strftime('%H:%M:%S')}] {cur}: writing static IP {ip}"
                        + (f" (via alias {dev.via})" if dev.via else "") + "...", "armed")

        def work():
            res = cip.make_static(cur, ip, mask, gw, expect_mac=mac, bind_ip=bind, verify_bind_ip=real)
            if res.ok and dev.via:
                netif.remove_alias(dev.via)      # no longer needed: the device left that subnet
            self.evq.put(("set_done", ip if res.ok else cur, res))

        threading.Thread(target=work, daemon=True).start()

    # ---------- unknown subnet search ----------
    def open_sweep(self):
        if self.sweeping or (self.sweep_dlg is not None and self.sweep_dlg.winfo_exists()):
            return
        if not netif.is_admin():
            if ask(self, "Administrator rights needed",
                   "Adding temporary IPs to the adapter needs administrator rights.\n\n"
                   "Restart toolDHCP as administrator? (Windows will ask for confirmation.)",
                   "Restart as admin", "Cancel"):
                self.restart_admin()
            return
        self.sweep_dlg = SweepDialog(self)

    def restart_admin(self):
        if getattr(sys, "frozen", False):
            exe, params = sys.executable, ""
        else:
            exe, params = sys.executable, f'"{os.path.abspath(__file__)}"'
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        if rc > 32:
            self.on_close()

    def start_sweep(self, nets):
        netif.remove_all_aliases()
        self.found = {ip: d for ip, d in self.found.items() if not d.via}
        self.sweep_stop.clear()
        self.sweeping = True
        iface = self.iface

        def work():
            err = ""
            items = []
            try:
                items = subnetscan.sweep(
                    iface, nets, log=self.logq.put, stop=self.sweep_stop.is_set,
                    progress=lambda d, t, f: self.evq.put(("sweep_progress", d, t, f)))
            except OSError as e:
                err = str(e)
            self.evq.put(("sweep_done", items, err))

        threading.Thread(target=work, daemon=True).start()

    # ---------- loop / shutdown ----------
    def tick(self):
        if self.resp is None:
            return
        try:
            while True:
                self.append_log(self.logq.get_nowait())
        except queue.Empty:
            pass
        try:
            while True:
                self.on_event(self.evq.get_nowait())
        except queue.Empty:
            pass
        self.check_permanent()
        self.refresh_tree()
        self._tick_id = self.after(500, self.tick)

    def stop_server(self):
        if self._tick_id:
            self.after_cancel(self._tick_id)
            self._tick_id = None
        self.stop_ev.set()
        self.sweep_stop.set()
        netif.remove_all_aliases()
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
    atexit.register(netif.remove_all_aliases)
    App().mainloop()


if __name__ == "__main__":
    main()
