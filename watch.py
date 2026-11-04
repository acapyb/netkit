# netkit/watch.py — polls the ARP table for devices joining the LAN.
# Scapy sweep optional; stdlib path works on bare Windows.
import argparse
import re
import subprocess
import sys
import time


ARP_LINE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})"
)


def arp_table():
    """Parse `arp -a`. Returns {ip: mac}. Skips multicast/broadcast noise."""
    out = subprocess.run(
        ["arp", "-a"], capture_output=True, text=True, errors="replace"
    ).stdout
    devs = {}
    for m in ARP_LINE.finditer(out):
        ip, mac = m.group(1), m.group(2).lower().replace(":", "-")
        if ip.startswith(("224.", "239.")) or ip.endswith(".255"):
            continue
        if mac == "ff-ff-ff-ff-ff-ff":
            continue
        devs[ip] = mac
    return devs


def sweep(subnet):
    """Active ARP sweep via scapy. Returns {ip: mac}; {} if scapy missing."""
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        return {}
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=2, verbose=0
    )
    return {r.psrc: r.hwsrc.lower().replace(":", "-") for _, r in ans}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=5.0, help="poll seconds")
    ap.add_argument("--sweep", default="", help="subnet CIDR for active ARP sweep")
    ap.add_argument(
        "--on-new",
        default="",
        help="command template on new device; {ip} and {mac} are substituted",
    )
    args = ap.parse_args()

    known = {}
    first = True
    print("[watch] interval=%ss sweep=%s" % (args.interval, args.sweep or "off"))
    while True:
        devs = dict(arp_table())
        if args.sweep:
            devs.update(sweep(args.sweep))
        stamp = time.strftime("%H:%M:%S")
        if first:
            known = dict(devs)
            first = False
            print("[watch] baseline: %d device(s)" % len(known))
        else:
            for ip, mac in devs.items():
                if ip not in known:
                    print("[watch] %s NEW %s  %s" % (stamp, ip, mac))
                    if args.on_new:
                        cmd = args.on_new.replace("{ip}", ip).replace("{mac}", mac)
                        print("[watch] hook: %s" % cmd)
                        subprocess.Popen(cmd, shell=True)
            for ip in list(known):
                if ip not in devs:
                    print("[watch] %s GONE %s" % (stamp, ip))
                    del known[ip]
            known.update(devs)
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
