# netkit/dns_sink.py — answers every DNS A query with one IP.
# Pair with the router's DHCP DNS override so each new device reports to this box.
import argparse
import socket


def build_response(data, spoof_ip):
    """Minimal DNS responder: A/ANY -> spoof_ip, everything else -> empty."""
    if len(data) < 12:
        return None
    i = 12
    while i < len(data) and data[i] != 0:
        i += data[i] + 1
    if i + 5 > len(data):
        return None
    qtype = int.from_bytes(data[i + 1:i + 3], "big")
    qclass = int.from_bytes(data[i + 3:i + 5], "big")
    question = data[12:i + 5]

    answer = b""
    ancount = 0
    if qtype in (1, 255) and qclass == 1:
        answer = (
            b"\xc0\x0c"                      # name: pointer to question
            b"\x00\x01"                      # type A
            b"\x00\x01"                      # class IN
            + (30).to_bytes(4, "big")        # ttl
            + b"\x00\x04"                    # rdlength
            + socket.inet_aton(spoof_ip)
        )
        ancount = 1

    header = (
        data[0:2]                            # same transaction id
        + b"\x81\x80"                        # qr=1 rd=1 ra=1, rcode=0
        + (1).to_bytes(2, "big")             # qdcount
        + ancount.to_bytes(2, "big")         # ancount
        + (0).to_bytes(2, "big")             # nscount
        + (0).to_bytes(2, "big")             # arcount
    )
    return header + question + answer


def qname(data):
    i = 12
    labels = []
    while i < len(data) and data[i] != 0:
        n = data[i]
        labels.append(data[i + 1:i + 1 + n].decode(errors="replace"))
        i += n + 1
    return ".".join(labels) or "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", required=True, help="answer every A query with this address")
    ap.add_argument("--port", type=int, default=53)
    args = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", args.port))
    print("[dns] listening on :%d, every A query -> %s" % (args.port, args.ip))

    while True:
        try:
            data, addr = s.recvfrom(4096)
        except OSError:
            continue
        resp = build_response(data, args.ip)
        if not resp:
            continue
        s.sendto(resp, addr)
        print("[dns] %s asked for %s" % (addr[0], qname(data)))


if __name__ == "__main__":
    main()
