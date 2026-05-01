# For each packet in the pcap process the contents
import dpkt
import socket
from collections import defaultdict

#Questions 1 - 2 
ping_count = 0
destination_ip = None
with open('google_pings.pcap', 'rb') as f:

    pcap = dpkt.pcap.Reader(f)

    for timestamp, buf in pcap:

        eth = dpkt.ethernet.Ethernet(buf)

        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        
        ip = eth.data

        if ip.p == dpkt.ip.IP_PROTO_ICMP:

            if isinstance(ip.data, dpkt.icmp.ICMP):
            
                icmp = ip.data

           
                if icmp.type == 8:
                    ping_count += 1
                    destination_ip = socket.inet_ntoa(ip.dst) #destination IP address
                    
print("Question 1:", ping_count)
print("Question 2:", destination_ip)

#Questions 3 - 5
http_count = 0
https_count = 0
with open('example_dot_com.pcap', 'rb') as f:

    dstIpAdressCount = defaultdict(int)
    maxDstIpAdress = 0
    bestipAdress = None
  
    pcap = dpkt.pcap.Reader(f)

    for timestamp, buf in pcap: #parsing packet data into a more friendly, usable form

        eth = dpkt.ethernet.Ethernet(buf) #parsing and decoding packet data into eth object

        if isinstance(eth.data, dpkt.ip.IP): #checking if IP is an instance of eth.data

            ip = eth.data
            raw_dst = ip.dst
            readable_dst = socket.inet_ntoa(raw_dst) #destination IP address
            dstIpAdressCount[readable_dst] += 1

            if not isinstance(ip.data, dpkt.tcp.TCP): #checking TCP is an instance of ip.data
                continue

            tcp = ip.data

            if tcp.sport == 80 or tcp.dport == 80:
                http_count += 1

            elif tcp.sport == 443 or tcp.dport == 443:
                https_count += 1

        else:
            continue

for ipAdress in dstIpAdressCount:

    if dstIpAdressCount[ipAdress] > maxDstIpAdress:

        maxDstIpAdress = dstIpAdressCount[ipAdress]
        bestipAdress = ipAdress

print("Question 3:", http_count)
print("Question 4:", https_count)
print("Question 5:", bestipAdress)


'''
parsing PCAP file: https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/

for HTTP: the client dst is 80 and the server src is 80
for HTTPS: the client dst is 443 and the server src is 443

'''