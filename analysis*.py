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
                    
print("Q1:", ping_count)
print("Q2:", destination_ip)

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

print("Q3:", https_count)
print("Q4:", http_count)
print("Q5:", bestipAdress)


http_count_forever = 0
https_count_forever = 0
with open('http_forever.pcap', 'rb') as f:

      pcap = dpkt.pcap.Reader(f)

      for timestamp, buf in pcap:
          
          eth = dpkt.ethernet.Ethernet(buf) #parsing and decoding packet data into eth object

          if isinstance(eth.data, dpkt.ip.IP):
              
              ip = eth.data

              if isinstance(ip.data, dpkt.tcp.TCP):
                  
                  tcp = ip.data

                  if tcp.sport == 80 or tcp.dport == 80:
                    http_count_forever += 1

                  elif tcp.sport == 443 or tcp.dport == 443:
                    https_count_forever += 1

print("Q6:", http_count_forever)
print("Q7:", https_count_forever)
          

ftpControlPackets = 0
with open('ftp.pcap', 'rb') as f:

    pcap = dpkt.pcap.Reader(f)

    for timestamp, buf in pcap:

        eth = dpkt.ethernet.Ethernet(buf)

        if isinstance(eth.data, dpkt.ip.IP):

            ip = eth.data

            if isinstance(ip.data, dpkt.tcp.TCP):

                tcp = ip.data

                if tcp.sport == 21:
                    ipAdd = socket.inet_ntoa(ip.src)
                    ftpControlPackets += 1
                
                elif tcp.dport == 21:
                    ipAdd = socket.inet_ntoa(ip.dst)
                    ftpControlPackets += 1
        

print("Q8:", ipAdd)
print("Q9:", ftpControlPackets)


totalPakcets = 0
httpsPackets = 0
uniqueDst = 0
with open("tmz.pcap", "rb") as f:

    pcap = dpkt.pcap.Reader(f)
    dstAddresses = set()

    for timestamp, buf in pcap:

        totalPakcets += 1

        eth = dpkt.ethernet.Ethernet(buf)

        if isinstance(eth.data, dpkt.ip.IP):

            ip = eth.data
            raw_dst = ip.dst
            readable_dst = socket.inet_ntoa(raw_dst) #destination IP address

            if readable_dst not in dstAddresses:
                uniqueDst += 1
                dstAddresses.add(readable_dst)

            if isinstance(ip.data, dpkt.tcp.TCP):

                tcp = ip.data

                if tcp.sport == 443 or tcp.dport == 443:
                    httpsPackets += 1
                  


print("Q10:", totalPakcets)
print("Q11:", httpsPackets)
print("Q12:", uniqueDst)


'''
parsing PCAP file: https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/

for HTTP: the client dst is 80 and the server src is 80
for HTTPS: the client dst is 443 and the server src is 443



Port 21 is the official, standardized port that FTP servers use for communication

'''