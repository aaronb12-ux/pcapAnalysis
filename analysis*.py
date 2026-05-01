# For each packet in the pcap process the contents
import dpkt
import socket

http = 0
with open('example_dot_com.pcap', 'rb') as f:

    pcap = dpkt.pcap.Reader(f)

    for timestamp, buf in pcap: #parsing packet data into a more friendly, usable form

        eth = dpkt.ethernet.Ethernet(buf) #parsing and decoding packet data into eth object

        if isinstance(eth.data, dpkt.ip.IP):

            ip = eth.data
            tcp = ip.data

            print(ip)
            print(tcp.sport)
            print(tcp.dport)

            print("\n")
            
            if tcp.dport == 80 and len(tcp.data) > 0:
                http += 1


    
'''
parsing PCAP file: https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/



'''