import argparse
import os.path
import sys

from scapy.utils import RawPcapReader, PcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP

filePath = "H:\\exp_data\\pcap_data\\caida-50w-1.pcap"
filePath2 = "H:\\exp_data\\pcap_data\\caida-100w.pcap"
filePath3 = "H:\\exp_data\\pcap_data\\equinix-nyc.dirB.20190117-130000.UTC.anon.pcap"
filePath4 = "H:\\exp_data\\pcap_data\\univ1_all.pcap"
filePath5 = "/data/xgr/sketch_data/caida_dirA/equinix-nyc.dirA.20190117-130000.UTC.anon.pcap"
def getLen():
    temp_len = []
    for data in RawPcapReader(filePath3):
        i += 1
        # print(data.show())
        # print(len(data[0]))
        temp_len.append(len(data[0]))
        if i > 2000:
            break
        if len(data[0]) == 64:
            print(IP(data[0]).show())
    print(max(temp_len))
    print(min(temp_len))    
    print(list(set(temp_len)))
if __name__ == "__main__":
    i = 0
    for data in RawPcapReader(filePath5):
        i += 1
        ip_pkt_sc = IP(data[0])
        print(ip_pkt_sc.show())
        print(len(data[0]))
        print("version", ip_pkt_sc.version)
        print("ihl", ip_pkt_sc.ihl)
        print("tos", ip_pkt_sc.tos)
        print("len", ip_pkt_sc.len)
        print("id", ip_pkt_sc.id)
        print("flags", ip_pkt_sc.flags)
        # print(ip_pkt_sc.flags.show2())
        print("frag", ip_pkt_sc.frag)
        print("ttl", ip_pkt_sc.ttl)
        print("chksum", ip_pkt_sc.chksum)
        print("options", ip_pkt_sc.options)

        #tcp
        print()
        if ip_pkt_sc.haslayer('TCP'):
            tcp_pkt_sc = ip_pkt_sc[TCP]
            print("dataofs", tcp_pkt_sc.dataofs)
            print("flags", tcp_pkt_sc.flags)
            print("window", tcp_pkt_sc.window)
        if i > 10:
            break
    