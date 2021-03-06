#!/usr/bin/env python3

"""pcap2csv
Script to extract specific pieces of information from a pcap file and
render into a csv file.
Usage: <program name> --pcap <input pcap file> --csv <output pcap file>
"""

import argparse
import os.path
import sys

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP

#--------------------------------------------------

def myrdpcap(filename, count=-1):
    """Read a pcap file and return a packet list
count: read only <count> packets"""
    pcap = RawPcapReader(filename)
    data = pcap.read_all(count=count)
    pcap.close() 
    return data

#--------------------------------------------------

def render_csv_row(timeInfo, pkt_sc, fh_csv):
    """Write one packet entry into the CSV file.
    pkt_sc is a 'bytes' representation of the packet as returned from
    scapy's RawPcapReader
    fh_csv is the csv file handle
    """
    # ether_pkt_sc = Ether(pkt_sc)
    # if ether_pkt_sc is None:
    #     return False

    # if not ether_pkt_sc.haslayer(IP):
    #     return False
    # ip_pkt_sc = ether_pkt_sc[IP]       # <<<< Assuming Ethernet + IPv4 here
    
    ip_pkt_sc = IP(pkt_sc)
    if ip_pkt_sc.version != 4:
        return False
    proto = ip_pkt_sc.fields['proto']
    if proto == 17 and ip_pkt_sc.haslayer('UDP'):
        udp_pkt_sc = ip_pkt_sc[UDP]
        l4_payload_bytes = bytes(udp_pkt_sc.payload)
        l4_proto_name = 'UDP'
        l4_sport = udp_pkt_sc.sport
        l4_dport = udp_pkt_sc.dport
    elif proto == 6 and ip_pkt_sc.haslayer('TCP'):
        tcp_pkt_sc = ip_pkt_sc[TCP]
        l4_payload_bytes = bytes(tcp_pkt_sc.payload)
        l4_proto_name = 'TCP'
        l4_sport = tcp_pkt_sc.sport
        l4_dport = tcp_pkt_sc.dport
    else:
        # Currently not handling packets that are not UDP or TCP
        # print('Ignoring non-UDP/TCP packet')
        return False
    srcIP = ip_pkt_sc.src
    dstIP = ip_pkt_sc.dst
    # length = len(pkt_sc)
    length = ip_pkt_sc.len
    # pkt_time = timeInfo.sec + timeInfo.usec / (10**6)
    pkt_time = 0
    # print("pkt_time", pkt_time)

    # Each line of the CSV has this format
    fmt = '{0}|{1}|{2}|{3}|{4}|{5}|{6}'
    # time srcIP srcPort dstIP dstPort protocol length

    print(fmt.format(pkt_time,                # {0}
                     srcIP,                   # {1}
                     l4_sport,                # {2}
                     dstIP,                   # {3}
                     l4_dport,                # {4}
                     l4_proto_name,           # {5}
                     length),                 # {6}
          file=fh_csv)

    return True
    #--------------------------------------------------

def pcap2csv(in_pcap, out_csv):
    """Main entry function called from main to process the pcap and
    generate the csv file.
    in_pcap = name of the input pcap file (guaranteed to exist)
    out_csv = name of the output csv file (will be created)
    This function walks over each packet in the pcap file, and for
    each packet invokes the render_csv_row() function to write one row
    of the csv.
    """
    frame_num = 0
    ignored_packets = 0
    with open(out_csv, 'w') as fh_csv:
        # Open the pcap file with scapy's RawPcapReader, and iterate over each packet
        # packets = myrdpcap(in_pcap)
        # for packet in packets:
        #     if packet:
        #         frame_num += 1
        #         if not render_csv_row(packet[1], packet[0], fh_csv):
        #             ignored_packets += 1
        for packet in RawPcapReader(in_pcap):
            # print("test", _)
            try:
                if packet:
                    frame_num += 1
                    if not render_csv_row(packet[1], packet[0], fh_csv):
                        ignored_packets += 1
                    if frame_num % 10000 == 0:
                        print(frame_num)
                    if frame_num >= 500000:
                        break
            except StopIteration:
                # Shouldn't happen because the RawPcapReader iterator should also
                # exit before this happens.
                break

    print('{} packets read, {} packets not written to CSV'.
          format(frame_num, ignored_packets))
#--------------------------------------------------

def command_line_args():
    """Helper called from main() to parse the command line arguments"""

    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', metavar='<input pcap file>',
                        help='pcap file to parse', required=True)
    parser.add_argument('--csv', metavar='<output csv file>',
                        help='csv file to create', required=True)
    args = parser.parse_args()
    return args
#--------------------------------------------------

def main():
    """Program main entry"""
    args = command_line_args()

    if not os.path.exists(args.pcap):
        print('Input pcap file "{}" does not exist'.format(args.pcap),
              file=sys.stderr)
        sys.exit(-1)

    # if os.path.exists(args.csv):
    #     print('Output csv file "{}" already exists, '
    #           'won\'t overwrite'.format(args.csv),
    #           file=sys.stderr)
    #     sys.exit(-1)

    pcap2csv(args.pcap, args.csv)
#--------------------------------------------------

if __name__ == '__main__':
    main()

# python pcap2csv.py --pcap H:\exp_data\pcap_data\caida-50w-1.pcap --csv original.csv
# python pcap2csv.py --pcap H:\exp_data\pcap_data\univ1_all.pcap --csv original-univ1.csv
# python pcap2csv.py --pcap /data/xgr/sketch_data/caida_dirA/equinix-nyc.dirA.20190117-130000.UTC.anon.pcap --csv data/packet-level/caida-A-50W-1.csv
# python pcap2csv.py --pcap /data/xgr/sketch_data/caida_dirA/equinix-nyc.dirA.20190117-130000.UTC.anon.pcap --csv /data/sym/one-class-svm/data/5+mean/packet-level/caida-A-50W-0.csv