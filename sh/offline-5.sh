#!/bin/sh

for var in 2 3 4 5 6 7 8 9;do
python ../pcap2csv.py --pcap /data/xgr/sketch_data/caida_dirA/equinix-nyc.dirA.20190117-130${var}00.UTC.anon.pcap --csv ../data/offline-5/packet-level/caida-A-50W-${var}.csv
done