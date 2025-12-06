import argparse 
import os 
from time import sleep 
import sys 
from scapy.utils import RawPcapReader 
from scapy.layers.dot11 import * 
from scapy.packet import Packet 
from scapy.all import * 
def process_pcap(): 
  print('Opening {}...'.format(FILE_NAME)) 
  for dot11_packet in PcapReader(FILE_NAME):
    if dot11_packet.haslayer(Dot11):
        print(dot11_packet[Dot11].mysummary())
if __name__ == '__main__': 
    parser = argparse.ArgumentParser(description='PCAP reader') 
    parser.add_argument('--pcap', metavar='<pcap file name>', 
                        help='pcap file to parse', required=True) 
    args = parser.parse_args() 
    global FILE_NAME 
    FILE_NAME = args.pcap 
    if not os.path.isfile(FILE_NAME):
       print('"{}" does not exist'.format(FILE_NAME), file=sys.stderr) 
       sys.exit(-1) 
    process_pcap() 
    sys.exit(0) 