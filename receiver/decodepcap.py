# -*- coding:utf8 -*- 
import struct as s
from scapy.all import *

pkts = rdpcap('receive.pcap')

sample_length = []
cal_length = []

def real_num(num):
    if num >= 32768:
        return num-65536
    else:
        return num

for pkt in pkts:
    if pkt['UDP'].dport == 124:  # change other conditions such that pkt is a statistic packet. 
        f = pkt['UDP'].load
        # print(type(f))
        # print(f)
        sample_len = int.from_bytes(f[0:2],byteorder='big',signed='false')
        sample_length.append(sample_len)
        decoded_len = [
            real_num(s.unpack('!H',f[4:6])[0]),
            real_num(s.unpack('!H',f[8:10])[0]),
            real_num(s.unpack('!H',f[12:14])[0]),
            real_num(s.unpack('!H',f[16:18])[0])
        ]
        cal_length.append(decoded_len)

print(sample_length)

print(cal_length)
