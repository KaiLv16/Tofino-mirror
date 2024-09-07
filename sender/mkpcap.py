# -*- coding:utf8 -*- 
import struct as s

import numpy as np

from scapy.all import wrpcap, Ether, IP, TCP, UDP, Raw

# 可以用print(ls(TCP))来查看TCP中的所有字段
# 更多用法：
# https://blog.csdn.net/pdcfighting/article/details/116279524
# http://www.linuxboy.net/linuxjc/54320.html

data_tmp = [i for i in range(100,500,10)]

data = np.array(data_tmp) - 28
data_str = 'helloworld'
packet = []

mac_src = '00:1b:21:a5:86:d8'
mac_dst = '00:1b:21:a5:82:7c'

ip_src = '10.22.0.200'
ip_dst = '10.22.0.201'

tcp_dport = 123


for d in data:
    # 各数字代表什么，见 https://zhuanlan.zhihu.com/p/387421751
    # 网络序：在字母前面加上感叹号
    # rawdata = s.pack('!H', d)                           # 单个数字打包发送
    # rawdata = s.pack('!'+str(len(data))+'H', *data)     # 多个数字打包发送
    # rawdata = s.pack('!10s', bytes(data_str, encoding = "utf8"))     # 发送字符串
    rawdata = bytes(d)                                  # 用0填充长度为d字节的负载(python3下有效，python2下等同于单个数字打包发送
    p = Ether(dst=mac_dst) / IP(src=ip_src, dst=ip_dst) / UDP(dport=tcp_dport) / rawdata
    packet.append(p)


wrpcap('send.pcap', packet)


newlen = 8
controldata = s.pack('!H', newlen)
ctrl_pkt = Ether(dst=mac_dst, type=0x1234) / controldata

wrpcap('ctrl.pcap', ctrl_pkt)

#  在root下：
#   send:
#       tcpreplay -i eth2 send.pcap (or ctrl.pcap)
#   receive:
#       tcpdump -i eth2 dst port 123 or 124 -w receive.pcap
#
#