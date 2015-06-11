#!/usr/bin/python
#通过scapy库抓取接口"eno2"网卡的入数据包，显示源IP，端口。
import argparse
from scapy.all import *
pkts = sniff(iface="eno2", count=10000, prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst% %IP.proto% %IP.dport%}"))
