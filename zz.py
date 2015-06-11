#!/usr/bin/python
import argparse
from scapy.all import *
pkts = sniff(iface="eno2", count=10000, prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst% %IP.proto% %IP.dport%}"))
