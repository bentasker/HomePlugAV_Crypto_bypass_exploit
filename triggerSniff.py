#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2014 B Tasker
#
# Get the PHY transfer rates
#
#

import sys
import fcntl, socket, struct


try:
  # Import Scapy
  from scapy.all import *
  from scapy.utils import rdpcap

except:
  sys.path.append( 'Scapy')
  # Import Scapy
  from scapy.all import *
  from scapy.utils import rdpcap

iface='eth0' # Which interface should we use


# Function from http://stackoverflow.com/questions/159137/getting-mac-address
def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]



# Enable Sniffer mode on the local HPAV device
#
#
payload='00:34:a0:00:b0:52:01:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00'
data_list = payload.split(":")

# Breakdown of payload above
#
# '00' - MAC Management header (Version: 1) - they're zero indexed
# '34:a0' - Sniffer type request
# 'b0:52' - OUI



# Build and send the packet
p = Ether()
p.src=getHwAddr(iface)
p.dst='00:B0:52:00:00:01'; # Only the nearest HomeplugAV device will respond
p.type=0x88e1; # HomeplugAV management frame
p.oui='00b052'
data=''.join(data_list).decode('hex')
b = p/data
ans = srp(b,iface=iface)

# You should be able to see the packet leave with tcpdump -i eth0 ether dst host '00:B0:52:00:00:01'

