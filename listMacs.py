# -*- coding: utf-8 -*-
# 
# List potential HomePlugAV MAC addresses found in a pcap
#
# Usage: listMacs.py [pcap filename]

# First we need to import the scapy modules files as it's not installed on the server
import sys


try:
  # Import Scapy
  from scapy.all import *
  from scapy.utils import rdpcap

except:
  sys.path.append( 'Scapy')
  # Import Scapy
  from scapy.all import *
  from scapy.utils import rdpcap



# Load the pcap
pkts=rdpcap('cap.pcap')  # could be used like this rdpcap("filename",500) fetches first 500 pkts

for pkt in pkts:
    if pkt.type == 35041:
	response=''.join(pkt.load).encode('hex')
	response=':'.join(a+b for a,b in zip(response[::2], response[1::2]))
	#print response,"\n"
	segments=response.split(":")
	try:
	  
	  # Rule out the IANA reserved range
	  if int(segments[66]) > 00 and int(segments[67]) > 00:
	    print "2:",segments[66],segments[67],segments[68],segments[69],segments[70],segments[71]
	    
	  if int(segments[58]) > 00 and int(segments[59]) > 00:
	    print "1:",segments[58],segments[59],segments[60],segments[61],segments[62],segments[63]
      
    
	except:
	    continue


