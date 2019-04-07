#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a message send and save it"""

__author__      = "Crescence Yimnaing && Francine Youndzo"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__status__ 		= "Prototype"

from scapy.all import*
import binascii
import rc4
import struct

#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

#read encrypt message
arp = rdpcap('arp.cap')[0]

#rc4 seed is the result of IV+key
seed = arp.iv + key

#the message in clear
message = 'Bienvenu au cours Teaching-SWI-2019'

#calculate icv
icv = binascii.crc32(message) & 0xffffffff
icv_bigedian_hex = struct.pack('<L', icv) 

message_Rc4 = message + icv_bigedian_hex

# encrypt message + icv  with rc4
message_encrypted = rc4.rc4crypt(message_Rc4, seed)

# extract message without icv
arp.wepdata = message_encrypted[:-4]

# the 4th last octects represents icv 
icv_crypte = message_encrypted[-4:]

# icv in Long big endian format
(icv_numerique,)=struct.unpack('!L', icv_crypte )

# icv's packet
arp.icv = icv_numerique

#save pcap file
wrpcap('arp-encrypted.pcap',arp)


