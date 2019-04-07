
#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a message send it in many fragments and save it into a pcap file """

__author__      = "Crescence Yimnaing && Francine Youndzo"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import*
import binascii
import rc4

#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

#read encrypt message
arp = rdpcap('arp.cap')[0]

#rc4 seed is the result of IV+key
seed = arp.iv+key

#the message in clear
message = 'salut nous traiterons de la securite wifi'

#list of fragments
fragments = []

#frangment length
length = len(message)/3

"""" this function take as parameter a message in clear and return the encrypt message """

def messageEncrypted(msg):

	#calculate icv
	icv = binascii.crc32(msg)
	
	#convertion in bigendian
	icv_bigedian_hex = struct.pack('<i', icv) 
	

	#concat msg with icv before encryption 
	message_Rc4 = msg + icv_bigedian_hex

	# encrypt message + icv  with rc4
	message_encrypted = rc4.rc4crypt(message_Rc4, seed)
	
	return message_encrypted
	
for x in range(0,3):

	#initialize the packet
	arp = rdpcap('arp.cap')[0]
	
	#fragmention of message into many frames
	fragment_msg = message[x-length: (x+1)*length]
	
	#encrypt fragments
	fragment_encrypted = messageEncrypted(fragment_msg)
	
	# extract message without icv
	arp.wepdata = fragment_encrypted[:-4]

	# the 4th last octects represents icv 
	icv_crypted = fragment_encrypted[-4:]

	# icv in Long big endian format
	(icv_numerique,)=struct.unpack('!L', icv_crypted)

	# icv's packet
	arp.icv = icv_numerique
	
	#change SC hich represent the fragment number
	arp.SC = x
	
	#change FC bit status, to specify wheter there is one fragment or more
	if x < 2:
		#for each fragment except the last one, we modify FCfield to TO DS not wep + TO DS as usual
		arp.FCfield = arp.FCfield | 0x04
		
	#add the new fragment to the list
	fragments.append(arp)
	
#save pcap file
wrpcap('fragment-encrypted.pcap',fragments)




