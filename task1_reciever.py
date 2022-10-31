#!/usr/bin/env python3
import socket
import struct
import sys

from Crypto.Cipher import AES

from aes import shared_aes_key
from icmp import *

from checksum1071 import ip_checksum

argc = len(sys.argv)
if argc != 3:
	print("Usage: python3 task1_sender.py <IP address> <port number>")
	sys.exit(1)

ip = sys.argv[1]
port = int(sys.argv[2])

# Construct ICMP socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) # AF_INET = IPv4, SOCK_RAW = raw socket, IPPROTO_ICMP = ICMP
s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

print(f"Ready to receive covert messages using ICMP packets on port {port}.")
while True:
	MAXIMUM_PACKET_SIZE = 4 * 1024
	payload, addr = s.recvfrom(MAXIMUM_PACKET_SIZE) # Establish connection with client.
	
	payload = payload[20:] # IP header is 20 bytes

	header = payload[:8] # ICMP header is 8 bytes
	type_, code, _, _ = struct.unpack(icmp_header_format, header) # Rest of header field is irrelevant for our message
	
	if type_ != icmp_type:
		continue

	nonce = payload[8:24]
	aes = AES.new(shared_aes_key, AES.MODE_GCM, nonce=nonce)
	tag = payload[24:40]
	ciphertext = payload[40:]

	# Verify RFC 1071 checksum
	icmp_checksum = ip_checksum(header + payload[8:])
	if icmp_checksum != 0:
		print("Invalid checksum.")
		continue

	plaintext = aes.decrypt_and_verify(ciphertext, tag)
	
	print(f"Recieved and decrypted message: {plaintext.decode('utf-8')}")
