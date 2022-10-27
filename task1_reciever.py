#!/usr/bin/env python3
import struct
import socket
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

from requests import head
from icmp import *
from aes import shared_aes_key

def receive(sock):
	# Upper limit of the message length
	MSGLEN = 4096

	chunks = []
	bytes_recd = 0
	while bytes_recd < MSGLEN:
		chunk = sock.recv(min(MSGLEN - bytes_recd, 2048))
		if chunk == b"":
			break
	# raise RuntimeError("Socket connection broken")
	chunks.append(chunks)
	bytes_recd = bytes_recd + len(chunks)
	return b"".join(chunks)

argc = len(sys.argv)
if argc != 3:
	print("Usage: python3 task1_sender.py <IP address> <port number>")
	sys.exit(1)

ip = sys.argv[1]
port = int(sys.argv[2])

# Construct ICMP socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) # AF_INET = IPv4, SOCK_RAW = raw socket, IPPROTO_ICMP = ICMP
s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

while True:
	payload, addr = s.recvfrom(1508) # Establish connection with client.
	print('Got connection from', addr)
	print(f"len(payload): {len(payload)}")

	payload = payload[20:] # assume IP header is 20 bytes

	print(payload)
	header = payload[:8]
	type_, code, checksum, _ = struct.unpack(icmp_header_format, header) # Rest of header field is irrelevant for our message

	# TODO: Check checksum
	
	if type_ != icmp_type:
		continue

	print(f"Type: {type_}, Code: {code}, Checksum: {checksum}")

	# Decrypting the data
	nonce = payload[8:24]
	aes = AES.new(shared_aes_key, AES.MODE_GCM, nonce=nonce)
	tag = payload[24:40]
	data = payload[40:]
	plaintext = aes.decrypt_and_verify(data, tag)
	
	print(f"Decrypted data: {plaintext.decode('utf-8')}")

	#c.send('Thank you for connecting')

	# Reading the whole message from the client
	#payload = receive(c)
	
	# Print the message
	#print(payload)
	
	#c.close() # Close the connection