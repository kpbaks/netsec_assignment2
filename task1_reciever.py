#!/usr/bin/env python3

from scapy.all import ICMP, IP, sr, raw
import sys
import socket

# def generate_icmp_packet(data: str, source_ip: str, dest_ip: str, dest_port: int=21):
#     return IP(raw(IP(dst=sys.argv[1], src=sys.argv[1])/ICMP(type=47) / data.encode("utf-8")))

# packet = generate_icmp_packet("Hello World", source_ip="127.0.0.1", dest_ip=sys.argv[1], dest_port=sys.argv[2])

# print(packet.show())

#unans, ans = sr(packet)

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

#s.bind((ip, port)) # Bind to port 0, which means any available port

#s.listen(5) # Listen for incoming connections

while True:
    payload, addr = s.recvfrom(1508) # Establish connection with client.

    print('Got connection from', addr)
    #c.send('Thank you for connecting')
    print(payload)
    # Reading the whole message from the client
    #payload = receive(c)
    
    # Print the message
    #print(payload)
    
    #c.close() # Close the connection