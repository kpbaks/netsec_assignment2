#from scapy.all import ICMP, IP, sr, raw
import sys
import socket

# Construct ICMP socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) # AF_INET = IPv4, SOCK_RAW = raw socket, IPPROTO_ICMP = ICMP
s.connect((sys.argv[1], int(sys.argv[2])))

s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)



ip_header = b'\x45\x00\x00\x1c' # Version, IHL, Type of Service | Total Length
ip_header += b'\xab\xcd\x00\x00' # Identification | Flags, Fragment Offset
ip_header += b'\x40\x01\x6b\xd8' # TTL, Protocol | Header Checksum
#ip_header += b'\xc0\xa8\x92\x83' # Source Address
ip_header += b'\x0e\x00\x00\x01' # Source Address
#ip_header += b'\x08\x08\x08\x08' # Destination Address
ip_header += b'\x0e\x00\x00\x01' # Destination Address

icmp_header = b'\x08\x00\xe5\xca' # Type of message, Code | Checksum
icmp_header += b'\x12\x34\x00\x01' # Identifier | Sequence Number

packet = ip_header + icmp_header

ip = sys.argv[1]
port = int(sys.argv[2])

s.send(b'helloworld')
# s.sendto(packet, (ip, port))






# def generate_icmp_packet(data: str, source_ip: str, dest_ip: str, dest_port: int=21):
#     # return IP(raw(IP(dst=sys.argv[1], src=sys.argv[1])/ICMP(type=0) / data.encode("utf-8")))
#     return IP(dst=sys.argv[1], src=sys.argv[1])/ICMP(type=0) / data.encode("utf-8")

# packet = generate_icmp_packet("Hello World", source_ip="127.0.0.1", dest_ip=sys.argv[1], dest_port=sys.argv[2])

# print(packet.show())

# sr(packet, retry=5, timeout=1.5, iface="lo0")

# import socket
# import sys

# argc = len(sys.argv)

# if argc != 3:
#     print("Usage: python3 task1_sender.py <IP address> <port number>")
#     sys.exit(1)

# ip = sys.argv[1]
# port = int(sys.argv[2])

# # Construct ICMP socket
# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) # AF_INET = IPv4, SOCK_RAW = raw socket, IPPROTO_ICMP = ICMP

# s.connect((ip, port)) # Bind to port 0, which means any available port

# while True:
#     message = input("Enter message to send the reicever: ")

#     # Encrypt with AES-GCM
#     # TODO

#     # Send the message
    
#     print(f"Sending the following message to {ip}:{port}\n{message}")

#     s.send(message.encode())