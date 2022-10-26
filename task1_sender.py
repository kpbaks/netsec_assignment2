from scapy.all import ICMP, IP, sr, raw
import sys

def generate_icmp_packet(data: str, source_ip: str, dest_ip: str, dest_port: int=21):
    # return IP(raw(IP(dst=sys.argv[1], src=sys.argv[1])/ICMP(type=0) / data.encode("utf-8")))
    return IP(dst=sys.argv[1], src=sys.argv[1])/ICMP(type=0) / data.encode("utf-8")

packet = generate_icmp_packet("Hello World", source_ip="127.0.0.1", dest_ip=sys.argv[1], dest_port=sys.argv[2])

print(packet.show())

sr(packet, retry=5, timeout=1.5, iface="lo0")

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