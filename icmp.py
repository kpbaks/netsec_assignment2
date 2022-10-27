import struct

# Struct packet ICMP header
icmp_header_format = '!BBHI' # ! = network byte order, B = unsigned char, H = unsigned short, I = unsigned int
icmp_type = 47 # ICMP covert espionage request
icmp_code = 0 # Irrelevant for covert espionage request
icmp_checksum = 0 # Pseudo checksum to be calculated later