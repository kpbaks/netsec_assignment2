import struct
import socket
import sys
from icmp import *
from aes import shared_aes_key
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

# RFC 1071 - Computing the Internet Checksum
def checksum(data: bytes) -> int:
    # Calculate checksum
    checksum = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            checksum += (data[i] << 8) + data[i + 1]
        else:
            checksum += data[i] << 8
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = ~checksum & 0xffff
    return checksum

def send_covert_message(ip: str = "127.0.0.1", port: int=9000, message: str="Hello World"):
    icmp_header: bytes = struct.pack(icmp_header_format, icmp_type, icmp_code, icmp_temp_checksum, 0) # Rest of header field is irrelevant for our message

    # The payload we want to send the receiver
    icmp_payload = bytes(message, encoding="utf-8")

    # Set the checksum
    icmp_header = struct.pack(icmp_header_format, icmp_type, icmp_code, icmp_temp_checksum, 0)

    #print(f"Type: {icmp_type}, Code: {icmp_code}, Checksum: {icmp_temp_checksum}, Data: {icmp_payload}")

    # Encrypting the payload and sending the nonce and tag witht he packet
    nonce = secrets.token_bytes(16)
    aes = AES.new(shared_aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = aes.encrypt_and_digest(icmp_payload)

    # Setting the checksum
    icmp_checksum = checksum(icmp_header + nonce + tag + ciphertext)
    icmp_header = struct.pack(icmp_header_format, icmp_type, icmp_code, icmp_checksum, 0)

    # Send the packet
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    packet = icmp_header + nonce + tag + ciphertext
    #print(f"len(header): {len(icmp_header)}, len(nonce): {len(nonce)}, len(tag): {len(tag)}, len(ciphertext): {len(ciphertext)}")
    s.sendto(packet, (sys.argv[1], int(sys.argv[2])))
    print("Message sent successfully")

while True:
    message = input("Enter message to covertly send: ")
    if len(sys.argv) == 3: # If the user has specified an IP and port
        send_covert_message(sys.argv[1], int(sys.argv[2]), message)
    else:
        send_covert_message(message=message)