#!/usr/bin/env python3
import secrets
import socket
import struct
import sys

from Crypto.Cipher import AES

from aes import shared_aes_key
from icmp import *

from checksum1071 import ip_checksum


def send_covert_message(message: str="Hello World"):

    # The payload we want to send the receiver
    icmp_payload = bytes(message, encoding="utf-8")

    # Set the checksum
    icmp_header: bytes = struct.pack(icmp_header_format, icmp_type, icmp_code, icmp_temp_checksum, 0) # Rest of header field is irrelevant for our message

    # Encrypting the payload and sending the nonce and tag witht he packet
    nonce = secrets.token_bytes(16)
    aes = AES.new(shared_aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = aes.encrypt_and_digest(icmp_payload)

    icmp_payload = nonce + tag + ciphertext

    # Setting the checksum
    icmp_checksum = ip_checksum(icmp_header + icmp_payload)
    icmp_header = struct.pack(icmp_header_format, icmp_type, icmp_code, icmp_checksum, 0) # Setting the correct ICMP checksum

    # Send the packet
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    packet = icmp_header + icmp_payload

    s.sendto(packet, ("127.0.0.1", 0)) # The port is irrelevant for ICMP
    print("Message sent successfully")

while True:
    message = input("Enter message to covertly send: ")
    if len(sys.argv) == 2: # If the user has specified an IP and port
        send_covert_message(message)
    else:
        send_covert_message(message=message)
