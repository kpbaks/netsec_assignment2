import socket
import sys

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
    chunks.append(chunk)
    bytes_recd = bytes_recd + len(chunk)
    return b"".join(chunks)

argc = len(sys.argv)
if argc != 3:
    print("Usage: python3 task1_sender.py <IP address> <port number>")
    sys.exit(1)


ip = sys.argv[1]
port = int(sys.argv[2])

# Construct ICMP socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) # AF_INET = IPv4, SOCK_RAW = raw socket, IPPROTO_ICMP = ICMP

s.bind((ip, port)) # Bind to port 0, which means any available port

s.listen(5) # Listen for incoming connections

while True:
    c, addr = s.accept() # Establish connection with client.
    print('Got connection from', addr)
    #c.send('Thank you for connecting')

    # Reading the whole message from the client
    payload = receive(c)
    
    # Print the message
    print(payload)
    
    c.close() # Close the connection