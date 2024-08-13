
from enum import Enum
from scapy import IP, UDP, TCP, ICMP, DNS

class PacketType(Enum):
    TCP = 6
    UDP = 17
    ICMP = 1
    DNS = 53


class Packet():

    def __init__(self, type: PacketType, packet) -> None:
        self.type = type
        pass

    
    def initialize_packet(self, packet) -> None:
        ''' Initialize the packet information based on packet type. '''

        packet_info = None

        match self.type:
            case PacketType.TCP:
                packet_info = self.initialize_tcp_packet(packet)
            case PacketType.UDP:
                packet_info = self.initialize_udp_packet(packet)
            case PacketType.ICMP:
                packet_info = self.initialize_icmp_packet(packet)
            case PacketType.DNS:
                packet_info = self.initialize_dns_packet(packet)
        
        self.packet_info = packet_info
    

    def initialize_tcp_packet(self, packet) -> dict:
        ''' Initialize the TCP packet information. '''

        return {
            "protocol": "TCP",
            "src_port": packet[TCP].sport,
            "dst_port": packet[TCP].dport,
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
        }
    
    def initialize_udp_packet(self, packet) -> dict:
        ''' Initialize the UDP packet information. '''

        return {
            "protocol": "UDP",
            "src_port": packet[UDP].sport,
            "dst_port": packet[UDP].dport,
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
        }
    
    
    def initialize_icmp_packet(self, packet) -> dict:
        ''' Initialize the ICMP packet information. '''

        return {
            "protocol": "ICMP"
        }
    

    def initialize_dns_packet(self, packet) -> dict:
        ''' Initialize the DNS packet information. '''

        return {
            "protocol": "DNS"
        }
        
