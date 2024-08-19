
from enum import Enum
from scapy.all import UDP, TCP, ICMP, DNS


# ----------------- Packet Classes ----------------- #
class PacketType(Enum):
    TCP = 6
    UDP = 17
    ICMP = 1
    DNS = 53


class Packet():

    def __init__(self, type: PacketType, packet) -> None:
        ''' Initialize the packet object. '''

        self.type = type

        try:
            self.packet = self.initialize_packet(packet)
        except ValueError as e:
            print(f"[ERROR] {e}")

    
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
            case _:
                raise ValueError("Invalid packet type.")
        
        return packet_info
    

    def initialize_tcp_packet(self, packet) -> dict:
        ''' Initialize the TCP packet information. '''

        return {
            'sport': packet[TCP].sport,
            'dport': packet[TCP].dport,
            'flags': get_tcp_flags(packet[TCP].flags),
            'seq': packet[TCP].seq,
            'ack': packet[TCP].ack,
        }
    
    def initialize_udp_packet(self, packet) -> dict:
        ''' Initialize the UDP packet information. '''

        return {
            'sport': packet[UDP].sport,
            'dport': packet[UDP].dport,
            'len': packet[UDP].len,
            'chksum': packet[UDP].chksum,
        }
    
    
    def initialize_icmp_packet(self, packet) -> dict:
        ''' Initialize the ICMP packet information. '''

        return {
            'type': packet[ICMP].type,
            'code': packet[ICMP].code,
            'chksum': packet[ICMP].chksum,
        }
    

    def initialize_dns_packet(self, packet) -> dict:
        ''' Initialize the DNS packet information. '''

        return {
            'qr': packet[DNS].qr, # query (0) or response (1)
            'opcode': packet[DNS].opcode, # type of query
            'rcode': packet[DNS].rcode, # response code
        }


# ----------------- Helper Functions ----------------- #

def get_tcp_flags(flags: int) -> list:
    ''' Get the TCP flags based on the flags value. '''

    tcp_flags = []

    if (flags & 0x01):
        tcp_flags.append("FIN")
    if (flags & 0x02):
        tcp_flags.append("SYN")
    if (flags & 0x04):
        tcp_flags.append("RST")
    if (flags & 0x08):
        tcp_flags.append("PSH")
    if (flags & 0x10):
        tcp_flags.append("ACK")
    if (flags & 0x20):
        tcp_flags.append("URG")
    if (flags & 0x40):
        tcp_flags.append("ECE")
    if (flags & 0x80):
        tcp_flags.append("CWR")

    return tcp_flags

