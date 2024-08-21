
from constants import PROTOCOLS, PACKET_COLUMNS
from ipaddress import ip_address
from pandas import DataFrame

class PacketManager():

    def __init__(self, file_path: str, protocols: list[str] = PROTOCOLS) -> None:
        ''' Initialize the packet manager. '''

        self.file_path = file_path # defaults to ./logs/packets/

        # List of protocols to be loaded
        self.protocols = protocols

        # initialize manager
        self.tcp_packets = DataFrame(columns=PACKET_COLUMNS)
        self.udp_packets = DataFrame(columns=PACKET_COLUMNS)
        self.icmp_packets = DataFrame(columns=PACKET_COLUMNS)
        self.dns_packets = DataFrame(columns=PACKET_COLUMNS)
    

    def load_packets(self, df: DataFrame) -> None:
        ''' Load packet into the manager. '''

        try:
            # fetch packets based on protocol
            tcps = df[df['PROTOCOL'] == 6]
            udps = df[df['PROTOCOL'] == 17]
            icmps = df[df['PROTOCOL'] == 1]
            dns = df[df['PROTOCOL'] == 53]

            # append packets to respective dataframes
            self.tcp_packets = self.tcp_packets.append(tcps, ignore_index=True)
            self.udp_packets = self.udp_packets.append(udps, ignore_index=True)
            self.icmp_packets = self.icmp_packets.append(icmps, ignore_index=True)
            self.dns_packets = self.dns_packets.append(dns, ignore_index=True)
        except Exception as e:
            print(f"[ERROR] Failed loading packet into manager: {e}")