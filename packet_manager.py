
from constants import PROTOCOLS, PACKET_COLUMNS
from ipaddress import ip_address
from pandas import DataFrame, concat

class PacketManager():

    def __init__(self, src_ip: str, file_path: str, protocols: list[str] = PROTOCOLS) -> None:
        ''' Initialize the packet manager. '''

        self.file_path = file_path # defaults to ./logs/packets/
        self.src_ip = src_ip

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
            self.tcp_packets = concat([self.tcp_packets, tcps], ignore_index=True)
            self.udp_packets = concat([self.udp_packets, udps], ignore_index=True)
            self.icmp_packets = concat([self.icmp_packets, icmps], ignore_index=True)
            self.dns_packets = concat([self.dns_packets, dns], ignore_index=True)
        except Exception as e:
            print(f"[ERROR] Failed loading packet into manager: {e}")
    

    def process_packets(self) -> None:
        ''' Process packets in the manager. '''

        # process packets based on protocol
        self.process_tcp_packets()
        self.process_udp_packets()
        self.process_icmp_packets()
        self.process_dns_packets()
    

    def check_syn_flood(self) -> None:
        ''' Check for SYN flood attacks in TLS packets. self.tcp_packets must not be empty. '''

        TIME_WINDOW = 60 # 60 seconds
        SYN_THRESHOLD = 100 # 100 SYN packets

        try:
            # fetch SYN packets
            print(self.tcp_packets)
            syn_packets = self.tcp_packets.loc[(self.tcp_packets['DST_IP'] == self.src_ip) & (self.tcp_packets['INFO'].isin(['SYN']))]
            print("SYN PACKETS BEFORE TIME: ", syn_packets)
            syn_packets = syn_packets[syn_packets['TIME'] >= syn_packets['TIME'].max() - TIME_WINDOW]
            print("SYN PACKETS AFTER TIME: ", syn_packets)

            # check if SYN packets exceed threshold
            if syn_packets.shape[0] >= SYN_THRESHOLD:
                print(f"[ALERT] SYN flood attack detected: {syn_packets.shape[0]} SYN packets in {TIME_WINDOW} seconds.")
        except Exception as e:
            print(f"[ERROR] Failed checking SYN flood attack: {e}")

    

    def process_tcp_packets(self) -> None:
        ''' Process TCP packets. '''

        # check if there are any packets to process
        if self.tcp_packets.empty:
            return
        
        self.check_syn_flood()



    def process_udp_packets(self) -> None:
        ''' Process UDP packets. '''

        # check if there are any packets to process
        if self.udp_packets.empty:
            return
        pass


    def process_icmp_packets(self) -> None:
        ''' Process ICMP packets. '''

        # check if there are any packets to process
        if self.icmp_packets.empty:
            return
        pass

    
    def process_dns_packets(self) -> None:
        ''' Process DNS packets. '''

        # check if there are any packets to process
        if self.dns_packets.empty:
            return
        pass
