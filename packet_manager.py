
import logging
from datetime import datetime, timedelta
from constants import PROTOCOLS, COLUMNS
from pandas import DataFrame, concat

class PacketManager():

    def __init__(self, src_ip: str, file_path: str, protocols: list[str] = PROTOCOLS, 
                 log_path = './logs/packet_manager_logs.log') -> None:
        ''' Initialize the packet manager. '''

        self.file_path = file_path # defaults to ./logs/packets/
        self.log_path = log_path # defaults to ./logs/packet_manager_logs.log
        self.src_ip = src_ip

        # List of protocols to be loaded
        self.protocols = protocols

        # initialize manager
        self.tcp_packets = DataFrame(columns=COLUMNS['TCP'])
        self.udp_packets = DataFrame(columns=COLUMNS['PACKET'])
        self.icmp_packets = DataFrame(columns=COLUMNS['ICMP'])
        self.dns_packets = DataFrame(columns=COLUMNS['PACKET'])

        # logging
        logging.basicConfig(filename=self.log_path, level=logging.INFO)
    

    def load_packets(self, df: DataFrame) -> None:
        ''' Load packet into the manager. '''

        try:
            # fetch packets based on protocol

            # TCP packets
            tcps = self.load_tcp_packets(df)

            # UDP packets
            udps = df[df['PROTOCOL'] == 17]

            # ICMP packets
            icmps = self.load_icmp_packets(df)
            dns = df[df['PROTOCOL'] == 53]

            # append packets to respective dataframes
            self.tcp_packets = concat([self.tcp_packets, tcps], ignore_index=True)
            self.udp_packets = concat([self.udp_packets, udps], ignore_index=True)
            self.icmp_packets = concat([self.icmp_packets, icmps], ignore_index=True)
            self.dns_packets = concat([self.dns_packets, dns], ignore_index=True)
        except Exception as e:
            print(f"[ERROR] Failed loading packet into manager: {e}")
    

    def load_icmp_packets(self, df: DataFrame) -> None:
        ''' Load ICMP packets into the manager. '''

        icmps = df[df['PROTOCOL'] == 1]

        icmps.loc[:, 'TYPE'] = icmps['INFO'].apply(lambda x: x['type'])
        icmps.loc[:, 'CODE'] = icmps['INFO'].apply(lambda x: x['code'])
        icmps.drop(columns=['INFO', 'PROTOCOL'], inplace=True)

        return icmps


    def load_tcp_packets(self, df: DataFrame) -> None:
        ''' Load TCP packets into the manager. '''

        tcps = df[df['PROTOCOL'] == 6]

        tcps.loc[:, 'SPORT'] = tcps['INFO'].apply(lambda x: x['sport'])
        tcps.loc[:, 'DPORT'] = tcps['INFO'].apply(lambda x: x['dport'])
        tcps.loc[:, 'SYN'] = tcps['INFO'].apply(lambda x: 1 if 'SYN' in x['flags'] else 0)
        tcps.loc[:, 'ACK'] = tcps['INFO'].apply(lambda x: 1 if 'ACK' in x['flags'] else 0)
        tcps.loc[:, 'PSH'] = tcps['INFO'].apply(lambda x: 1 if 'PSH' in x['flags'] else 0)
        tcps.loc[:, 'FIN'] = tcps['INFO'].apply(lambda x: 1 if 'FIN' in x['flags'] else 0)
        tcps.loc[:, 'SEQ_NUM'] = tcps['INFO'].apply(lambda x: x['seq'])
        tcps.loc[:, 'ACK_NUM'] = tcps['INFO'].apply(lambda x: x['ack'])
        tcps.drop(columns=['INFO', 'PROTOCOL'], inplace=True)

        return tcps
    

    def check_syn_flood(self) -> None:
        ''' Check for SYN flood attacks in TLS packets. self.tcp_packets must not be empty. '''

        TIME_WINDOW = 60 # 60 seconds
        SYN_THRESHOLD = 100 # 100 SYN packets

        try:
            # fetch SYN packets
            print("CHECKING SYN FLOOD")
            syn_packets = self.tcp_packets.loc[(self.tcp_packets['DST_IP'] == self.src_ip) & (self.tcp_packets['SYN'] == 1)]

            if syn_packets.empty:
                logging.info("[SYN FLOOD] No SYN packets found.")
                return
            
            syn_packets.loc[:, 'TIME'] = syn_packets['TIME'].apply(lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S'))
            most_recent = max(syn_packets['TIME'])
            syn_packets = syn_packets[syn_packets['TIME'] >= most_recent - timedelta(seconds=TIME_WINDOW)]

            # check if SYN packets exceed threshold
            if syn_packets.shape[0] >= SYN_THRESHOLD:
                logging.info(f"[ALERT] SYN flood attack detected: {syn_packets.shape[0]} SYN packets in {TIME_WINDOW} seconds.")
        except Exception as e:
            print(f"[ERROR] Failed checking SYN flood attack: {e}")
        
    
    def check_ping_flood(self) -> None:
        ''' Check for ping flood attacks in ICMP packets. self.icmp_packets must not be empty. '''

        PING_THRESHOLD = 100 # 100 ICMP packets

        try:
            # fetch ICMP packets
            icmp_packets = self.icmp_packets.loc[(self.icmp_packets['DST_IP'] == self.src_ip) & (self.icmp_packets['TYPE'] == 8)]

            if icmp_packets.empty:
                logging.info("[PING FLOOD] No ICMP packets found.")
                return
            
            # check if ICMP packets exceed threshold
            if icmp_packets.shape[0] >= PING_THRESHOLD:
                logging.info(f"[ALERT] Ping flood attack detected: {icmp_packets.shape[0]} ICMP packets.")
        except Exception as e:
            print(f"[ERROR] Failed checking ping flood attack: {e}")

    
    def process_packets(self) -> None:
        ''' Process packets in the manager. '''

        # process packets based on protocol
        self.process_tcp_packets()
        self.process_udp_packets()
        self.process_icmp_packets()
        self.process_dns_packets()
    

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
        
        self.process_icmp_packets()

    
    def process_dns_packets(self) -> None:
        ''' Process DNS packets. '''

        # check if there are any packets to process
        if self.dns_packets.empty:
            return
        pass
