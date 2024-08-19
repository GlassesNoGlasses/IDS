
import scapy.all as scapy
import pandas as pd
import logging
import socket
import datetime
from helper import Packet, PacketType, get_tcp_flags
from ast import literal_eval

scapy.load_layer("tls")
scapy.load_layer("http")
scapy.load_layer("dns")

# Constants
ALERT_COLUMNS = ["TIME", "ALERT_TYPE", "SRC_IP", "DST_IP", "PROTOCOL"]
ALERT_THRESHOLD = 10

PACKET_COLUMNS = ["TIME", "SRC_IP", "DST_IP", "PROTOCOL", "INFO"]

class IDS():

    def __init__(self, alerts_path: str = "./logs/alerts.csv", packets_path: str = "./logs/packets.csv") -> None:
        ''' Initialize the Intrusion Detection System. '''

        # Host settings
        self.host_ip = self.get_host_ip()

        # file paths
        self.alerts_path = alerts_path
        self.packets_path = packets_path

        # Packet configs/storage
        self.alert_count = 0 # Number of alerts
        self.alerts_df = pd.DataFrame(columns=ALERT_COLUMNS)
        self.packets_df = pd.DataFrame(columns=PACKET_COLUMNS)

    
    def get_host_ip(self) -> str:
        ''' Get the IP address of the host machine '''
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()

        return ip
    

    def save_dfs(self) -> None:
        ''' Save alerts and packets dataframes to their respective paths. '''

        self.alerts_df.to_csv(self.alerts_path, columns=ALERT_COLUMNS, index=False)
        self.packets_df.to_csv(self.packets_path, columns=PACKET_COLUMNS, index=False)
    

    def load_dfs(self) -> None:
        ''' Load the alert and packet dataframes from the initialized paths. '''

        try:
            self.alerts_df = pd.read_csv(self.alerts_path)
            self.packets_df = pd.read_csv(self.packets_path)
            self.packets_df["INFO"] = self.packets_df["INFO"].apply(lambda x: literal_eval(x.strip()))
        except Exception as e:
            print(f"[ERROR] Failed loading dataframes from csv path: {e}")


    def check_alerts(self, packet) -> None:
        ''' Check for any alerts in the packet. '''

        # Check for any alerts
        if (self.alert_count >= ALERT_THRESHOLD):
            # TODO: ALERT USER ABOVE THRESHOLD
            return

        # Check for any alerts
        if (packet.haslayer(scapy.TCP)):
            self.check_tcp_alerts(packet)
        elif (packet.haslayer(scapy.UDP)):
            self.check_udp_alerts(packet)
        elif (packet.haslayer(scapy.ICMP)):
            self.check_icmp_alerts(packet)


    def packet_filter(self, packet) -> bool:
        ''' Filter the packets to only include the ones that are not from the host machine. '''

        if (not packet.haslayer(scapy.IP)):
            return False
        
        # filter packets based on current machines ip address src/dst
        sip = packet[IPv6].src if (IPv6 in packet) else packet[IP].src
        dip = packet[IPv6].dst if (IPv6 in packet) else packet[IP].dst

        return sip == self.host_ip or dip == self.host_ip
    

    def process_packet(self, packet) -> None:
        ''' Process the packet and check for any alerts. '''

        # packet.show()

        # fixed params
        time = datetime.datetime.now()
        sip = packet[IPv6].src if (IPv6 in packet) else packet[IP].src
        dip = packet[IPv6].dst if (IPv6 in packet) else packet[IP].dst

        # variable params 
        p_type = None

        if (packet.haslayer(scapy.TCP)):
            p_type = PacketType.TCP
            print(get_tcp_flags(packet[TCP].flags))
        elif (packet.haslayer(scapy.UDP)):
            p_type = PacketType.UDP
        elif (packet.haslayer(scapy.ICMP)):
            p_type = PacketType.ICMP
        elif (packet.haslayer(scapy.DNS)):
            p_type = PacketType.DNS
        
        ids_packet = Packet(type=p_type, packet=packet)

        if (not ids_packet.packet):
            logging.info(f"Failed to initialize packet for {sip} -> {dip}") 
            return
        
        logging.info(f"Packet: {sip} -> {dip} | Protocol: {p_type}")
        self.packets_df.loc[len(self.packets_df), PACKET_COLUMNS] = [time, sip, dip, p_type.value, ids_packet.packet]

        # Add the packet to the list of packets
        # self.packets_df = pd.concat([self.packets_df, pd.DataFrame([packet], columns=PACKET_COLUMNS)], ignore_index=True)

        # Check for alerts
        # self.check_alerts(packet)
    

    def sniff_packets(self):
        scapy.sniff(lfilter=self.packet_filter, prn=self.process_packet, store=False, count=20)


if __name__ == "__main__":
    with open("./logs/ids_info.log", "w"):
        pass
    logging.basicConfig(filename="./logs/ids_info.log", level=logging.INFO)
    logging.info("Starting the program")
    ids = IDS()
    print(ids.host_ip)
    ids.sniff_packets()
    # print(ids.packets_df)
    ids.save_dfs()
    ids.load_dfs()

