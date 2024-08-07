
import scapy.all as scapy
import pandas as pd
import logging
import socket

scapy.load_layer("tls")
scapy.load_layer("http")
scapy.load_layer("dns")

# Constants
ALERT_COLUMNS = ["TIME", "ALERT_TYPE", "SRC_IP", "DST_IP", "SRC_PORT", "DST_PORT", "PROTOCOL"]
ALERT_THRESHOLD = 10

PACKET_COLUMNS = ["TIME", "SRC_IP", "DST_IP", "SRC_PORT", "DST_PORT", "PROTOCOL"]

class IDS():

    def __init__(self) -> None:
        ''' Initialize the Intrusion Detection System. '''

        # Host settings
        self.host_ip = self.get_host_ip()

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

        print(packet.summary())

        # Add the packet to the list of packets
        # self.packets_df = pd.concat([self.packets_df, pd.DataFrame([packet], columns=PACKET_COLUMNS)], ignore_index=True)

        # Check for alerts
        # self.check_alerts(packet)
    
    
    def sniff_packets(self):
        scapy.sniff(lfilter=self.packet_filter, prn=self.process_packet, store=False, count=20)





if __name__ == "__main__":
    logging.basicConfig(filename="ids_info.log", level=logging.INFO)
    logging.info("Starting the program")
    ids = IDS()
    print(ids.host_ip)
    ids.sniff_packets()

