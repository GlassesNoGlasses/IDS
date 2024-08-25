
# Alerts
ALERT_COLUMNS = ["TIME", "ALERT_TYPE", "SRC_IP", "DST_IP", "PROTOCOL"]
ALERT_THRESHOLD = 10

# Packets
PACKET_COLUMNS = ["TIME", "SRC_IP", "DST_IP", "PROTOCOL", "INFO"]
PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS"]
TCP_COLUMNS = ["TIME", "SRC_IP", "DST_IP", "SPORT", "DPORT", 
               "SYN", "ACK", "PSH", "FIN", "SEQ_NUM", "ACK_NUM"]

PROTOCOL_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
    53: "DNS",
}
