
# Alerts

ALERT_THRESHOLD = 10

# Packets

COLUMNS = {
    'ALERT': ["TIME", "ALERT_TYPE", "SRC_IP", "DST_IP", "PROTOCOL"],
    'PACKET': ["TIME", "SRC_IP", "DST_IP", "PROTOCOL", "INFO"],
    'TCP': ["TIME", "SRC_IP", "DST_IP", "SPORT", "DPORT", 
            "SYN", "ACK", "PSH", "FIN", "SEQ_NUM", "ACK_NUM"],
    'UDP': ["TIME", "SRC_IP", "DST_IP", "SPORT", "DPORT", "LEN", "CHKSUM"],
    'ICMP': ["TIME", "SRC_IP", "DST_IP", "TYPE", "CODE"],
    'DNS': ["TIME", "SRC_IP", "DST_IP", "QR", "OPCODE", "RCODE"],
}

# Protocols

PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS"]
PROTOCOL_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
    53: "DNS",
}
