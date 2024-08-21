
from helper import PROTOCOL_MAP, PROTOCOLS
from ipaddress import ip_address

''' Manager Structure:
ip1: {
    'inbound': {
        'TCP': {
            'packets': [],
            'count': 0
        },
    },
    'outbound': {
        'TCP': {
            'packets': [],
            'count': 0
        },
    }
}
'''

class PacketManager():

    def __init__(self, protocols: list[str] = PROTOCOLS) -> None:
        ''' Initialize the packet manager. '''

        # List of protocols to be loaded
        self.protocols = protocols

        # initialize manager
        self.manager = {}
    

    def initialize_ip(self, ip: str) -> None:
        ''' Initialize IP address in the manager. '''

        try:
            # Check if IP is valid
            ip_address(ip)
            
            # intialize IP in manager
            self.manager[ip] = {
                'inbound': {},
                'outbound': {}
            }

            # Initialize protocols for IP inbound/outbound traffic
            for protocol in self.protocols:
                self.manager[ip]['inbound'][protocol] = {
                    'packets': [],
                    'count': 0
                }
                
                self.manager[ip]['outbound'][protocol] = {
                    'packets': [],
                    'count': 0
                }

        except ValueError as e:
            print(f"[ERROR] Invalid IP address: {e}")

    
    def load_packet(self, ip: str, protocol: int, info, inbound: bool = True) -> None:
        ''' Load packet into the manager. '''

        try:
            
            # Check if IP exists in manager
            if ip not in self.manager:
                self.initialize_ip(ip=ip)

            # Load packet into manager
            protocol = PROTOCOL_MAP[protocol]

            manager = self.manager[ip]['inbound'] if inbound else self.manager[ip]['outbound']
            manager[protocol]['packets'].append(info)
            manager[protocol]['count'] += 1

        except Exception as e:
            print(f"[ERROR] Failed loading packet into manager: {e}")