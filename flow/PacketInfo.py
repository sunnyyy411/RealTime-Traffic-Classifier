from scapy.all import TCP, UDP, IP

class PacketInfo:
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.protocol = 6  # Default: TCP
        self.timestamp = None
        self.packet_size = 0
        self.header_bytes = 0
        self.payload_bytes = 0
        self.win_bytes = 0
        self.fwd_id = ""
        self.bwd_id = ""

        # TCP Flags
        self.flags = {
            'FIN': 0,
            'SYN': 0,
            'RST': 0,
            'PSH': 0,
            'ACK': 0,
            'URG': 0
        }

    def setSrc(self, pkt):
        if IP in pkt:
            self.src_ip = pkt[IP].src

    def setDest(self, pkt):
        if IP in pkt:
            self.dst_ip = pkt[IP].dst

    def setSrcPort(self, pkt):
        if TCP in pkt:
            self.src_port = pkt[TCP].sport
        elif UDP in pkt:
            self.src_port = pkt[UDP].sport
        else:
            self.src_port = 0

    def setDestPort(self, pkt):
        if TCP in pkt:
            self.dst_port = pkt[TCP].dport
        elif UDP in pkt:
            self.dst_port = pkt[UDP].dport
        else:
            self.dst_port = 0

    def setProtocol(self, pkt):
        if IP in pkt:
            self.protocol = pkt[IP].proto
        else:
            self.protocol = 6  # Default to TCP

    def setTimestamp(self, pkt):
        try:
            self.timestamp = float(pkt.time)
        except:
            from datetime import datetime
            self.timestamp = datetime.now().timestamp()

    def setPacketSize(self, pkt):
        try:
            self.packet_size = len(pkt)
        except:
            self.packet_size = 0

    def setHeaderBytes(self, pkt):
        try:
            self.header_bytes = 0
            if IP in pkt:
                self.header_bytes += pkt[IP].ihl * 4
            if TCP in pkt:
                self.header_bytes += pkt[TCP].dataofs * 4
            elif UDP in pkt:
                self.header_bytes += 8  # UDP header is fixed at 8 bytes
        except:
            self.header_bytes = 0

    def setPayloadBytes(self, pkt):
        try:
            self.payload_bytes = self.packet_size - self.header_bytes
        except:
            self.payload_bytes = 0

    def setWinBytes(self, pkt):
        try:
            if TCP in pkt:
                self.win_bytes = pkt[TCP].window
            else:
                self.win_bytes = 0
        except:
            self.win_bytes = 0

    # TCP Flags
    def setFINFlag(self, pkt):
        try:
            if TCP in pkt:
                self.flags['FIN'] = 1 if pkt[TCP].flags.F else 0
            else:
                self.flags['FIN'] = 0
        except:
            self.flags['FIN'] = 0

    def setSYNFlag(self, pkt):
        try:
            if TCP in pkt:
                self.flags['SYN'] = 1 if pkt[TCP].flags.S else 0
            else:
                self.flags['SYN'] = 0
        except:
            self.flags['SYN'] = 0

    def setRSTFlag(self, pkt):
        try:
            if TCP in pkt:
                self.flags['RST'] = 1 if pkt[TCP].flags.R else 0
            else:
                self.flags['RST'] = 0
        except:
            self.flags['RST'] = 0

    def setPSHFlag(self, pkt):
        try:
            if TCP in pkt:
                self.flags['PSH'] = 1 if pkt[TCP].flags.P else 0
            else:
                self.flags['PSH'] = 0
        except:
            self.flags['PSH'] = 0

    def setACKFlag(self, pkt):
        try:
            if TCP in pkt:
                self.flags['ACK'] = 1 if pkt[TCP].flags.A else 0
            else:
                self.flags['ACK'] = 0
        except:
            self.flags['ACK'] = 0

    def setURGFlag(self, pkt):
        try:
            if TCP in pkt:
                self.flags['URG'] = 1 if pkt[TCP].flags.U else 0
            else:
                self.flags['URG'] = 0
        except:
            self.flags['URG'] = 0

    def setFwdID(self):
        try:
            self.fwd_id = f"{self.src_ip}_{self.dst_ip}_{self.src_port}_{self.dst_port}_{self.protocol}"
        except:
            self.fwd_id = "unknown_flow"

    def setBwdID(self):
        try:
            self.bwd_id = f"{self.dst_ip}_{self.src_ip}_{self.dst_port}_{self.src_port}_{self.protocol}"
        except:
            self.bwd_id = "unknown_flow"

    def getFwdID(self):
        return getattr(self, 'fwd_id', 'unknown_flow')

    def getBwdID(self):
        return getattr(self, 'bwd_id', 'unknown_flow')