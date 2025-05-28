from datetime import datetime
import numpy as np

REQUIRED_FEATURES = [
    'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean',
    'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
    'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot',
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s', 'Pkt Len Min',
    'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt',
    'SYN Flag Cnt', 'RST Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
    'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Fwd Seg Size Min',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min'
]

class Flow:
    def __init__(self, packet_info=None):
        self.forward_packets = []
        self.backward_packets = []
        self.start_time = datetime.now().timestamp()
        self.last_seen = self.start_time
        self.proto = 6  # Default protocol is TCP
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None

        if packet_info:
            self.add_packet(packet_info, direction='fwd')

    def add_packet(self, packet_info, direction='fwd'):
        if direction == 'fwd':
            self.forward_packets.append(packet_info)
        else:
            self.backward_packets.append(packet_info)

        self.last_seen = packet_info.timestamp

        if len(self.forward_packets) == 1:
            self.src_ip = packet_info.src_ip
            self.dst_ip = packet_info.dst_ip
            self.src_port = packet_info.src_port
            self.dst_port = packet_info.dst_port
            self.proto = packet_info.protocol

    def new(self, packet_info, direction):
        self.add_packet(packet_info, direction)

    def get_metadata(self):
        return {
            'source_ip': str(self.src_ip or 'N/A'),
            'dest_ip': str(self.dst_ip or 'N/A'),
            'source_port': str(self.src_port or 'N/A'),
            'dest_port': str(self.dst_port or 'N/A'),
            'protocol': str(self.proto or 'N/A')
        }

    def terminated(self):
        try:
            all_packets = self.forward_packets + self.backward_packets
            if not all_packets:
                print("[INFO] Empty flow, skipping")
                return {}

            duration = abs(self.last_seen - self.start_time)
            if duration == 0:
                return {}

            # Extract packet sizes and timestamps
            fwd_sizes = [p.packet_size for p in self.forward_packets]
            bwd_sizes = [p.packet_size for p in self.backward_packets]
            all_sizes = [p.packet_size for p in all_packets]

            fwd_timestamps = [p.timestamp for p in self.forward_packets]
            bwd_timestamps = [p.timestamp for p in self.backward_packets]
            all_timestamps = [p.timestamp for p in all_packets]

            # Compute inter-arrival times (IATs)
            def safe_diff(timestamps):
                if len(timestamps) < 2:
                    return []
                return np.diff(np.array(timestamps))

            iats = safe_diff(all_timestamps)
            fwd_iats = safe_diff(fwd_timestamps)
            bwd_iats = safe_diff(bwd_timestamps)

            # Helper functions to compute stats safely
            def safe_stat(values, stat_func=np.mean):
                values = np.array(values)
                return float(stat_func(values)) if len(values) > 0 else 0.0

            def safe_min(values):
                values = np.array(values)
                return float(np.min(values)) if len(values) > 0 else 0.0

            def safe_max(values):
                values = np.array(values)
                return float(np.max(values)) if len(values) > 0 else 0.0

            def safe_std(values):
                values = np.array(values)
                return float(np.std(values)) if len(values) > 0 else 0.0

            # Forward packet stats
            fwd_pkt_len_mean = safe_stat(fwd_sizes, np.mean)
            fwd_pkt_len_std = safe_std(fwd_sizes)
            fwd_pkt_len_max = safe_max(fwd_sizes)
            fwd_pkt_len_min = safe_min(fwd_sizes)

            # Backward packet stats
            bwd_pkt_len_mean = safe_stat(bwd_sizes, np.mean)
            bwd_pkt_len_std = safe_std(bwd_sizes)
            bwd_pkt_len_max = safe_max(bwd_sizes)
            bwd_pkt_len_min = safe_min(bwd_sizes)

            # Flow-level stats
            flow_byts_s = sum(all_sizes) / duration if duration > 0 else 0
            flow_pkts_s = len(all_packets) / duration if duration > 0 else 0

            # IAT stats
            flow_iat_mean = safe_stat(iats, np.mean)
            flow_iat_std = safe_std(iats)
            flow_iat_max = safe_max(iats)
            flow_iat_min = safe_min(iats)

            # Fwd IAT
            fwd_iat_tot = float(np.sum(fwd_iats)) if len(fwd_iats) > 0 else 0
            fwd_iat_mean = safe_stat(fwd_iats, np.mean)
            fwd_iat_std = safe_std(fwd_iats)
            fwd_iat_max = safe_max(fwd_iats)
            fwd_iat_min = safe_min(fwd_iats)

            # Bwd IAT
            bwd_iats_array = np.array(bwd_iats)
            bwd_iat_tot = float(np.sum(bwd_iats_array)) if len(bwd_iats_array) > 0 else 0
            bwd_iat_mean = safe_stat(bwd_iats_array, np.mean)
            bwd_iat_std = safe_std(bwd_iats_array)
            bwd_iat_max = safe_max(bwd_iats_array)
            bwd_iat_min = safe_min(bwd_iats_array)

            # TCP flags
            fin_count = sum(p.flags.get('FIN', 0) for p in all_packets)
            syn_count = sum(p.flags.get('SYN', 0) for p in all_packets)
            rst_count = sum(p.flags.get('RST', 0) for p in all_packets)
            ack_count = sum(p.flags.get('ACK', 0) for p in all_packets)
            urg_count = sum(p.flags.get('URG', 0) for p in all_packets)
            psh_count = sum(p.flags.get('PSH', 0) for p in all_packets)

            # Packet length stats
            pkt_len_min = safe_min(all_sizes)
            pkt_len_mean = safe_stat(all_sizes, np.mean)
            pkt_len_std = safe_std(all_sizes)
            pkt_len_var = float(np.var(all_sizes)) if len(all_sizes) > 0 else 0

            # Down/Up ratio
            down_up_ratio = len(self.forward_packets) / max(1, len(self.backward_packets))

            # Active time stats
            active_times = iats if len(iats) > 0 else []
            active_mean = safe_stat(active_times, np.mean)
            active_std = safe_std(active_times)
            active_max = safe_max(active_times)
            active_min = safe_min(active_times)

            features = {
                'Dst Port': self.dst_port or 0,
                'Protocol': self.proto or 6,
                'Flow Duration': duration,
                'Tot Fwd Pkts': len(self.forward_packets),
                'Tot Bwd Pkts': len(self.backward_packets),
                'TotLen Fwd Pkts': sum(fwd_sizes) if fwd_sizes else 0,
                'Fwd Pkt Len Max': fwd_pkt_len_max,
                'Fwd Pkt Len Min': fwd_pkt_len_min,
                'Fwd Pkt Len Mean': fwd_pkt_len_mean,
                'Fwd Pkt Len Std': fwd_pkt_len_std,
                'Bwd Pkt Len Max': bwd_pkt_len_max,
                'Bwd Pkt Len Min': bwd_pkt_len_min,
                'Bwd Pkt Len Mean': bwd_pkt_len_mean,
                'Bwd Pkt Len Std': bwd_pkt_len_std,
                'Flow Byts/s': flow_byts_s,
                'Flow Pkts/s': flow_pkts_s,
                'Flow IAT Mean': flow_iat_mean,
                'Flow IAT Std': flow_iat_std,
                'Flow IAT Max': flow_iat_max,
                'Flow IAT Min': flow_iat_min,
                'Fwd IAT Tot': fwd_iat_tot,
                'Fwd IAT Mean': fwd_iat_mean,
                'Fwd IAT Std': fwd_iat_std,
                'Fwd IAT Max': fwd_iat_max,
                'Fwd IAT Min': fwd_iat_min,
                'Bwd IAT Tot': bwd_iat_tot,
                'Bwd IAT Mean': bwd_iat_mean,
                'Bwd IAT Std': bwd_iat_std,
                'Bwd IAT Max': bwd_iat_max,
                'Bwd IAT Min': bwd_iat_min,
                'Fwd PSH Flags': float(psh_count),
                'Bwd PSH Flags': float(psh_count),
                'Fwd URG Flags': float(urg_count),
                'Bwd URG Flags': float(urg_count),
                'Fwd Header Len': sum(p.header_bytes for p in self.forward_packets) if self.forward_packets else 0,
                'Fwd Pkts/s': len(self.forward_packets) / duration if duration > 0 and self.forward_packets else 0,
                'Bwd Pkts/s': len(self.backward_packets) / duration if duration > 0 and self.backward_packets else 0,
                'Pkt Len Min': pkt_len_min,
                'Pkt Len Mean': pkt_len_mean,
                'Pkt Len Std': pkt_len_std,
                'Pkt Len Var': pkt_len_var,
                'FIN Flag Cnt': float(fin_count),
                'SYN Flag Cnt': float(syn_count),
                'RST Flag Cnt': float(rst_count),
                'ACK Flag Cnt': float(ack_count),
                'URG Flag Cnt': float(urg_count),
                'CWE Flag Count': 0.0,
                'ECE Flag Cnt': 0.0,
                'Down/Up Ratio': float(down_up_ratio),
                'Fwd Seg Size Min': float(fwd_pkt_len_min) if fwd_pkt_len_min != 0 else 0.0,
                'Active Mean': float(active_mean),
                'Active Std': float(active_std),
                'Active Max': float(active_max),
                'Active Min': float(active_min)
            }

            # Ensure we only return required features
            feature_dict = {name: features[name] for name in REQUIRED_FEATURES}

            return feature_dict

        except Exception as e:
            print(f"[ERROR] Feature extraction failed: {e}")
            return {name: 0.0 for name in REQUIRED_FEATURES}
