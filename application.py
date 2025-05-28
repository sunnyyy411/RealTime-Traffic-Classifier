from flask_socketio import SocketIO, emit
from flask import Flask, render_template
from threading import Thread, Event
from flow.PacketInfo import PacketInfo
from flow.Flow import Flow
import numpy as np
import tensorflow as tf
import csv
import os
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

# Create logs directory
os.makedirs('logs', exist_ok=True)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
input_log_file = f'logs/input_logs_{timestamp}.csv'
output_log_file = f'logs/output_logs_{timestamp}.csv'

try:
    f_out = open(output_log_file, 'w', newline='')
    w_out = csv.writer(f_out)
    f_in = open(input_log_file, 'w', newline='')
    w_in = csv.writer(f_in)

    # Output log headers
    w_out.writerow(['Flow Analysis Results'])
    w_out.writerow(['Timestamp:', timestamp])
    w_out.writerow([])
    w_out.writerow(['FlowID', 'SourceIP', 'SourcePort', 'DestIP', 'DestPort', 'Protocol', 'Classification'])

    # Input log headers
    w_in.writerow(['Input Flow Data'])
    w_in.writerow(['Timestamp:', timestamp])
    w_in.writerow([])
    w_in.writerow(['Timestamp'] + [f'{i+1}' for i in range(54)])
except Exception as e:
    f_out = f_in = w_out = w_in = None

flow_count = 0
current_flows = {}
thread_stop_event = Event()
thread = None

# Feature list used by model
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

# Normalization values from training data
FEATURE_MEANS = {
    'Dst Port': 49204.78646561142,
    'Protocol': 6.00326587549098,
    'Flow Duration': 0.3621486419277787,
    'Tot Fwd Pkts': 2.859141414792125,
    'Tot Bwd Pkts': 2.5732272633129003,
    'TotLen Fwd Pkts': 1532.041961927413,
    'Fwd Pkt Len Max': 1460.0,
    'Fwd Pkt Len Min': 40.0,
    'Fwd Pkt Len Mean': 535.8928571428571,
    'Fwd Pkt Len Std': 396.1827808423427,
    'Bwd Pkt Len Max': 1460.0,
    'Bwd Pkt Len Min': 40.0,
    'Bwd Pkt Len Mean': 495.55555555555554,
    'Bwd Pkt Len Std': 380.2920380706224,
    'Flow Byts/s': 8553.569023569024,
    'Flow Pkts/s': 15.032658754909802,
    'Flow IAT Mean': 0.024691358024691357,
    'Flow IAT Std': 0.04700807279015142,
    'Flow IAT Max': 0.25,
    'Flow IAT Min': 0.0,
    'Fwd IAT Tot': 0.0,
    'Fwd IAT Mean': 0.0,
    'Fwd IAT Std': 0.0,
    'Fwd IAT Max': 0.0,
    'Fwd IAT Min': 0.0,
    'Bwd IAT Tot': 0.0,
    'Bwd IAT Mean': 0.0,
    'Bwd IAT Std': 0.0,
    'Bwd IAT Max': 0.0,
    'Bwd IAT Min': 0.0,
    'Fwd PSH Flags': 0.0,
    'Bwd PSH Flags': 0.0,
    'Fwd URG Flags': 0.0,
    'Bwd URG Flags': 0.0,
    'Fwd Header Len': 1480,
    'Fwd Pkts/s': 1.480246913580247,
    'Bwd Pkts/s': 1.3395061728395062,
    'Pkt Len Min': 40.0,
    'Pkt Len Mean': 517.8024691358025,
    'Pkt Len Std': 389.4008801229892,
    'Pkt Len Var': 151633.03703703703,
    'FIN Flag Cnt': 0.0,
    'SYN Flag Cnt': 1.0,
    'RST Flag Cnt': 0.0,
    'ACK Flag Cnt': 1.0,
    'URG Flag Cnt': 0.0,
    'CWE Flag Count': 0.0,
    'ECE Flag Cnt': 0.0,
    'Down/Up Ratio': 1.1111111111111112,
    'Fwd Seg Size Min': 52,
    'Active Mean': 0.0,
    'Active Std': 0.0,
    'Active Max': 0.0,
    'Active Min': 0.0
}

FEATURE_STDS = {
    'Dst Port': 39321.60712872588,
    'Protocol': 0.05749049894526575,
    'Flow Duration': 0.7246922641101408,
    'Tot Fwd Pkts': 4.745061728395062,
    'Tot Bwd Pkts': 4.262345679012346,
    'TotLen Fwd Pkts': 2649.8024691358023,
    'Fwd Pkt Len Max': 0.0,
    'Fwd Pkt Len Min': 0.0,
    'Fwd Pkt Len Mean': 0.0,
    'Fwd Pkt Len Std': 0.0,
    'Bwd Pkt Len Max': 0.0,
    'Bwd Pkt Len Min': 0.0,
    'Bwd Pkt Len Mean': 0.0,
    'Bwd Pkt Len Std': 0.0,
    'Flow Byts/s': 17320.508075688772,
    'Flow Pkts/s': 10.0,
    'Flow IAT Mean': 0.04700807279015142,
    'Flow IAT Std': 0.04700807279015142,
    'Flow IAT Max': 0.25,
    'Flow IAT Min': 0.0,
    'Fwd IAT Tot': 0.0,
    'Fwd IAT Mean': 0.0,
    'Fwd IAT Std': 0.0,
    'Fwd IAT Max': 0.0,
    'Fwd IAT Min': 0.0,
    'Bwd IAT Tot': 0.0,
    'Bwd IAT Mean': 0.0,
    'Bwd IAT Std': 0.0,
    'Bwd IAT Max': 0.0,
    'Bwd IAT Min': 0.0,
    'Fwd PSH Flags': 0.0,
    'Bwd PSH Flags': 0.0,
    'Fwd URG Flags': 0.0,
    'Bwd URG Flags': 0.0,
    'Fwd Header Len': 0.0,
    'Fwd Pkts/s': 0.0,
    'Bwd Pkts/s': 0.0,
    'Pkt Len Min': 0.0,
    'Pkt Len Mean': 0.0,
    'Pkt Len Std': 0.0,
    'Pkt Len Var': 0.0,
    'FIN Flag Cnt': 0.0,
    'SYN Flag Cnt': 0.0,
    'RST Flag Cnt': 0.0,
    'ACK Flag Cnt': 0.0,
    'URG Flag Cnt': 0.0,
    'CWE Flag Count': 0.0,
    'ECE Flag Cnt': 0.0,
    'Down/Up Ratio': 0.0,
    'Fwd Seg Size Min': 0.0,
    'Active Mean': 0.0,
    'Active Std': 0.0,
    'Active Max': 0.0,
    'Active Min': 0.0
}

# Load model
model = None
try:
    print("Loading recovered model...")
    model = tf.keras.models.load_model('rescnn_reptile_plus_plus_best_model.h5', compile=False)
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    print("✅ Model loaded and compiled successfully.")
except Exception as e:
    print(f"❌ Failed to load or compile model: {e}")

def preprocess_features(features_dict):
    """Normalize and reshape features"""
    df_values = []
    for name in REQUIRED_FEATURES:
        val = features_dict.get(name, 0.0)
        try:
            val = float(val)
        except:
            val = 0.0
        mean = FEATURE_MEANS[name]
        std = FEATURE_STDS[name]
        norm_val = (val - mean) / std if std != 0 else 0.0
        df_values.append(np.clip(norm_val, -5, 5))  # Clip outliers
    assert len(df_values) == 54, f"Expected 54 features, got {len(df_values)}"
    return np.array(df_values, dtype=np.float32).reshape((1, 54, 1))

def classify(raw_features, metadata=None):
    global flow_count
    if not raw_features or model is None:
        return None

    confidence = 0.0
    classification = -1
    input_array = None

    try:
        input_array = preprocess_features(raw_features)
        prediction = model.predict(input_array, verbose=0)
        raw_score = float(prediction[0][0])
        classification = int(raw_score > 0.65)  # Lower threshold
        confidence = abs(0.5 - raw_score) * 2

        print("\n--- RAW FEATURES ---")
        for key, value in raw_features.items():
            print(f"{key}: {value}")
        print("--------------------")
        print(f"[MODEL] Raw Score: {raw_score:.4f} | Confidence: {confidence:.2f} → Class: {'Malicious' if classification else 'Normal'}\n")

    except Exception as e:
        print(f"[ERROR] Prediction failed: {e}")
        classification = -1

    src_ip = metadata.get('source_ip', 'N/A')
    dst_ip = metadata.get('dest_ip', 'N/A')
    src_port = metadata.get('source_port', 'N/A')
    dst_port = metadata.get('dest_port', 'N/A')
    proto = metadata.get('protocol', 'N/A')
    class_str = 'Malicious' if classification == 1 else 'Normal'

    # Log to files
    if input_array is not None and w_in:
        try:
            numeric_features = input_array.flatten().tolist()
            w_in.writerow([datetime.now().isoformat()] + numeric_features)
            f_in.flush()
        except Exception as e:
            print(f"[ERROR] Failed to log input data: {e}")

    if w_out:
        try:
            w_out.writerow([
                str(flow_count),
                src_ip, src_port,
                dst_ip, dst_port,
                proto,
                class_str
            ])
            f_out.flush()
        except Exception as e:
            print(f"[ERROR] Failed to log output data: {e}")

    flow_count += 1
    result = {
        'flow_id': str(flow_count),
        'source_ip': src_ip,
        'dest_ip': dst_ip,
        'source_port': src_port,
        'dest_port': dst_port,
        'protocol': proto,
        'classification': classification
    }
    emit_result(result, [])
    return result

def emit_result(result_data, ip_stats):
    socketio.emit('newresult', {
        'result': result_data,
        'ips': ip_stats
    }, namespace='/test')

def process_timed_out_flows():
    now = datetime.now()
    to_process = []
    for fid, flow in list(current_flows.items()):
        elapsed = now.timestamp() - flow.last_seen
        timeout = 60 if flow.proto == 17 else 120
        if elapsed > timeout:
            to_process.append(fid)
    for fid in to_process:
        try:
            flow = current_flows.pop(fid)
            features = flow.terminated()
            if len(features) >= 3:
                classify(features, flow.get_metadata())
        except Exception as e:
            print(f"[ERROR] Flow termination failed: {e}")

def flow_timeout_checker():
    while not thread_stop_event.is_set():
        process_timed_out_flows()
        socketio.sleep(5)

def newPacket(pkt):
    if not pkt.haslayer(IP):
        return
    try:
        packet_info = PacketInfo()
        packet_info.setTimestamp(pkt)
        packet_info.setSrc(pkt)
        packet_info.setDest(pkt)
        packet_info.setSrcPort(pkt)
        packet_info.setDestPort(pkt)
        packet_info.setProtocol(pkt)
        if pkt.haslayer(TCP):
            packet_info.setPSHFlag(pkt)
            packet_info.setFINFlag(pkt)
            packet_info.setSYNFlag(pkt)
            packet_info.setACKFlag(pkt)
            packet_info.setURGFlag(pkt)
            packet_info.setRSTFlag(pkt)
        packet_info.setHeaderBytes(pkt)
        packet_info.setPayloadBytes(pkt)
        packet_info.setPacketSize(pkt)
        packet_info.setWinBytes(pkt)
        packet_info.setFwdID()
        packet_info.setBwdID()

        fwd_id = packet_info.getFwdID()
        bwd_id = packet_info.getBwdID()
        flow_id = None

        if fwd_id in current_flows:
            flow = current_flows[fwd_id]
            flow.new(packet_info, 'fwd')
            flow_id = fwd_id
        elif bwd_id in current_flows:
            flow = current_flows[bwd_id]
            flow.new(packet_info, 'bwd')
            flow_id = bwd_id
        else:
            flow = Flow(packet_info)
            current_flows[fwd_id] = flow
            flow_id = fwd_id

        if flow_id:
            flow = current_flows[flow_id]
            features = flow.terminated()
            if len(features) >= 3:
                classify(features, flow.get_metadata())

    except Exception as e:
        print(f"[ERROR] Packet processing failed: {e}")

def packet_callback(pkt):
    if IP in pkt:
        if pkt[IP].src.startswith('127.') or pkt[IP].dst.startswith('127.'):
            return
        newPacket(pkt)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect', namespace='/test')
def test_connect():
    global thread
    if thread is None or not thread.is_alive():
        thread = socketio.start_background_task(snif_and_detect)
    socketio.start_background_task(flow_timeout_checker)

@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    pass

def close_log_files():
    if 'f_out' in globals() and f_out and not f_out.closed:
        f_out.close()
    if 'f_in' in globals() and f_in and not f_in.closed:
        f_in.close()

import atexit
atexit.register(close_log_files)

def snif_and_detect():
    iface = "Wi-Fi"
    try:
        sniff(
            iface=iface,
            prn=packet_callback,
            filter="tcp",
            store=0
        )
    except Exception as e:
        print(f"[ERROR] Sniffer failed: {e}")

if __name__ == '__main__':
    socketio.run(app, use_reloader=False, host='0.0.0.0', port=5001)
