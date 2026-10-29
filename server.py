from flask import Flask
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import numpy as np
import xgboost as xgb
import joblib
import threading
import time
import os
import random
from collections import defaultdict
import csv

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

FLOW_TIMEOUT = 5.0
FLOW_CHECK_INTERVAL = 1.0
LOG_FILE = "traffic_logs.csv"

LOCAL_SAVE_PATH = r"modeller"
SIM_DATA_FILE = "canli_test_seti.csv"

class DummyNetworkGuard:
    def process_flow(self, df): return "NORMAL", "Gatekeeper (Dummy)", 100.0

class NetworkGuardSystem:
    def __init__(self, binary_booster, expert_model, label_encoder, feature_columns):
        self.gatekeeper = binary_booster 
        self.expert = expert_model
        self.le = label_encoder
        self.features = feature_columns

    def process_flow(self, flow_features_df):
        try:
            model_input = flow_features_df[self.features]
            
            dmatrix_input = xgb.DMatrix(model_input)
            attack_prob = self.gatekeeper.predict(dmatrix_input)[0] 

            if attack_prob > 0.5:
                attack_code = self.expert.predict(model_input)[0]
                attack_name = self.le.inverse_transform([attack_code])[0]
                confidence = float(self.expert.predict_proba(model_input).max() * 100)
                return attack_name, "Expert Model", confidence
            else:
                return "NORMAL", "Gatekeeper", float((1.0 - attack_prob) * 100)
        except Exception as e:
            print(f"🔄 Model Tahmin Hatası: {e}")
            return "HATA", "System", 0.0

system_instance = None
feature_list = []
binary_path = os.path.join(LOCAL_SAVE_PATH, 'xgb_binary_model.json')
expert_path = os.path.join(LOCAL_SAVE_PATH, 'rf_multiclass_model.pkl')
le_path = os.path.join(LOCAL_SAVE_PATH, 'label_encoder.pkl')

if os.path.exists(binary_path) and os.path.exists(expert_path) and os.path.exists(le_path):
    try:
        loaded_gatekeeper = xgb.Booster()
        loaded_gatekeeper.load_model(binary_path)
        
        loaded_expert = joblib.load(expert_path)
        loaded_le = joblib.load(le_path)
        
        feature_list = list(loaded_gatekeeper.feature_names)
        
        system_instance = NetworkGuardSystem(loaded_gatekeeper, loaded_expert, loaded_le, feature_list)
        print("🎉 [MÜKEMMEL] Yapay Zeka Gerçek Çekirdeğiyle Başarıyla Yüklendi! Canlı Defans Aktif.")
    except Exception as e:
        print(f"❌ Kritik Hata (Dummy Moda Geçiliyor): {e}")
        system_instance = DummyNetworkGuard()
else:
    print(f"⚠️ HATA: Dosyalar '{LOCAL_SAVE_PATH}' klasöründe bulunamadı! Dummy sistem devrede.")
    system_instance = DummyNetworkGuard()

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, mode='w', newline='', encoding='utf-8') as f:
        csv.writer(f).writerow(["Timestamp", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Label", "Confidence"])

class FlowManager:
    def __init__(self):
        self.active_flows = {}
        self.lock = threading.Lock()

    def update(self, packet_info):
        key = packet_info['key']
        timestamp = packet_info['timestamp']
        length = packet_info['length']
        flags = packet_info['flags']
        direction = packet_info['direction']

        with self.lock:
            if key not in self.active_flows:
                self.active_flows[key] = {
                    'start_time': timestamp, 'last_time': timestamp,
                    'fwd_lengths': [], 'bwd_lengths': [],
                    'iat_list': [], 'fwd_iat': [], 'bwd_iat': [],
                    'last_fwd_time': None, 'last_bwd_time': None,
                    'SYN_count': 0, 'FIN_count': 0, 'RST_count': 0, 'PSH_count': 0, 'ACK_count': 0,
                    'src_ip': key[0], 'dst_ip': key[1], 'src_port': key[2], 'dst_port': key[3], 'protocol': key[4]
                }
            
            flow = self.active_flows[key]
            
            if flow['last_time']:
                flow['iat_list'].append((timestamp - flow['last_time']) * 1_000_000)
            
            if direction == 'Fwd':
                flow['fwd_lengths'].append(length)
                if flow['last_fwd_time']:
                    flow['fwd_iat'].append((timestamp - flow['last_fwd_time']) * 1_000_000)
                flow['last_fwd_time'] = timestamp
            else:
                flow['bwd_lengths'].append(length)
                if flow['last_bwd_time']:
                    flow['bwd_iat'].append((timestamp - flow['last_bwd_time']) * 1_000_000)
                flow['last_bwd_time'] = timestamp

            flow['last_time'] = timestamp

            if flags:
                if 'S' in flags: flow['SYN_count'] += 1
                if 'F' in flags: flow['FIN_count'] += 1
                if 'R' in flags: flow['RST_count'] += 1
                if 'P' in flags: flow['PSH_count'] += 1
                if 'A' in flags: flow['ACK_count'] += 1

    def check_timeouts_and_predict(self):
        current_time = time.time()
        flows_to_process = []
        with self.lock:
            keys_to_remove = []
            for key, flow in self.active_flows.items():
                if (current_time - flow['last_time']) > FLOW_TIMEOUT:
                    flows_to_process.append(flow)
                    keys_to_remove.append(key)
            for k in keys_to_remove: del self.active_flows[k]

        for flow in flows_to_process: self._analyze_flow(flow)

    def _analyze_flow(self, flow):
        duration = max(flow['last_time'] - flow['start_time'], 0.001)
        fwd_len = flow['fwd_lengths']
        bwd_len = flow['bwd_lengths']
        total_packets = len(fwd_len) + len(bwd_len)
        total_bytes = sum(fwd_len) + sum(bwd_len)

        features = {
            'Flow Duration': duration * 1_000_000,
            'Total Fwd Packets': len(fwd_len),
            'Total Backward Packets': len(bwd_len),
            'Total Length of Fwd Packets': sum(fwd_len),
            'Total Length of Bwd Packets': sum(bwd_len),
            'Fwd Packet Length Max': np.max(fwd_len) if fwd_len else 0,
            'Fwd Packet Length Min': np.min(fwd_len) if fwd_len else 0,
            'Fwd Packet Length Mean': np.mean(fwd_len) if fwd_len else 0,
            'Fwd Packet Length Std': np.std(fwd_len) if fwd_len else 0,
            'Bwd Packet Length Max': np.max(bwd_len) if bwd_len else 0,
            'Bwd Packet Length Min': np.min(bwd_len) if bwd_len else 0,
            'Bwd Packet Length Mean': np.mean(bwd_len) if bwd_len else 0,
            'Bwd Packet Length Std': np.std(bwd_len) if bwd_len else 0,
            'Flow Bytes/s': total_bytes / duration,
            'Flow Packets/s': total_packets / duration,
            'Flow IAT Mean': np.mean(flow['iat_list']) if flow['iat_list'] else 0,
            'Flow IAT Std': np.std(flow['iat_list']) if flow['iat_list'] else 0,
            'Flow IAT Max': np.max(flow['iat_list']) if flow['iat_list'] else 0,
            'Flow IAT Min': np.min(flow['iat_list']) if flow['iat_list'] else 0,
            'Fwd IAT Total': sum(flow['fwd_iat']),
            'Fwd IAT Mean': np.mean(flow['fwd_iat']) if flow['fwd_iat'] else 0,
            'Fwd IAT Std': np.std(flow['fwd_iat']) if flow['fwd_iat'] else 0,
            'Fwd IAT Max': np.max(flow['fwd_iat']) if flow['fwd_iat'] else 0,
            'Fwd IAT Min': np.min(flow['fwd_iat']) if flow['fwd_iat'] else 0,
            'Bwd IAT Total': sum(flow['bwd_iat']),
            'Bwd IAT Mean': np.mean(flow['bwd_iat']) if flow['bwd_iat'] else 0,
            'Bwd IAT Std': np.std(flow['bwd_iat']) if flow['bwd_iat'] else 0,
            'Bwd IAT Max': np.max(flow['bwd_iat']) if flow['bwd_iat'] else 0,
            'Bwd IAT Min': np.min(flow['bwd_iat']) if flow['bwd_iat'] else 0,
            'SYN Flag Count': flow['SYN_count'],
            'FIN Flag Count': flow['FIN_count'],
            'RST Flag Count': flow['RST_count'],
            'PSH Flag Count': flow['PSH_count'],
            'ACK Flag Count': flow['ACK_count'],
            'Packet Length Mean': np.mean(fwd_len + bwd_len) if (fwd_len + bwd_len) else 0,
            'Packet Length Std': np.std(fwd_len + bwd_len) if (fwd_len + bwd_len) else 0,
            'Packet Length Variance': np.var(fwd_len + bwd_len) if (fwd_len + bwd_len) else 0,
            'Init_Win_bytes_forward': 29200 if flow['SYN_count'] > 0 else 0,
            'Init_Win_bytes_backward': 14600 if len(bwd_len) > 0 else 0
        }

        df = pd.DataFrame([features])
        if feature_list:
            for f in feature_list:
                if f not in df.columns: df[f] = 0.0

        label, source, conf = system_instance.process_flow(df)

        try:
            with open(LOG_FILE, mode='a', newline='', encoding='utf-8') as f:
                csv.writer(f).writerow([time.strftime("%Y-%m-%d %H:%M:%S"), flow['src_ip'], flow['src_port'], flow['dst_ip'], flow['dst_port'], flow['protocol'], label, f"{conf:.2f}"])
        except Exception: pass

        if label != "NORMAL":
            print(f"🚨 ALERT !!! Canlı Ağda {label} TESPİT EDİLDİ -> {flow['dst_ip']}")

        socketio.emit('new_packet', {
            'id': random.randint(10000, 999999), 'time': time.strftime("%H:%M:%S"),
            'src': flow['src_ip'], 'srcPort': flow['src_port'], 'dst': flow['dst_ip'], 'dstPort': flow['dst_port'],
            'flowBytes': float(features['Flow Bytes/s']), 'label': label, 'model': source, 'confidence': conf, 'is_attack': label != "NORMAL"
        })

flow_manager = FlowManager()

def packet_callback(packet):
    if IP in packet:
        try:
            src_ip = packet[IP].src; dst_ip = packet[IP].dst
            if dst_ip == "127.0.0.1" or src_ip == "127.0.0.1": return
            if dst_ip.startswith("224.") or dst_ip.startswith("239."): return

            proto = 0; src_port = 0; dst_port = 0; flags = ""
            if TCP in packet:
                proto = 6; src_port = packet[TCP].sport; dst_port = packet[TCP].dport; flags = packet[TCP].flags
            elif UDP in packet:
                proto = 17; src_port = packet[UDP].sport; dst_port = packet[UDP].dport
                if src_port in [53, 5353, 1900] or dst_port in [53, 5353, 1900]: return

            if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
                key = (src_ip, dst_ip, src_port, dst_port, proto); direction = 'Fwd'
            else:
                key = (dst_ip, src_ip, dst_port, src_port, proto); direction = 'Bwd'

            flow_manager.update({
                'key': key, 'timestamp': time.time(), 'length': len(packet), 'flags': str(flags), 'direction': direction
            })
        except Exception: pass

def flow_monitor_loop():
    while True:
        try:
            time.sleep(FLOW_CHECK_INTERVAL)
            flow_manager.check_timeouts_and_predict()
        except Exception: pass

def start_sniffing(): sniff(prn=packet_callback, store=False)

# def auto_real_data_simulation_loop():
#     print("[+] Simülatör Hazırlanıyor...")
#     while not os.path.exists(SIM_DATA_FILE):
#         print(f"⚠️ {SIM_DATA_FILE} bekleniyor... Notebook'ta ürettiğin 'canli_test_seti.csv' dosyasını bu klasöre at.")
#         time.sleep(5.0)

#     df_sim = pd.read_csv(SIM_DATA_FILE)
#     if 'Real_Target_Label' in df_sim.columns:
#         df_sim = df_sim.drop(columns=['Real_Target_Label'])

#     print(f"🎉 {SIM_DATA_FILE} BAŞARIYLA BAĞLANDI! Toplam {len(df_sim)} gerçek laboratuvar satırı döngüye girdi.")

#     while True:
#         try:
#             time.sleep(10.0) # Tam 10 saniyede bir uyanır
            
#             satir_df = df_sim.sample(n=1)
            
#             src_ip = f"172.16.1.{random.randint(10, 254)}"
#             dst_ip = "192.168.1.108"
#             src_port = random.randint(1025, 65535)
#             dst_port = 80
#             protocol = 6

#             label, source, conf = system_instance.process_flow(satir_df)

#             timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
#             print(f"🤖 [KUSURSUZ PANEL SİMÜLASYONU] -> Orijinal Satır Soruldu | Yapay Zeka Teşhisi: {label} (%{conf:.2f}) [{source}]")

#             try:
#                 with open(LOG_FILE, mode='a', newline='', encoding='utf-8') as f:
#                     csv.writer(f).writerow([timestamp, src_ip, src_port, dst_ip, dst_port, protocol, label, f"{conf:.2f}"])
#             except Exception: pass

#             flow_bytes = float(satir_df['Flow Bytes/s'].iloc[0]) if 'Flow Bytes/s' in satir_df.columns else 4500.0
#             socketio.emit('new_packet', {
#                 'id': random.randint(10000, 999999), 'time': time.strftime("%H:%M:%S"),
#                 'src': src_ip, 'srcPort': src_port, 'dst': dst_ip, 'dstPort': dst_port,
#                 'flowBytes': flow_bytes, 'label': label, 'model': source, 'confidence': conf, 'is_attack': label != "NORMAL"
#             })
#         except Exception as e:
#             print(f"Simülasyon döngü hatası: {e}")


if __name__ == '__main__':
    threading.Thread(target=start_sniffing, daemon=True).start()

    threading.Thread(target=flow_monitor_loop, daemon=True).start()

    #threading.Thread(target=auto_real_data_simulation_loop, daemon=True).start()

    print("🚀 IDS Sunucusu (Gerçek Çekirdek + Canlı Mod) http://localhost:5000 portunda aktiftir...")
    socketio.run(app, port=5000, allow_unsafe_werkzeug=True)