import socket
import struct
import random
import redis
import psycopg2
import time
import os
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

GKS_ID = random.randint(10,99)
HOST = "0.0.0.0"
PORT = 5000
GPS_SCALE = 10000000.0

UNPACK_FORMAT = '<IQiifffBB' 
ACK_FORMAT = '<BIQ'

DB_HOST = os.getenv("DB_HOST", "sentinel_db")
DB_USER = os.getenv("DB_USER", "admin")
DB_PASS = os.getenv("DB_PASS", "password123")
DB_NAME = os.getenv("DB_NAME", "sentinel_hq")
REDIS_HOST = os.getenv("REDIS_HOST", "redis_db")

def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

try:
    GKS_PRIVATE_KEY = load_private_key("../keys/gks_private.pem")
    UAV_PUBLIC_KEY = load_public_key("../keys/uav_public.pem")
except Exception as e:
    print(f"❌ [KRİTİK HATA] Asimetrik Anahtarlar okunamadı! 'keys' klasörünü kontrol edin. Hata: {e}")
    exit(1)

uav_session_keys = {}

def connect_to_db():
    conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
    conn.autocommit = True
    return conn, conn.cursor()

def connect_to_redis():
    client = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)
    client.ping()
    return client

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((HOST, PORT))

try:
    pg_conn, pg_cursor = connect_to_db()
    r = connect_to_redis()
    print(f"🗄️ [GKS-{GKS_ID}] PostgreSQL ve Redis Bağlantıları Başarılı!")
except Exception as e:
    print(f"❌ Başlatma Hatası: {e}")
    exit(1)

print(f"🛡️ [GKS-{GKS_ID}] SIFIR GÜVEN (Zero Trust) ECDH-ECDSA Kalkanı Aktif!")
print(f"📊 [GKS-{GKS_ID}] Dinlemede...\n")

RATE_LIMIT_PER_SECOND = 100
ip_packet_counts = defaultdict(int)
last_rate_limit_reset = time.time()
local_fec_windows = {}
last_valid_timestamps = {}

while True:
    try:
        current_time = time.time()
        if current_time - last_rate_limit_reset >= 1.0:
            ip_packet_counts.clear()
            last_rate_limit_reset = current_time

        data, address = server_socket.recvfrom(2048)
        
        ip_addr = address[0]
        ip_packet_counts[ip_addr] += 1
        if ip_packet_counts[ip_addr] > RATE_LIMIT_PER_SECOND:
            continue 

        magic_byte = data[0]

        if magic_byte == 0xDD:
            uav_id = struct.unpack('<i', data[1:5])[0]
            uav_pub_key_bytes = data[5:70]
            sig_len = data[70]
            signature = data[71:71+sig_len]

            payload_to_verify = data[1:70]
            try:
                UAV_PUBLIC_KEY.verify(signature, payload_to_verify, ec.ECDSA(hashes.SHA256()))
                print(f"🔐 [KİMLİK DOĞRULANDI] İHA-{uav_id} filoya ait!")
            except Exception:
                print(f"🛑 [SİBER SALDIRI] İHA-{uav_id} sahte kimlik sundu! IP: {ip_addr}")
                continue

            gks_ephemeral_private = ec.generate_private_key(ec.SECP256R1())
            gks_ephemeral_public_bytes = gks_ephemeral_private.public_key().public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )

            uav_ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), uav_pub_key_bytes)
            shared_key = gks_ephemeral_private.exchange(ec.ECDH(), uav_ephemeral_public)
            
            session_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake').derive(shared_key)
            uav_session_keys[uav_id] = AESGCM(session_key)
            print(f"🔑 [ŞİFRE OLUŞTURULDU] İHA-{uav_id} için tek kullanımlık AES-256 zırhı hazır!")

            gks_signature = GKS_PRIVATE_KEY.sign(gks_ephemeral_public_bytes, ec.ECDSA(hashes.SHA256()))
            response_pkt = struct.pack('<B', 0xEE) + gks_ephemeral_public_bytes + struct.pack('<B', len(gks_signature)) + gks_signature
            server_socket.sendto(response_pkt, address)
            continue

        if magic_byte not in [0xFF, 0xFE]: continue
        
        if len(data) < 33: continue 
        
        uav_id = struct.unpack('<i', data[1:5])[0]
        
        if uav_id not in uav_session_keys:
            if current_time - last_valid_timestamps.get(f"reset_{uav_id}", 0) > 2.0:
                print(f"⚠️ İHA-{uav_id} oturumu bulunamadı! RESET sinyali gönderiliyor...")
                server_socket.sendto(struct.pack('<B', 0xBB), address)
                last_valid_timestamps[f"reset_{uav_id}"] = current_time
            continue

        iv = data[5:17]
        ciphertext = data[17:-16]
        auth_tag = data[-16:]

        aad = data[1:5]
        
        try:
            decrypted_payload = uav_session_keys[uav_id].decrypt(iv, ciphertext + auth_tag, associated_data = aad)
        except InvalidTag:
            print(f"⚠️ [SPOOFING] Sahte paket reddedildi! IP: {ip_addr}")
            continue

        if len(decrypted_payload) != struct.calcsize(UNPACK_FORMAT): continue

        unpacked_data = struct.unpack(UNPACK_FORMAT, decrypted_payload)
        seq_num, timestamp, lat_raw, lon_raw, alt, speed, batt, mode, priority = unpacked_data
        
        lat, lon = lat_raw / GPS_SCALE, lon_raw / GPS_SCALE
        uav_key = f"uav:{uav_id}"

        if magic_byte != 0xFE:
            if uav_id in last_valid_timestamps:
                if timestamp <= last_valid_timestamps[uav_id]:
                    ack_packet = struct.pack(ACK_FORMAT, 0xAA, seq_num, timestamp)
                    server_socket.sendto(ack_packet, address)
                    continue
            last_valid_timestamps[uav_id] = max(timestamp, last_valid_timestamps.get(uav_id, 0))
        
        if not r.exists(uav_key):
            pg_cursor.execute("INSERT INTO uav_registery (uav_id) VALUES (%s) ON CONFLICT (uav_id) DO NOTHING;", (uav_id,))
            pg_cursor.execute("INSERT INTO flight_sessions (uav_id) VALUES (%s) RETURNING session_id;", (uav_id,))
            new_session_id = pg_cursor.fetchone()[0]

            r.hset(uav_key, mapping={
                "expected_seq_num": 0, "total_received": 0, "total_lost": 0,
                "recovered_packets": 0, "last_seen_by": GKS_ID, "session_id": new_session_id
            })
            local_fec_windows[uav_id] = {}

        if uav_id not in local_fec_windows:
            local_fec_windows[uav_id] = {}

        state = r.hgetall(uav_key)
        expected_seq_num = int(state["expected_seq_num"])
        total_received = int(state["total_received"])
        total_lost = int(state["total_lost"])
        recovered_packets = int(state["recovered_packets"])
        last_seen_by = int(state["last_seen_by"])
        current_session_id = int(state.get("session_id", 0))

        if last_seen_by != GKS_ID:
            r.hset(uav_key, "last_seen_by", GKS_ID)

        if magic_byte == 0xFE:
            if len(local_fec_windows[uav_id]) == 2:
                recovered_payload = bytearray(decrypted_payload)
                for stored_seq in local_fec_windows[uav_id]:
                    stored_data = local_fec_windows[uav_id][stored_seq]
                    for i in range(len(recovered_payload)):
                        recovered_payload[i] ^= stored_data[i]
                
                rec_seq = struct.unpack('<I', recovered_payload[0:4])[0]
                print(f"🪄 [FEC SİHİRİ] İHA-{uav_id} Paket #{rec_seq} ŞİFRELİ OLARAK KURTARILDI!")

                if total_lost > 0:
                    r.hincrby(uav_key, "total_lost", -1)
                    total_lost -= 1
                r.hincrby(uav_key, "recovered_packets", 1)
                recovered_packets += 1
            local_fec_windows[uav_id].clear()
            continue

        try:
            pg_cursor.execute("""
                INSERT INTO telemetry_logs (session_id, gks_id, seq_num, latitude, longitude, altitude, speed, battery, flight_mode, priority)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (current_session_id, GKS_ID, seq_num, lat, lon, alt, speed, batt, mode, priority))
        except Exception:
            try:
                pg_conn, pg_cursor = connect_to_db()
            except Exception: pass

        r.hincrby(uav_key, "total_received", 1)
        total_received += 1
        
        next_expected = expected_seq_num
        if expected_seq_num == 0:
            next_expected = seq_num + 1
        else:
            if seq_num > expected_seq_num:
                lost_count = seq_num - expected_seq_num
                r.hincrby(uav_key, "total_lost", lost_count)
                total_lost += lost_count
                next_expected = seq_num + 1
            elif seq_num == expected_seq_num:
                next_expected = seq_num + 1
            else:
                 if priority == 1: 
                     r.hincrby(uav_key, "recovered_packets", 1)
                     recovered_packets += 1
                     if total_lost > 0:
                        r.hincrby(uav_key, "total_lost", -1)
                        total_lost -= 1
                 next_expected = expected_seq_num 

        r.hset(uav_key, "expected_seq_num", next_expected)

        total_processed = total_received + total_lost
        qos = (total_received / total_processed) * 100 if total_processed > 0 else 100.0
        prio_str = "🔴 KRİTİK" if priority == 1 else "🟢 AKAN"

        print(f"🛡️ [{prio_str}] [GKS-{GKS_ID} -> İHA-{uav_id}] Pkt #{seq_num} | 🔋 %{batt:.1f}")
        
        if priority == 1 and magic_byte != 0xFE:
            local_fec_windows[uav_id][seq_num] = decrypted_payload
            if len(local_fec_windows[uav_id]) > 3:
                oldest_seq = min(local_fec_windows[uav_id].keys())
                del local_fec_windows[uav_id][oldest_seq]

        ack_packet = struct.pack(ACK_FORMAT, 0xAA, seq_num, timestamp)
        server_socket.sendto(ack_packet, address)

    except Exception as e:
        try:
            r = connect_to_redis()
        except Exception: time.sleep(1)