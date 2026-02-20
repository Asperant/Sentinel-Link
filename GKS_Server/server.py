import socket
import struct
import zlib

HOST = "0.0.0.0"
PORT = 5000
GPS_SCALE = 10000000.0

PACKET_FORMAT = '<BIQiiifffBI'

MODES = {0:"Manuel",1:"Otonom",2:"Eve Dönüş"}

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((HOST,PORT))

print(f"GKS Dinlemeye Başladı {HOST}:{PORT}")

while True:
    try:
        data,address = server_socket.recvfrom(1024)
        expected_size = struct.calcsize(PACKET_FORMAT)

        if len(data) != expected_size:
            print(f"⚠️ Hatalı Paket Boyutu! Gelen: {len(data)}, Beklenen: {expected_size}")
            continue
        
        payload = data[:-4]
        calculated_crc = zlib.crc32(payload) & 0xFFFFFFFF

        unpacked_data = struct.unpack(PACKET_FORMAT,data)

        magic = unpacked_data[0]
        seq_num = unpacked_data[1]
        timestamp = unpacked_data[2]
        uav_id = unpacked_data[3]
        lat = unpacked_data[4] / GPS_SCALE
        lon = unpacked_data[5] / GPS_SCALE
        alt = unpacked_data[6]
        speed = unpacked_data[7]
        batt = unpacked_data[8]
        mode = unpacked_data[9]
        received_crc = unpacked_data[10]

        if magic != 0xFF:
            print(f"⛔ GEÇERSİZ İMZA! Magic Byte: {magic}")
            continue

        if calculated_crc != received_crc:
            print(f"☢️ BOZUK VERİ (CRC HATA)! Seq: {seq_num} | Çöpe Atıldı.")
            continue

        mode_str = MODES.get(mode,"BİLİNMİYOR")
        print(f"✅ [Paket #{seq_num}] İHA-{uav_id} | ⏱️ T: {timestamp} | 📍 GPS: {lat:.4f}, {lon:.4f} | 🛡️ CRC: OK")

    except Exception as e:
        print(f"Bir Hata oluştu: {e}")