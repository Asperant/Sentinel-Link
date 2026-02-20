import socket
import struct

HOST = "0.0.0.0"
PORT = 5000

PACKET_FORMAT = '<iff'

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((HOST,PORT))

print(f"GKS(Binary Mod) Dinlemeye Başladı {HOST}:{PORT}")

while True:
    data, address = server_socket.recvfrom(1024)

    if(len(data) == struct.calcsize(PACKET_FORMAT)):
        uav_id, speed, battery = struct.unpack(PACKET_FORMAT,data)

        print(f"📥 [İHA-{uav_id}] Veri Geldi | Hız: {speed:.1f} km/h | 🔋 Batarya: %{battery:.1f}")
    
    else:
        print(f"⚠️ Hatalı paket boyutu geldi! Beklenen: 12, Gelen: {len(data)}")