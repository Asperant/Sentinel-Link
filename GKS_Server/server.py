import socket

HOST = "0.0.0.0"
PORT = 5000

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_socket.bind((HOST,PORT))

print(f"GKS Dinlemeye Başladı: {HOST}:{PORT}")

while True:
    message, address = server_socket.recvfrom(1024)

    print(f"Mesaj Geldi [{address}]: {message.decode('utf-8')}")