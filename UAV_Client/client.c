#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

struct TelemetryPacket{
    int uav_id;
    float speed;
    float battery;
} __attribute__((packed));

#define SERVER_IP "172.18.0.3"
#define PORT 5000

int main(){
    int sockfd;
    struct sockaddr_in server_addr;

    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("Socket oluşturulamadı");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    printf("İHA Başlatıldı. Hedef: %s %d\n",SERVER_IP, PORT);

    while(1){
        struct TelemetryPacket packet;
        packet.uav_id = 1;
        packet.speed = 125.5;
        packet.battery = 98.2;

        int sent_bytes = sendto(sockfd, &packet, sizeof(packet), 0, (const struct sockaddr*) &server_addr, sizeof(server_addr));

        if (sent_bytes < 0){
            perror("Mesaj Gönderilemedi");
        }
        else{
            printf("Binary Paket Gönderildi -> ID: %d | Hız: %.1f | Batarya: %.1f\n", 
                   packet.uav_id, packet.speed, packet.battery);
        }
        sleep(2);
    }
    close(sockfd);
    return 0;
}