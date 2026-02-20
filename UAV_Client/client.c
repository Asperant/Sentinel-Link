#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <math.h>
#include <stdint.h>

#define SERVER_IP "172.18.0.3"
#define PORT 5000
#define GPS_SCALE 10000000.0

typedef enum{
    MODE_MANUAL = 0,
    MODE_AUTONOMUS = 1,
    MODE_RTL = 2
}FlightMode;

struct TelemetryPacket{
    unsigned char magic_byte;
    uint32_t seq_num;
    uint64_t timestamp;
    int32_t uav_id;
    int32_t latitude;
    int32_t longitude;
    float altitude;
    float speed;
    float battery;
    uint8_t flight_mode;
    uint32_t crc32;
} __attribute__((packed));

uint64_t get_time_ms(){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)(tv.tv_sec) * 1000 + (uint64_t)(tv.tv_usec) / 1000;
}

uint32_t calculate_crc32(const unsigned char *data, size_t length){
    uint32_t crc = 0xFFFFFFFF;
    for(size_t i = 0; i < length; i++){
        crc ^= data[i];
        for(int j = 0; j < 8; j++){
            if(crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
            else crc >>= 1;
        }
    }
    return ~crc;
}

int main(){
    int sockfd;
    struct sockaddr_in server_addr;
    struct TelemetryPacket packet;

    float angle = 0.0;
    float current_lat = 37.8715;
    float current_lon = 32.4930;
    uint32_t current_seq = 1;

    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("Socket oluşturulamadı");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    printf("İHA Başlatıldı. Hedef: %s %d\n",SERVER_IP, PORT);

    packet.magic_byte = 0xFF;
    packet.uav_id = 101;
    packet.battery = 100.0;
    packet.flight_mode = MODE_AUTONOMUS;

    while(1){

        current_lat = 37.8715 + (0.001 * sin(angle));
        current_lon = 32.4930 + (0.001 * cos(angle));

        packet.latitude = (int32_t)(current_lat * GPS_SCALE);
        packet.longitude = (int32_t)(current_lon * GPS_SCALE);

        packet.altitude = 500 + (10 * sin(angle * 2));
        packet.speed = 80 + (rand() % 10);
        packet.battery -=  0.05;

        if(packet.battery < 0) packet.battery = 0;
        angle += 0.1;

        packet.seq_num = current_seq;
        packet.timestamp = get_time_ms();
        
        size_t data_length = sizeof(packet) - sizeof(uint32_t);
        packet.crc32 = calculate_crc32((const unsigned char*)&packet, data_length);

        sendto(sockfd, &packet, sizeof(packet), 0, (const struct sockaddr*)&server_addr, sizeof(server_addr));

        printf("📤 Paket #%d | Zaman: %llu ms | Boyut: %lu byte | CRC: %X\n", 
               packet.seq_num, (unsigned long long)packet.timestamp, (unsigned long)sizeof(packet), packet.crc32);
        
        current_seq++;
        sleep(1);
    }

    close(sockfd);
    return 0;
}