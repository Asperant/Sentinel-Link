#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define SERVER_IP "172.18.0.3"
#define PORT 5000
#define BUFFER_SIZE 1024

int main(){
    int sockfd;
    struct sockaddr_in server_addr;
    char* message = "İHA-1: Uçuş Verisi [Hız: 100km/h]";

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
        sendto(sockfd, (const char*) message, strlen(message),
            MSG_CONFIRM, (const struct sockaddr*) &server_addr,
            sizeof(server_addr));
        
        printf("Mesaj Gönderildi: %s\n",message);

        sleep(2);
    }
    close(sockfd);
    return 0;
}