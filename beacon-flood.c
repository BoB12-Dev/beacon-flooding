#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

struct Radiotap_Frame {
    uint8_t header_revision;
    uint8_t header_pad;
    uint16_t header_length;
    uint32_t header_presentflag;
    uint8_t idontknow[3];
};

struct Beacon_Packet {
    uint16_t type;
    uint16_t duration;
    uint8_t destination_address[6];
    uint8_t source_address[6];
    uint8_t bssid[6];
    uint16_t sequence_number;
    struct {
        uint8_t tag_number;
        uint8_t tag_length;
        uint8_t ssid[32];
    } tag_ssid;
};

void generateRandomMac(u_int8_t *mac);
void initPacket(struct Beacon_Packet *packet, const char *ssid);
void printMacAddress(uint8_t *mac);

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <ssid-list-file>\n", argv[0]);
        return -1;
    }

    char *interfaceName = argv[1];
    char *filename = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(interfaceName, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interfaceName, errbuf);
        return -1;
    }

    FILE *fp;
    fp = fopen(filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "파일을 열 수 없습니다.\n");
        return 1;
    }

    char beacon_name[34];
    struct Beacon_Packet packet;

    while (true) {
        while ((fgets(beacon_name, sizeof(beacon_name), fp)) != 0) {
            // 파일에서 한 줄을 읽어와 flooding할 beacon name을 설정.
            char *ssid = strtok(beacon_name, "\r\n\t");
            

            // Beacon_Packet 구조체 초기화 함수 호출
            initPacket(&packet, ssid);
            // Source Address 설정
            generateRandomMac(packet.source_address);
            // 나머지 필요한 값들을 설정
            memcpy(packet.tag_ssid.ssid, ssid, 32);
            memcpy(packet.bssid, packet.source_address, 6);


            printMacAddress(packet.source_address);
            printf("ssid name : %s\n", ssid);
            // 패킷을 pcap으로 전송
            if (pcap_sendpacket(pcap, (unsigned char*)&packet, sizeof(packet)) != 0) {
                printf("send fail\n");
                exit(-1);
            } // Beacon Flooding 패킷을 보냄
            usleep(10);
        }
        // 파일 첫부분으로 이동
        if (feof(fp)) {
            fseek(fp, 0, SEEK_SET);
        }
        memset(packet.source_address,0,6);
    }

    fclose(fp);
    pcap_close(pcap);
    printf("pcap close!\n");
    return 0;
}

void generateRandomMac(uint8_t *mac) {
    mac[0] = 0x00;
    for (int i = 0; i < 6; i++) {
        mac[i] = rand() % 256;
    }
}

void initPacket(struct Beacon_Packet *packet, const char *ssid) {
    // Structure initialization function modified
    memset(packet, 0, sizeof(struct Beacon_Packet));

    // Common values setting
    packet->type = 0x0800; // Beacon Frame type
    packet->duration = 0;

    // Set destination_address to broadcast address (FF:FF:FF:FF:FF:FF)
    memset(packet->destination_address, 0xFF, 6);
    memset(packet->source_address, 0, 6);
    memset(packet->bssid, 0, 6);
    packet->sequence_number = 0;
    packet->tag_ssid.tag_number = 0; // Tag number for SSID
    packet->tag_ssid.tag_length = strlen(ssid); // Length of SSID
    strncpy((char *)packet->tag_ssid.ssid, ssid, sizeof(packet->tag_ssid.ssid) - 1);
}


// void printMacAddress(uint8_t *mac){
//     printf("tmp MAC address : %02X:%02X:%02X:%02X:%02X:%02X \n", 
//         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6]
//     );
// }

void printMacAddress(uint8_t *mac) {
    printf("tmp MAC address: ");
    for (int i = 0; i < 6; i++) {
        printf("%02X", mac[i]);
        if (i < 5) {
            printf(":");
        }
    }
    printf("\n");
}
