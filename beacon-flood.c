#include <stdio.h>
#include <stdint.h> // uint
#include <pcap.h>   // pcap
#include <unistd.h> // sleep
#include <string.h> // memcpy, memcmp, memset, strcat
#include <ctype.h>  // isupper
#include <stdlib.h> // exit
#include <stdbool.h> // bool type


struct Beacon_Packet {
    uint16_t type;
    uint16_t duration;
    uint8_t destination_address[6];
    uint8_t source_address[6];
    uint8_t bssid[6];
    uint16_t sequence_number;
}; // beacon frame 24byte

struct Radiotap_Frame {
    uint8_t header_revison;
    uint8_t header_pad;
    uint16_t header_length;
    uint32_t header_presentflag;
    uint8_t idontknow[3]; // wireshark check <not found>
};

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <ssid-list-file>\n", argv[0]);
        return -1;
    }

    char *interfaceName = argv[1];
    char *filename = argv[2];

    // pcap open
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(interfaceName, BUFSIZ, 1, 1000, errbuf); // 무차별 모드
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interfaceName, errbuf);
        return -1;
    } // 실패시 중단

    FILE *fp;
    fp = fopen(filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "파일을 열 수 없습니다.\n");
        return 1;
    }

    char beacon_name[35];
    struct Beacon_Packet packet;

    // beacon-flooding을 위한 무한 루프
    while (true) {
        while ((fgets(beacon_name, sizeof(beacon_name), fp)) != 0) {
            // fgets로 읽은 beacon_name에 대한 처리가 필요
            // 예를 들어, printf("%s", beacon_name) 등으로 화면에 출력하거나
            // Beacon_Packet 구조체에 데이터를 채워넣는 등의 작업이 필요

            // Beacon_Packet 구조체 초기화 예시
            memset(&packet, 0, sizeof(struct Beacon_Packet));
            // packet 구조체에 데이터 채워넣는 작업이 필요
        }
    }

    fclose(fp);
    pcap_close(pcap); // 캡쳐 중단
    return 0;
}
