#include <stdio.h>
#include <stdint.h> // uint
#include <pcap.h>   // pcap
#include <unistd.h> // sleep
#include <string.h> // memcpy, memcmp, memset, strcat
#include <ctype.h>  // isupper
#include <stdlib.h> // exit
#include <stdbool.h> // bool type



struct Radiotap_Frame {
    uint8_t header_revison;
    uint8_t header_pad;
    uint16_t header_length;
    uint32_t header_presentflag;
    uint8_t idontknow[3]; // wireshark check <not found>
};  // Radiotap_Frame은 패킷에서 맨 처음 24byte를 차지

struct Beacon_Packet {
    uint16_t type;               // 패킷 타입 (Beacon 프레임의 경우 0x0800)
    uint16_t duration;           // 프레임의 전송 지속 시간
    uint8_t destination_address[6];  // 수신기의 MAC 주소
    uint8_t source_address[6];       // 송신기의 MAC 주소
    uint8_t bssid[6];                // BSSID (Basic Service Set Identifier)
    uint16_t sequence_number;        // 프레임의 일련 번호
    struct {
        uint8_t tag_number;
        uint8_t tag_length;
        uint8_t ssid[32];
    } tag_ssid;
}; // beacon frame은 패킷에서 Radiotap다음으로 24byte를 차지함


void initPacket(struct Beacon_Packet *packet){
    memset(packet, 0,sizeof(struct Beacon_Packet));
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <ssid-list-file>\n", argv[0]);
        return -1;
    }

    char *interfaceName = argv[1];
    char *filename = argv[2];

    // pcap open
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(interfaceName, BUFSIZ, 1, 1000, errbuf); // 무차별 모드로 캡쳐
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

    char beacon_name[34]; //ssid + 줄바꿈
    struct Beacon_Packet packet;

    // beacon-flooding을 위한 무한 루프
    while (true) {
        while ((fgets(beacon_name, sizeof(beacon_name), fp)) != 0) {
            // 파일에서 한줄을 읽어서 가져와 flooding할 beacon name을 설정.
            
            //1. 맨 끝 공백 제거
            char *tmp = strtok(beacon_name,"\r\n\t");

            // Beacon_Packet 구조체 초기화 예시
            memset(&packet, 0, sizeof(struct Beacon_Packet));
            // packet 구조체에 데이터 채워넣는 작업이 필요

            



            // if (pcap_sendpacket(handle, (unsigned char*)&data, length) != 0){
            //     printf("※  Beacon Flooding Fail..\n");
            //     exit (-1);
            // } // Beacon Flooding 패킷을 보냄
        }
    }

    fclose(fp);
    pcap_close(pcap); // 캡쳐 중단
    return 0;
}
