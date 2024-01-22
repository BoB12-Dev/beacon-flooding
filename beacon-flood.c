#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "beacon_frame.h"

void generateRandomMac(u_int8_t *mac);
void initPacket(struct Packet *packet);
void printMacAddress(uint8_t *mac);

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <interface> <ssid-list-file>\n", argv[0]);
        return -1;
    }

    char *interfaceName = argv[1];
    char *filename = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(interfaceName, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interfaceName, errbuf);
        return -1;
    }

    FILE *fp;
    fp = fopen(filename, "rb");
    if (fp == NULL)
    {
        fprintf(stderr, "파일을 열 수 없습니다.\n");
        return 1;
    }

    char beacon_name[34];
    struct Packet packet;
    initPacket(&packet); // 패킷 전체 초기화

    while (true)
    {
        while ((fgets(beacon_name, sizeof(beacon_name), fp)) != 0)
        {
            // 파일에서 한 줄을 읽어와 flooding할 beacon name을 설정.
            // 우측 공백 제거하기
            if (beacon_name[strlen(beacon_name) - 1] == 0x0d || beacon_name[strlen(beacon_name) - 1] == 0x0a)
            {
                beacon_name[strlen(beacon_name) - 1] = 0x00;
            }
            memcpy(packet.tag_ssid.ssid, beacon_name, 32);

            // Source Address 설정
            generateRandomMac(packet.beacon.source_address);
            // ssid, bssid 설정

            memcpy(packet.beacon.bssid, packet.beacon.source_address, 6);

            printMacAddress(packet.beacon.source_address);
            // 패킷을 pcap으로 전송
            if (pcap_sendpacket(pcap, (unsigned char *)&packet, sizeof(packet)) != 0)
            {
                printf("send fail\n");
                exit(-1);
            } // Beacon Flooding 패킷을 보냄
            printf(" packet size : %d \n", sizeof(packet));
            // 전송후 필드 다시 초기화
            memset(packet.beacon.bssid, 0, 6);
            memset(packet.tag_ssid.ssid, 0, 32);
            memset(beacon_name, 0, 34);
            usleep(1000);
        }
        // 파일 첫부분으로 이동
        if (feof(fp))
        {
            fseek(fp, 0, SEEK_SET);
        }
        memset(packet.beacon.source_address, 0, 6);
    }

    fclose(fp);
    pcap_close(pcap);
    printf("pcap close!\n");
    return 0;
}

void generateRandomMac(uint8_t *mac)
{
    mac[0] = 0x00;
    for (int i = 0; i < 6; i++)
    {
        mac[i] = rand() % 256;
    }
}

void initPacket(struct Packet *packet)
{
    // Structure initialization function modified
    memset(packet, 0, sizeof(struct Packet));

    // Radiotap
    packet->radiotap.header_revison = 0x00;
    packet->radiotap.header_pad = 0x00;
    packet->radiotap.header_length = 0x000b;
    packet->radiotap.header_presentflag = 0x00028000;

    // beacon frame
    packet->beacon.type = 0x0080;
    packet->beacon.duration = 0x0000;
    memset(packet->beacon.destination_address, 0xFF, 6);
    memset(packet->beacon.source_address, 0x00, 6);
    memset(packet->beacon.bssid, 0x00, 6);
    packet->beacon.sequence_number = 0x0000;

    // Fixed
    packet->fixed.timestamp = 0x76f11d4907010000;
    packet->fixed.interval = 0x6400;
    packet->fixed.capabilities = 0x1104;

    // SSID
    packet->tag_ssid.number = 0x00;
    packet->tag_ssid.length = 0x20;
    memset(packet->tag_ssid.ssid, 0x00, 32);

    // DS
    packet->tag_ds.number = 0x03;
    packet->tag_ds.length = 0x01;
    packet->tag_ds.channel = 0x01;

    // Support
    packet->tag_support.number = 0x01;
    packet->tag_support.length = 0x08;
    uint8_t rate[] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    memcpy(packet->tag_support.rates, rate, sizeof(rate));
}

void printMacAddress(uint8_t *mac){
    printf("tmp MAC address : %02X:%02X:%02X:%02X:%02X:%02X ",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6]
    );
}