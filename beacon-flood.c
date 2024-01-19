#include <stdio.h>
#include <stdint.h> // uint
#include <pcap.h>   // pcap
#include <unistd.h> // sleep
#include <string.h> // memcpy, memcmp, memset, strcat
#include <ctype.h>  // isupper
#include <stdlib.h> // exit
#include <sys/ioctl.h> // isMonitorMode
#include <net/if.h>
#include <netinet/in.h>


struct Beacon_Packet {
    uint16_t type;
    uint16_t duration;
    uint8_t destination_address[6];
    uint8_t source_address[6];
    uint8_t bssid[6];
    uint16_t sequence_number;
}; // beacon frame 24byte

struct Radiotap_Frame{
    uint8_t header_revison;
    uint8_t header_pad;
    uint16_t header_length;
    uint32_t header_presentflag;
    uint8_t idontknow[3]; // wireshark check <not found>
};
int isMonitorMode(char *interfaceName) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd == -1) {
        perror("Socket creation error");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ);

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1) {
        perror("IOCTL error");
        close(sockfd);
        return -1;
    }

    close(sockfd);

    return (ifr.ifr_flags & IFF_UP) != 0;
}

int changeMode(char *interfaceName) {
    printf("Executing command: gmon %s mon0\n", interfaceName);
    char command[256];
    snprintf(command, sizeof(command), "gmon %s mon0", interfaceName);
    int ret = system(command);

    if (ret != 0) {
        fprintf(stderr, "Failed to execute gmon command\n");
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <ssid-list-file>\n", argv[0]);
        return -1;
    }

    char *interfaceName = argv[1];
    char *ssidListFile = argv[2];

    int result = isMonitorMode(interfaceName);

    if (result == -1) {
        fprintf(stderr, "Error checking monitor mode for interface %s\n", interfaceName);
        return 1;
    }

    if (!result) {
        if (changeMode(interfaceName) != 0) {
            return 1; // 모니터 모드로 변경 실패 시 종료
        }
    }

    // TODO: 나머지 코드 추가

    return 0;
}