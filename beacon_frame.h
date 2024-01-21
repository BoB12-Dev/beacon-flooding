
// 구조체 정의
struct Radiotap_Frame {
    uint8_t header_revison; // 0x00
    uint8_t header_pad;// 0x00
    uint16_t header_length; // 0x000b
    uint32_t header_presentflag; // 0x00028000
    uint8_t idontknow[3]; //{0,0,0}
};

struct Beacon_Packet {
    uint16_t type;
    uint16_t duration;
    uint8_t destination_address[6];
    uint8_t source_address[6];
    uint8_t bssid[6];
    uint16_t sequence_number;
};

struct Fixed_Parameter {
    uint64_t timestamp; // 0x0000000000000000;
    uint16_t interval; // 0x0000;
    uint16_t capabilities; // 0x0000;
}; // fixed 12byte


struct Tagged_SSID_Parameter {
    uint8_t number; //0x00;
    uint8_t length; // 32;
    char ssid[32]; // {0,};
}; // taged_ssid 34byte

struct Tagged_DS_Parameter {
    uint8_t number; // 0x03;
    uint8_t length; // 0x01;
    uint8_t channel; // 0x01;
}; // taged_ds 3byte

struct Tagged_Support_Parameter {
    uint8_t number; // 0x01;
    uint8_t length; // 0x03;
    uint8_t rates[3]; // {0x82,0x8b,0x96};
}; // taged_support 5byte


struct Tagged_Parameter{
    struct Tagged_SSID_Parameter ssid;
    struct Tagged_DS_Parameter channel;
    struct Tagged_Support_Parameter support;
};

struct Packet {
    struct Radiotap_Frame radiotap;
    struct Beacon_Packet beacon;
    struct Fixed_Parameter fixed;
    struct Tagged_Parameter tag;
};