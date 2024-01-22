
// // 구조체 정의

// #pragma pack(push,1)
// struct Beacon_Packet {
//     uint16_t type;
//     uint16_t control;
//     uint32_t duration;
//     uint8_t destination_address[6];
//     uint8_t source_address[6];
//     uint8_t bssid[6];
//     uint16_t sequence_number;
// } __attribute__((__packed__));

// struct Radiotap_Frame {
//     uint8_t version;
//     uint8_t pad;
//     uint16_t length;
//     uint32_t present_flags;
//     uint8_t flags;
//     uint8_t data_rate;
//     uint16_t channel_freequency;
//     uint16_t channel_flags;
//     int8_t antenna_signal;
//     uint16_t RX_flag;
//     // int16_t Antenna_signal2;
//     // uint16_t Antenna;
// };


// struct Fixed_Parameter {
//     uint64_t timestamp; // 0x0000000000000000;
//     uint16_t interval; // 0x0000;
//     uint16_t capabilities; // 0x0000;
// }; // fixed 12byte


// struct Tagged_SSID_Parameter {
//     uint8_t number; //0x00;
//     uint8_t length; // 32;
//     char ssid[32]; // {0,};
// }; // taged_ssid 34byte

// struct Tagged_DS_Parameter {
//     uint8_t number; // 0x03;
//     uint8_t length; // 0x01;
//     uint8_t channel; // 0x01;
// }; // taged_ds 3byte

// struct Tagged_Support_Parameter {
//     uint8_t number;       // 0x01
//     uint8_t length;       // 0x08
//     uint16_t rates[8];    // {0x82, 0x84, 0x8b, 0x96, 0x12, 0x24, 0x48, 0x6c}
// }; // tagged_support 10 bytes



// struct Tagged_Parameter {
//     struct Tagged_SSID_Parameter ssid;
//     struct Tagged_DS_Parameter channel;
//     struct Tagged_Support_Parameter support;
// };

// struct Packet {
//     struct Radiotap_Frame radiotap;
//     struct Beacon_Packet beacon;
//     struct Fixed_Parameter fixed;
//     struct Tagged_Parameter tag;
// };
// #pragma pack(pop)


#pragma pack(push,1)
struct Radiotap {
    uint8_t header_revison;
    uint8_t header_pad ;
    uint16_t header_length;
    uint32_t header_presentflag;
    uint8_t idontknow[3]; // wireshark check <not found>
}; // radiotap 11byte

struct Beacon_Packet {
    uint16_t type;
    uint16_t duration;
    uint8_t destination_address[6];
    uint8_t source_address[6];
    uint8_t bssid[6];
    uint16_t sequence_number;
}; // beacon frame 24byte

struct Fixed_Parameter {
    uint64_t timestamp;
    uint16_t interval;
    uint16_t capabilities;
}; // fixed 12byte

struct Taged_SSID_Parameter {
    uint8_t number;
    uint8_t length;
    char ssid[32];
}; // taged_ssid 34byte

struct Taged_DS_Parameter {
    uint8_t number;
    uint8_t length;
    uint8_t channel;
}; // taged_ds 3byte

struct Taged_Support_Parameter {
    uint8_t number;
    uint8_t length;
    uint8_t rates[8];
}; // taged_support 5byte

struct Packet {
    struct Radiotap radiotap;
    struct Beacon_Packet beacon;
    struct Fixed_Parameter fixed;
    struct Taged_SSID_Parameter tag_ssid;
    struct Taged_DS_Parameter tag_ds;
    struct Taged_Support_Parameter tag_support;
}; // 89byte
#pragma pack(pop)