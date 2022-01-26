#include <pcap.h>
#include <libnet.h>

#define ADDR_LEN 6

#ifndef HEADER_H
#define HEADER_H

struct radiotap_header {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
};

struct beacon_frame {
    uint8_t type;
    uint8_t flag1:4,
            flag2:4;
    uint16_t duration;
    uint8_t recv_addr[ADDR_LEN];
    uint8_t trans_addr[ADDR_LEN];
    uint8_t bssid[ADDR_LEN];
    uint16_t num;
};

struct dot11_fixed_param {
    uint8_t timestamp[8];
    uint16_t beacon_interval;
    uint16_t capability_info;
};

struct dot11_ssid_param {
    uint8_t ssid_param;     //0x00
    uint8_t tag_len;
};

struct dot11_support_rate {
    uint8_t support_rate;   //0x01
    uint8_t tag_len;
};

struct dot11_ds_param {
    uint8_t ds_param;       //0x03
    uint8_t tag_len;
};


#endif // HEADER_H
