#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <thread>
#include <mutex>
#include <tuple>
#include <set>
#include <stdio.h>
#include <header.h>

std::mutex _mutex;
std::string bssid;

struct tag_param {
    uint8_t tag_num;
    uint8_t tag_len;
    u_char tag_data;
};

enum column
{
    PWR = 0,
    Beacons,
    Data,
    ESSID,
};

void usage()
{
    std::cout << "syntax : airodump <interface>" << std::endl;
    std::cout << "sample : airodump mon0" << std::endl;
}

void convert_str_mac(uint8_t mac_addr[]) {
    bssid = "";
    char buf[20];
    sprintf(buf, "%02x:%02X:%02X:%02X:%02X:%02X", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
            mac_addr[4], mac_addr[5]);
    bssid += std::string(buf);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        usage();
        return -1;
    }

    char* interface = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
       fprintf(stderr, "couldn`t open device %s(%s)\n", interface, errbuf);
       return -1;
    }

    struct pcap_pkthdr* pkthdr;
    struct radiotap_header* Rtap_hdr;
    struct beacon_frame* b_frame;
    struct dot11_ssid_param* tagged_param;

    const u_char* frame;
    const u_char* Rtap;

    uint8_t Rtap_len;
    uint8_t essid_len;
    int8_t signal = 0;

    std::set<int8_t> set_signal;
    std::set<int8_t>::iterator iter_signal;

    // BSSID, PWR, Beacons, Data, ESSID
    std::map<std::string, std::tuple<int8_t, int, uint8_t, std::string>> result_map;

    while(true) {
        bool bool_beacon_frame = false;
        bool bool_data = false;

        // receive frame
        int res = pcap_next_ex(handle, &pkthdr, &frame);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        Rtap_hdr = (struct radiotap_header *)(frame);
        Rtap_len = Rtap_hdr->it_len;
        Rtap = (u_char *)(frame + Rtap_len);
        b_frame = (struct beacon_frame *)(Rtap);

        // beacon_frame
        if(b_frame->type == 0x80) {
            bool_beacon_frame = true;
        }

        // QoS data or data
        else if(b_frame->type == 0x08 || b_frame->type == 0x88) {
            bool_data = true;
        }

        if(bool_beacon_frame || bool_data) {
            tagged_param = (struct dot11_ssid_param *)(Rtap + sizeof(beacon_frame) + sizeof(dot11_fixed_param));

            // get PWR
            if(Rtap[-1] >= 0) {
                for(int i = 0; i < Rtap[-1]+1; i++) {
                    set_signal.clear();

                    set_signal.insert(Rtap[-2*(i+1)]);
                    iter_signal = set_signal.begin();

                    signal = *iter_signal;
                }
            }
            else { signal = 0; }

            // is beacon_frame
            if(bool_beacon_frame) {
                // get BSSID
                convert_str_mac(b_frame->bssid);
                essid_len = tagged_param->tag_len;

                printf("tag_len: %02x\n", essid_len);

                char essid[essid_len];
                memcpy(essid, tagged_param + sizeof(dot11_ssid_param) - 1, essid_len);

                if(result_map.find(bssid) != result_map.end()) {
                    std::get<column::PWR>(result_map[bssid]) = signal;

                    // Beacons ++
                    if(bool_beacon_frame) {
                        std::get<column::Beacons>(result_map[bssid])++;
                        if(std::get<column::ESSID>(result_map[bssid]) == " ") {
                            std::get<column::ESSID>(result_map[bssid]) = std::string(essid);
                        }
                    }
                }

                // can`t find same bssid in map
                else { result_map[bssid] = make_tuple(signal, 1, 0, std::string(essid)); }
            }

            // is QoS_data or Data
            else if(bool_data) {
                // get BSSID
                if(b_frame->flag1 == 0x1) {
                    convert_str_mac(b_frame->recv_addr);
                }
                else if(b_frame->flag1 == 0x2) {
                    convert_str_mac(b_frame->trans_addr);
                }

                if(result_map.find(bssid) != result_map.end()) {
                    std::get<column::PWR>(result_map[bssid]) = signal;

                    // Data ++
                    std::get<column::Data>(result_map[bssid])++;
                }

                // can`t find same bssid in map
                else { result_map[bssid] = make_tuple(signal, 0, 1, std::string(" ")); }
            }

            std::map<std::string, std::tuple<int8_t, int, uint8_t, std::string>>::iterator iter_result = result_map.begin();

            // print result : BSSID, PWR, Beacons, Data, ESSID
            system("clear");
            std::cout << "BSSID" << "\t\t\t" << "PWR" << "\t\t" << "Beacons" << "\t\t" << "#Data" << "\t\t" << "ESSID" << std::endl;

            for(iter_result=result_map.begin(); iter_result != result_map.end(); iter_result++) {
                std::cout << iter_result->first << "\t"
                          << (int)std::get<column::PWR>(result_map[iter_result->first]) << "\t\t"
                          << (int)std::get<column::Beacons>(result_map[iter_result->first]) << "\t\t"
                          << (int)std::get<column::Data>(result_map[iter_result->first]) << "\t\t"
                          << std::get<column::ESSID>(result_map[iter_result->first]) << std::endl;
            }
        }
    }
}

