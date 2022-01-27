#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <pcap.h>
#include "wireless.h"
#include "ap.h"

std::vector<AP> ap_pool;

void hex_dump(uint8_t* addr, int len) {
    for (int i = 0; i < len; i++)
        printf("%02x ", addr[i]);
    printf("\n");
}

char hex(int num) {
    char res = '0';

    switch(num) {
    case 10:
        res = 'a';
        break;
    case 11:
        res = 'b';
        break;
    case 12:
        res = 'c';
        break;
    case 13:
        res = 'd';
        break;
    case 14:
        res = 'e';
        break;
    case 15:
        res = 'f';
        break;
    default:
        res = num + '0';
        break;
    }

    return res;
}

void set_bssid(std::string& dsc, uint8_t* src) {
    char tmp[18];

    for (int i=0; i<6; i++) {
        tmp[3 * i] = hex(src[i] / 16);
        tmp[3 * i + 1] = hex(src[i] % 16);
        tmp[3 * i + 2] = ':';
    }
    tmp[3 * 5 + 2] = '\0';

    dsc = tmp;
}

void set_ssid(std::string& dsc, uint8_t* src, int len) {
    char tmp[256];
    strncpy(tmp, (const char*)src, len);
    tmp[len] = '\0';

    dsc = tmp;
}

void usage() {
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump mon0\n");
}

struct Param {
    char* dev_;
};

Param param {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if(!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }


        ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*)packet;
        ieee80211_beacon_frame_header* beacon_header = (struct ieee80211_beacon_frame_header*)((uint8_t*)radiotap + radiotap->it_len);
        if (ntohs(beacon_header->frame_control) != 0x8000)
            continue;

        //parse bssid
        uint8_t* bssid_addr = (uint8_t*)(beacon_header) + 0x10;
        std::string bssid;
        set_bssid(bssid, bssid_addr);

        //parse ssid
        ieee80211_beacon_frame_body* beacon_body = (struct ieee80211_beacon_frame_body*)((uint8_t*)beacon_header + 0x18);
        if (beacon_body->Tag_Number[0] != 0)
            continue;
        int tag_length = (int)*((uint8_t*)(beacon_body->Tag_Number) + 1);
        std::string ssid;
        set_ssid(ssid,((uint8_t*)(beacon_body->Tag_Number) + 2), tag_length);

        auto iter = ap_pool.begin();
        for (; iter != ap_pool.end(); iter++) {
            if ((*iter).get_bssid() == bssid) {
                (*iter).increment_beacons();
                break;
            }
        }
        if (iter == ap_pool.end()) {
            AP ap = AP(bssid, 0, ssid);
            ap_pool.emplace_back(ap);
        }

        printf("%s\t\t%s\t%s\n", "bssid", "beacons", "ssid");
        for (auto iter = ap_pool.begin(); iter != ap_pool.end(); iter++) {
            (*iter).print_bssid();
            (*iter).print_beacons();
            (*iter).print_ssid();
        }
        printf("\n");
    }

    return 0;
}
