#ifndef AP_H
#define AP_H

#include <string>

struct AP
{
    std::string bssid;
    int beacons;
    std::string ssid;

    AP();
    AP(std::string bssid, int beacons, std::string ssid);
    void increment_beacons(void);
    void print_bssid(void);
    void print_beacons(void);
    void print_ssid(void);
    ~AP();
};

#endif // AP_H
