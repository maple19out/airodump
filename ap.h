#ifndef AP_H
#define AP_H

#include <string>

class AP
{
private:
    std::string bssid;
    int beacons;
    std::string ssid;

public:
    AP(std::string bssid, int beacons, std::string ssid);
    void increment_beacons(void);
    void print_bssid(void);
    void print_beacons(void);
    void print_ssid(void);
    std::string& get_bssid(void);
    ~AP();
};

#endif // AP_H
