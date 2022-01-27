#include "ap.h"

AP::AP(std::string bssid, int beacons, std::string ssid)
{
    this->bssid = bssid;
    this->beacons = beacons;
    this->ssid = ssid;
}

void AP::increment_beacons()
{
    this->beacons++;
}

void AP::print_bssid()
{
    printf("%s\t", bssid.c_str());
}

void AP::print_beacons()
{
    printf("%d\t", beacons);
}

void AP::print_ssid()
{
    printf("%s\n", ssid.c_str());
}

std::string &AP::get_bssid()
{
    return bssid;
}

AP::~AP()
{
}
