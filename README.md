# airodump

무선 해킹 툴인 airodump-ng의 기능을 구현한 프로그램입니다. Monitor 모드를 지원하는 무선 네트워크 어댑터가 필요하며, 인자로 해당 어댑터의 인터페이스 이름을 주고 실행시키면 됩니다.

무선 어댑터가 수신한 패킷 중, beacon frame에 대한 정보를 포함한 패킷에 대해서만 분석을 진행합니다. 802.11의 경우 정확한 표준 문서가 없기 때문에, radiotap header의 경우 [https://www.radiotap.org/](https://www.radiotap.org/) 사이트를, beacon frame의 경우 [https://mrncciew.com/2014/10/08/802-11-mgmt-beacon-frame/](https://mrncciew.com/2014/10/08/802-11-mgmt-beacon-frame/) 사이트를 참조하여 구조체를 분석하고 프로그램을 작성했습니다.

기본적으로 `bssid`(Access Point의 mac 주소), `beacons`(Monitor 모드의 무선 어댑터가 수신한 주변 AP들의 beacon frame 수), `ssid`(주변 Access Point의 ssid(이름)) 정보를 출력해줍니다. 정보를 출력하는 별도의 스레드를 설정해주어서 출력과 내부 연산을 분리시킴으로써 효율적인 작동을 수행하게끔 작성하였습니다.
