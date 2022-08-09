이 프로그램은 Sender의 IP와 Target IP를 매개변수로 하여 Sender의 ARP Table의 Target IP의 MAC을 공격자의 MAC으로 변조하는 프로그램입니다.

사용방법
syntax: send-arp-test <interface> <sender ip> <target ip>
sample: send-arp-test wlan0 192.168.0.5 192.168.0.1