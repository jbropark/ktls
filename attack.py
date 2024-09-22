from scapy.all import *
import random
import time

# 4-tuple 정의
source_ip = "10.0.1.8"      # 출발지 IP 주소
destination_ip = "10.0.1.7" # 목적지 IP 주소
source_port = 443          # 출발지 포트
destination_port = 44284    # 목적지 포트 (예: HTTP)

# 원하는 페이로드 설정
payload = "my attack packet attack attack"  # 패킷의 페이로드에 들어갈 문자열

# 100개의 패킷 전송
for i in range(100):
    # 랜덤 시퀀스 번호 생성
    sequence_number = random.randint(4000000000, 4294967295)  # 32비트 시퀀스 번호

    # TCP 패킷 생성 및 페이로드 추가
    packet = IP(src=source_ip, dst=destination_ip) / \
             TCP(sport=source_port, dport=destination_port, seq=sequence_number, flags="A") / \
             Raw(load=payload)

    # 패킷 전송
    send(packet)

    # 출력 및 대기 시간 설정
    print(f"Sent TCP packet {i+1} with sequence number: {sequence_number} and payload: {payload}")
    time.sleep(0.5)
