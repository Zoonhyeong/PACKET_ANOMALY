# packet_analysis.analyze() 가 만든 anomalies CSV -> 이상 플로우별 "왜 이상한지" 설명
#  - explain_anomalies(): 이상 플로우마다 {플로우 정보 + 이상 이유} 딕셔너리 리스트 반환 (노트북 6, 7번)
#  - summarize() / plot_scores(): 점수 요약과 차트 (노트북 5번)
#  - print_report(): explain_anomalies() 결과를 콘솔에 보기 좋게 출력
#
# 이상 이유는 세 가지를 합쳐서 보여줌
#  1) judge  (6번): 플로우 하나의 프로토콜/포트/방향/양/시간 패턴 -> 정상 추정 / 확인 필요 / 의심
#  2) assess (7번): 같은 출발지가 캡처 전체에서 한 행동(스캔 범위, 반복 횟수)까지 보고 위험 점수 합산
#  3) model_reasons (6번): 특징 하나를 중앙값으로 바꿨을 때 점수가 얼마나 떨어지는지 = 모델이 본 원인
#     -> flow_vectors CSV 가 있어야 계산 가능 (없으면 생략)
#  + attack: 의심 유형을 MITRE ATT&CK 기법 ID 로 매핑
import ipaddress
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

META_COLS = ["src", "sport", "dst", "dport", "protocol", "start_time"]

TOP_K = 3                 # 플로우마다 보여줄 모델 원인 특징 개수
SCAN_TARGETS = 20         # 응답 없는 SYN을 서로 다른 (IP, 포트) 몇 곳 이상에 보내면 스캔으로 볼지
SCAN_SERVICES = 15        # 한 출발지가 1024 미만 서비스 포트 몇 종류 이상에 접근하면 정찰로 볼지
REPEAT_MIN_FLOWS = 50     # 같은 (출발지, 목적지, 포트)로 최소 몇 번 이상 연결했을 때
REPEAT_PER_MIN = 20       #   분당 몇 회 이상이면 반복 공격으로 볼지 (정상 반복 접속은 보통 분당 몇 회 수준)
REPEAT_FAIL_RATIO = 0.5   #   (로그인 포트가 아니면) 그 연결 중 실패(응답 없음/RST) 비율이 이 이상일 때만 DoS 로 봄
                          #   -> DNS 서버로 가는 질의, 프록시로 가는 HTTP 처럼 "많지만 정상 응답받는" 반복은 제외
BIG_UPLOAD = 500_000      # 이 바이트 이상을 보내고, 받은 양의 3배 이상이면 대용량 업로드
BIG_DOWNLOAD = 1_000_000  # 이 바이트 이상을 받으면 대용량 전송
BIG_PAYLOAD = 500         # 응답 없는 UDP의 평균 패킷 길이가 이 이상이면 큰 페이로드
ODD_TTL = 200             # 평균 TTL이 이 이상이면 일반 PC(64/128)가 아닌 값으로 봄


# ---- 이름 / 서비스 ----
IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6", 89: "OSPF", 103: "PIM", 132: "SCTP"}
SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 69: "TFTP",
    80: "HTTP", 110: "POP3", 111: "RPC portmap", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS", 139: "NetBIOS-SMB",
    143: "IMAP", 161: "SNMP", 179: "BGP", 443: "HTTPS", 445: "SMB", 500: "IKE(VPN)", 514: "syslog/rsh",
    520: "RIP", 1433: "MSSQL", 1900: "SSDP", 2049: "NFS", 3306: "MySQL", 3389: "RDP", 4444: "Metasploit 기본",
    5060: "SIP(VoIP)", 5190: "AIM", 6667: "IRC", 6881: "BitTorrent", 7002: "WebLogic", 8080: "HTTP-alt",
    8089: "Splunk 관리", 31337: "Back Orifice",
}
ROUTING = {179: "BGP", 520: "RIP"}
ROUTING_PROTOCOLS = {89: "OSPF", 103: "PIM"}
AUTH_PORTS = {21, 22, 23, 25, 110, 143, 3389, 1433, 3306}
VULN_PORTS = {21, 23, 25, 69, 110, 111, 135, 137, 139, 143, 161, 445, 514, 1433, 2049, 3306, 3389,
              4444, 5060, 6667, 7002, 8089, 31337}
BACKDOOR_PORTS = {4444, 31337, 6667, 1524, 12345}
LAN_SERVICES = {5353: "mDNS(기기 탐색)", 5355: "LLMNR(이름 조회)", 137: "NetBIOS 이름 조회",
                138: "NetBIOS 데이터그램", 1900: "SSDP(UPnP 탐색)", 67: "DHCP", 68: "DHCP"}
PUSH_SERVICES = {5223: "Apple 푸시 알림(APNs)", 5228: "Google 푸시 알림(FCM)"}

FEATURE_INFO = {
    "duration": ("지속 시간", "s"), "fwd_pkts": ("보낸 패킷 수", ""), "bwd_pkts": ("받은 패킷 수", ""),
    "fwd_bytes": ("보낸 바이트", "B"), "bwd_bytes": ("받은 바이트", "B"),
    "pkt_len_mean": ("평균 패킷 길이", "B"), "pkt_len_std": ("패킷 길이 편차", "B"),
    "pkt_len_max": ("최대 패킷 길이", "B"), "pkt_len_min": ("최소 패킷 길이", "B"),
    "fwd_len_mean": ("보낸 패킷 평균 길이", "B"), "bwd_len_mean": ("받은 패킷 평균 길이", "B"),
    "iat_mean": ("평균 패킷 간격", "s"), "iat_std": ("패킷 간격 편차", "s"),
    "iat_max": ("최대 패킷 간격", "s"), "iat_min": ("최소 패킷 간격", "s"),
    "pkts_per_sec": ("초당 패킷 수", ""), "bytes_per_sec": ("초당 바이트", "B/s"),
    "down_up_ratio": ("받은/보낸 패킷 비율", ""), "payload_bytes": ("페이로드 바이트", "B"),
    "zero_payload_ratio": ("빈 페이로드 비율", ""),
    "syn_cnt": ("SYN 수", ""), "ack_cnt": ("ACK 수", ""), "fin_cnt": ("FIN 수", ""),
    "rst_cnt": ("RST 수", ""), "psh_cnt": ("PSH 수", ""), "urg_cnt": ("URG 수", ""),
    "ttl_mean": ("평균 TTL", ""), "win_mean": ("평균 TCP 윈도우", ""),
    "src_internal": ("출발지 내부 IP", None), "dst_internal": ("목적지 내부 IP", None),
    "dst_multicast": ("목적지 멀티캐스트", None),
    "proto_tcp": ("TCP", None), "proto_udp": ("UDP", None), "proto_icmp": ("ICMP", None), "proto_other": ("기타 프로토콜", None),
    "dport_well_known": ("잘 알려진 포트(<1024)", None), "dport_registered": ("registered 포트(1024~49151)", None),
    "dport_ephemeral": ("임시 포트(49152~)", None), "dport_none": ("포트 없음", None),
}


def svc(port):
    return SERVICES.get(port, "")


def endpoint(ip, port):
    name = svc(port)
    return f"{ip}:{port}" + (f"({name})" if name else "")


def is_internal(ip):
    a = ipaddress.ip_address(ip)
    return a.is_private or a.is_link_local


def fmt(v, unit=""):
    if float(v).is_integer():
        s = f"{int(v):,}"
    elif abs(v) >= 100:
        s = f"{v:,.0f}"
    else:
        s = f"{v:.3g}"
    return f"{s}{unit}"


def resolve_domains(pcap_path):
    """원본 캡처의 DNS 응답으로 IP -> 도메인 매핑. 캡처를 한 번 더 읽으므로 큰 파일은 오래 걸림"""
    from scapy.all import PcapReader, DNS, UDP  # PcapReader는 .pcap / .pcapng 모두 읽음
    ip_domain = {}
    for pkt in PcapReader(str(pcap_path)):
        if UDP in pkt and pkt[UDP].sport == 53 and DNS in pkt and pkt[DNS].qr == 1 and pkt[DNS].qd:
            qname = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
            for k in range(pkt[DNS].ancount):
                try:
                    rr = pkt[DNS].an[k]
                except (IndexError, TypeError):
                    break
                if getattr(rr, "type", None) in (1, 28):  # A, AAAA
                    ip_domain.setdefault(str(rr.rdata), qname)
    return ip_domain


# ---- 캡처 전체 기준 맥락 (출발지별 스캔 범위, 반복 횟수 등) ----
def build_context(df):
    no_reply_syn = df[(df["protocol"] == 6) & (df["syn_cnt"] >= 1) & (df["ack_cnt"] == 0) & (df["bwd_pkts"] == 0)]
    syn_targets = no_reply_syn.drop_duplicates(["src", "dst", "dport"]).groupby("src").size().to_dict()

    well_known = df[(df["dport"] > 0) & (df["dport"] < 1024)]
    services_per_src = well_known.groupby("src")["dport"].nunique()
    dsts_per_src = well_known.groupby("src")["dst"].nunique()
    busy_srcs = df["src"].value_counts()
    services_baseline = services_per_src[busy_srcs[busy_srcs >= 100].index.intersection(services_per_src.index)].median()

    failed = (df["bwd_pkts"] == 0) | (df["rst_cnt"] > 0)
    rep = (df.assign(failed=failed).groupby(["src", "dst", "dport", "protocol"])
           .agg(size=("start_time", "size"), min=("start_time", "min"), max=("start_time", "max"),
                fail_ratio=("failed", "mean")))
    rep["per_min"] = rep["size"] / ((rep["max"] - rep["min"]) / 60 + 1)  # +1분: 짧은 구간에서 과대 계산 방지

    return {
        "syn_targets": syn_targets,
        "services_per_src": services_per_src,
        "dsts_per_src": dsts_per_src,
        "services_baseline": services_baseline,
        "rep": rep,
        "ttl_baseline": df["ttl_mean"].median(),
    }


# ---- 1) 플로우 하나 판정 (노트북 6번, 위에서부터 먼저 맞는 것 하나) ----
def judge(r, ctx):
    """(판정, 유형, 설명) 반환"""
    tot_pkts = r.fwd_pkts + r.bwd_pkts
    src_in, dst_in = is_internal(r.src), is_internal(r.dst)

    if r.protocol == 6:
        if r.syn_cnt >= 1 and r.ack_cnt == 0 and r.bwd_pkts == 0:
            n_targets = ctx["syn_targets"].get(r.src, 1)
            if n_targets >= SCAN_TARGETS:
                return "의심", "스캔 (응답 없는 SYN)", (f"{r.src}가 응답 없는 SYN을 서로 다른 {n_targets}곳(IP·포트)에 보냈어요. "
                                                     "포트·호스트 스캔의 전형적인 형태예요.")
            if r.syn_cnt >= 3:
                return "확인 필요", "연결 실패 (SYN 재전송)", (f"{fmt(r.duration, 's')} 동안 SYN을 {r.syn_cnt}번 재전송했지만 응답이 없었어요. "
                                                         "서버 다운, 방화벽·광고 차단에 막힌 연결이 흔해요. "
                                                         "모르는 도메인으로 계속 재시도하면 악성코드의 C2 접속 시도일 수 있어요.")
            return "확인 필요", "응답 없는 SYN", "SYN 1개를 보내고 응답이 없었어요. 같은 출발지에서 여러 포트로 반복되는지 확인하세요."
        if r.rst_cnt >= 1 and tot_pkts <= 3:
            return "확인 필요", "즉시 RST", "연결이 바로 거부(RST)됐어요. 닫힌 포트 접속이며, 같은 출발지에서 여러 포트로 반복되면 스캔이에요."
        if r.urg_cnt > 0:
            return "의심", "URG 플래그", "일반 트래픽에서 거의 쓰지 않는 URG 플래그가 있어요. Xmas 스캔 등 조작된 패킷일 수 있어요."
        if not src_in and dst_in and r.syn_cnt >= 1:
            return "확인 필요", "외부에서 들어온 연결", "외부 IP가 내부로 연결을 시작했어요. 내부에 열린 서비스가 있는지 확인하세요."

    if r.pkts_per_sec > 1000 and r.bwd_pkts == 0 and tot_pkts > 100:
        return "의심", "단방향 고속 전송", "응답 없이 초당 1,000개 이상을 보냈어요. flood 공격 패턴과 비슷해요."
    if r.fwd_bytes > 1_000_000 and r.fwd_bytes > 5 * max(r.bwd_bytes, 1):
        return "확인 필요", "대용량 업로드", f"{fmt(r.fwd_bytes, 'B')}를 외부로 보냈어요. 업로드 서비스가 아니라면 데이터 유출 가능성을 확인하세요."
    if r.bwd_bytes > 1_000_000:
        return "정상 추정", "대용량 다운로드", f"{fmt(r.bwd_bytes, 'B')}를 받았어요. 파일·업데이트·동영상 다운로드에서 흔한 패턴이에요."
    if r.duration > 300 and r.iat_mean > 5 and tot_pkts < 200:
        regular = r.iat_std < r.iat_mean
        msg = "일정한 간격으로" if regular else "드문드문"
        base = f"{fmt(r.duration, 's')} 동안 평균 {fmt(r.iat_mean, 's')} 간격으로 {msg} 작은 패킷을 주고받았어요. "
        if r.dport in PUSH_SERVICES:
            return "정상 추정", "장시간 주기적 통신", base + f"{PUSH_SERVICES[r.dport]} 연결의 keep-alive예요."
        return "확인 필요", "장시간 주기적 통신", base + "푸시 알림·keep-alive가 흔하지만 C2 비컨과 모양이 같아 목적지를 확인하세요."
    if r.protocol in (1, 58):
        direction = "내부→외부" if src_in else "외부→내부"
        return "정상 추정", f"ICMP ({direction})", ("포트 없는 ICMP라 드물게 보였어요. 대부분 Port Unreachable 같은 오류 응답이에요. "
                                                 "짧은 시간에 수백 개가 넘으면 ping sweep·ICMP flood를 의심하세요.")
    port = r.dport if r.dport in LAN_SERVICES else (r.sport if r.sport in LAN_SERVICES else None)
    if port is not None:
        return "정상 추정", LAN_SERVICES[port], "LAN 기기끼리 주고받는 탐색·이름 조회 트래픽이에요. 내부↔내부 + 흔치 않은 포트 조합이라 드물게 보였어요."
    if r.dport in PUSH_SERVICES:
        return "정상 추정", PUSH_SERVICES[r.dport], "푸시 알림 서버와의 연결이에요. 흔치 않은 포트라 드물게 보였어요."
    if r.protocol == 17 and r.dport == 53:
        return "정상 추정", "DNS", "DNS 조회예요. 한 플로우에 쿼리가 매우 많거나 크면 DNS 터널링을 의심하세요."
    return "확인 필요", "기타 희귀 패턴", "규칙에 해당하지 않는 드문 패턴이에요. 모델 원인 특징을 보고 직접 확인하세요."


# ---- 2) 출발지 맥락까지 본 위험 점수 (노트북 7번) ----
def assess(r, ctx):
    """(위험 점수, 의심 유형 목록, 근거 목록) 반환"""
    risk, kinds, ev = 0, [], []
    proto_name = IP_PROTOCOLS.get(r.protocol, f"프로토콜 {r.protocol}")

    # 1) 정찰: 한 출발지가 여러 종류의 서비스 포트를 두드림
    n_svc = ctx["services_per_src"].get(r.src, 0)
    if n_svc >= SCAN_SERVICES:
        risk += 2
        kinds.append("정찰(서비스 스캔)")
        ev.append(f"{r.src}가 서비스 포트(1024 미만) {n_svc}종류를 서버 {ctx['dsts_per_src'][r.src]}대에 걸쳐 접근 "
                  f"(일반 출발지 중앙값 {ctx['services_baseline']:.0f}종류)")

    # 2) 같은 서비스로 빠르게 반복 연결
    key = (r.src, r.dst, r.dport, r.protocol)
    rep = ctx["rep"]
    if key in rep.index:
        n_rep, per_min, fail = rep.at[key, "size"], rep.at[key, "per_min"], rep.at[key, "fail_ratio"]
        if n_rep >= REPEAT_MIN_FLOWS and per_min >= REPEAT_PER_MIN:
            if r.dport in AUTH_PORTS and r.fwd_bytes < 5_000:
                risk += 2
                kinds.append("무차별 대입(brute force)")
                ev.append(f"로그인 서비스 {svc(r.dport)}에 작은 연결을 {n_rep}번, 분당 {per_min:.0f}회 반복")
            elif fail >= REPEAT_FAIL_RATIO:
                risk += 2
                kinds.append("서비스 거부·반복 공격(DoS)")
                ev.append(f"같은 목적지 {endpoint(r.dst, r.dport)}로 {n_rep}번, 분당 {per_min:.0f}회 반복 연결 "
                          f"(그중 {fail * 100:.0f}%가 응답 없음/RST)")

    # 3) 라우팅 프로토콜 대상
    if r.dport in ROUTING or r.protocol in ROUTING_PROTOCOLS:
        risk += 2
        name = ROUTING.get(r.dport) or ROUTING_PROTOCOLS.get(r.protocol)
        kinds.append("라우팅 프로토콜 공격")
        ev.append(f"{name}는 라우터끼리 경로를 주고받는 프로토콜이에요. 일반 호스트가 보내면 경로 조작·라우팅 테이블 오염 시도일 수 있어요")

    # 4) 비표준 IP 프로토콜 / 포트 0
    if r.protocol not in (1, 6, 17, 58) and r.protocol not in ROUTING_PROTOCOLS:
        risk += 2
        kinds.append("비정상 프로토콜")
        ev.append(f"일반 트래픽에 거의 없는 IP 프로토콜 {proto_name}")
    if r.protocol in (6, 17) and (r.dport == 0 or r.sport == 0):
        risk += 2
        kinds.append("조작된 패킷")
        ev.append("포트 0은 정상 통신에서 쓰지 않아요. 직접 만든(조작한) 패킷일 가능성이 커요")

    # 5) 응답 없는 UDP 단발 (+ 큰 페이로드)
    if r.protocol == 17 and r.bwd_pkts == 0 and r.fwd_pkts <= 3:
        risk += 1
        target = svc(r.dport) or f"{r.dport}번 포트"
        ev.append(f"{target}에 UDP {r.fwd_pkts}개({r.fwd_bytes:,}B)를 보내고 응답이 없음")
        if r.pkt_len_mean >= BIG_PAYLOAD:
            risk += 1
            kinds.append("익스플로잇·퍼징")
            ev.append(f"평균 패킷 {r.pkt_len_mean:,.0f}B로 큼. 취약점 공격 페이로드나 퍼징(비정상 입력 대량 주입)일 수 있어요")
        elif "정찰(서비스 스캔)" not in kinds:
            kinds.append("서비스 탐지·공격 시도")

    # 6) 응답 없는 TCP SYN
    if r.protocol == 6 and r.syn_cnt >= 1 and r.ack_cnt == 0 and r.bwd_pkts == 0:
        risk += 1
        kinds.append("응답 없는 연결 시도")
        ev.append(f"SYN {r.syn_cnt}개를 보냈지만 응답 없음 (닫힌 포트·차단·스캔)")

    # 7) 취약 서비스 / 백도어 포트
    if r.dport in BACKDOOR_PORTS:
        risk += 2
        kinds.append("백도어 의심")
        ev.append(f"백도어·원격제어 도구가 흔히 쓰는 포트 {r.dport}({svc(r.dport)})")
    elif r.dport in VULN_PORTS and r.dport not in ROUTING:
        risk += 1
        ev.append(f"공격 대상이 되기 쉬운 서비스 {svc(r.dport)}({r.dport})")

    # 8) 대용량 업로드
    if r.fwd_bytes >= BIG_UPLOAD and r.fwd_bytes > 3 * max(r.bwd_bytes, 1):
        risk += 2
        kinds.append("대용량 업로드")
        what = "스팸·대량 메일" if r.dport == 25 else "공격 페이로드 전송이나 데이터 유출"
        ev.append(f"{r.fwd_bytes:,}B를 보내고 {r.bwd_bytes:,}B만 받음. {what} 가능성")

    # 9) TTL 이상
    if r.ttl_mean >= ODD_TTL and ctx["ttl_baseline"] < ODD_TTL:
        risk += 1
        ev.append(f"평균 TTL {r.ttl_mean:.0f} (전체 중앙값 {ctx['ttl_baseline']:.0f}). "
                  "일반 PC(64/128)와 다른 값이라 패킷 생성 도구나 다른 네트워크에서 온 트래픽일 수 있어요")

    # 10) 대용량 다운로드만 있는 경우 -> 정상 가능성
    if r.bwd_bytes >= BIG_DOWNLOAD and not kinds:
        kinds.append("대용량 전송(정상 가능)")
        name = svc(r.dport) or f"{r.dport}번 포트"
        ev.append(f"{name}에서 {r.bwd_bytes:,}B를 받음. 파일·P2P·웹 다운로드에서 흔한 패턴이라 "
                  "양이 많아서 드물게 보였을 가능성이 커요")

    if not kinds:
        kinds.append("드문 패턴(규칙 해당 없음)")
        if not ev:
            ev.append("공격 규칙에 해당하지 않아요. 모델 원인 특징을 보고 직접 확인하세요")
    return risk, list(dict.fromkeys(kinds)), ev


# ---- MITRE ATT&CK 매핑 ----
#  의심 유형 -> (기법 ID, 기법 이름, 전술). 트래픽만으로 단정할 수 없는 유형(조작된 패킷, 응답 없는 SYN 1개 등)은
#  억지로 붙이지 않고 비워 둠. 관제 보고서·SIEM 상관분석에서 공통 용어로 쓰기 위함
ATTACK = {
    "정찰(서비스 스캔)":        [("T1046", "Network Service Discovery", "Discovery")],
    "서비스 탐지·공격 시도":     [("T1046", "Network Service Discovery", "Discovery")],
    "스캔 (응답 없는 SYN)":      [("T1046", "Network Service Discovery", "Discovery")],
    "URG 플래그":              [("T1046", "Network Service Discovery", "Discovery")],
    "무차별 대입(brute force)": [("T1110", "Brute Force", "Credential Access")],
    "서비스 거부·반복 공격(DoS)": [("T1499", "Endpoint Denial of Service", "Impact")],
    "단방향 고속 전송":          [("T1498", "Network Denial of Service", "Impact")],
    "비정상 프로토콜":           [("T1095", "Non-Application Layer Protocol", "Command and Control")],
    "익스플로잇·퍼징":           [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "백도어 의심":              [("T1571", "Non-Standard Port", "Command and Control")],
    "대용량 업로드":             [("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration")],
    "장시간 주기적 통신":         [("T1071", "Application Layer Protocol", "Command and Control")],
}


def attack_techniques(kinds, judge_type=None, verdict=None):
    """assess() 의심 유형 + judge() 유형 -> 중복 없는 ATT&CK 기법 목록.
    judge 유형은 '정상 추정'이면 붙이지 않음 (푸시 알림 keep-alive 를 C2 로 표시하지 않도록)"""
    names = list(kinds)
    if judge_type and verdict != "정상 추정":
        names.append(judge_type)
    seen, out = set(), []
    for n in names:
        for tid, name, tactic in ATTACK.get(n, []):
            if tid not in seen:
                seen.add(tid)
                out.append({"id": tid, "name": name, "tactic": tactic,
                            "url": f"https://attack.mitre.org/techniques/{tid}/"})
    return out


def level(risk):
    return "높음" if risk >= 4 else ("중간" if risk >= 2 else "낮음")


# ---- 3) 모델이 이상하다고 본 특징 (노트북 6번) ----
class ModelExplainer:
    """탐지에 쓴 Isolation Forest 로 "특징 하나를 정상값으로 바꾸면 점수가 얼마나 떨어지나"를 계산.
    iforest / median 은 packet_analysis.detect_anomalies() 결과 attrs 에서 그대로 받음 (다시 학습하지 않음).
    CSV 만 있어서 모델이 없으면 같은 설정으로 다시 학습 (같은 데이터·순서 -> 점수 동일)"""

    def __init__(self, df, vec_df, iforest=None, median=None):
        # anomalies 에 있는 플로우(=탐지 대상)만, flow_vectors 의 원래 순서대로
        vec = vec_df.merge(df[META_COLS].drop_duplicates(), on=META_COLS, how="inner")
        self.keys = vec[META_COLS]
        self.X_df = vec.drop(columns=META_COLS)
        self.X = self.X_df.to_numpy(dtype=np.float32)
        self.names = list(self.X_df.columns)
        self.model = iforest if iforest is not None else \
            IsolationForest(n_estimators=300, random_state=42, n_jobs=-1).fit(self.X)
        self.scores = -self.model.score_samples(self.X)
        # 기준선 모드면 학습 데이터(정상 트래픽)의 중앙값 = "정상값", 캡처별 모드면 이 캡처의 중앙값
        self.median = np.asarray(median, dtype=np.float32) if median is not None else np.median(self.X, axis=0)
        self.row_of = {tuple(k): i for i, k in enumerate(self.keys.itertuples(index=False))}
        self.flows = df.set_index(META_COLS)
        self._cache = {}
        self._stats = {}

    def _perturb(self, i):
        """플로우 i 의 특징 j를 하나씩 중앙값으로 바꾼 변형들 (바뀐 특징 인덱스, 변형 행렬)"""
        x = self.X[i]
        changed = np.where(x != self.median)[0]
        perturbed = np.repeat(x[None, :], len(changed), axis=0)
        perturbed[np.arange(len(changed)), changed] = self.median[changed]
        return changed, perturbed

    def precompute(self, rows):
        """여러 플로우의 변형을 score_samples 한 번으로 계산해 캐시 (플로우마다 따로 부르면 이상 수천 개일 때 느림)"""
        idx = [self.row_of[k] for k in rows if k in self.row_of and self.row_of[k] not in self._cache]
        parts = [(i, *self._perturb(i)) for i in idx]
        parts = [p for p in parts if len(p[1])]
        if not parts:
            return
        all_scores = -self.model.score_samples(np.vstack([p[2] for p in parts]))
        pos = 0
        for i, changed, perturbed in parts:
            self._cache[i] = (changed, self.scores[i] - all_scores[pos:pos + len(changed)])
            pos += len(changed)

    def contributions(self, i):
        """특징 j를 중앙값으로 바꿨을 때 점수 하락폭이 큰 순으로 반환"""
        if i not in self._cache:
            changed, perturbed = self._perturb(i)
            if len(changed) == 0:
                return []
            self._cache[i] = (changed, self.scores[i] - (-self.model.score_samples(perturbed)))
        changed, drops = self._cache[i]
        order = np.argsort(-drops)
        return [(self.names[changed[k]], float(drops[k])) for k in order]

    def describe_feature(self, name, i, r):
        label, unit = FEATURE_INFO.get(name, (name, ""))
        if unit is None:  # 원-핫 / 이진 특징 -> 같은 값을 가진 플로우 비율로 설명
            v = self.X_df.at[i, name]
            share = self._shares(name).get(v, 0.0) * 100
            return f"{label} 해당 (전체의 {share:.1f}%)" if v == 1 else f"{label} 아님 (이런 플로우 {share:.1f}%)"
        sorted_col, n, median = self._col_stats(name)
        v = getattr(r, name)
        pct = np.searchsorted(sorted_col, v, side="left") / n * 100  # == (col < v).mean() * 100
        pos = f"상위 {100 - pct:.1f}%" if pct >= 50 else f"하위 {pct:.1f}%"
        return f"{label} {fmt(v, unit)} (중앙값 {fmt(median, unit)}, {pos})"

    # 이상 플로우마다 전체 플로우를 다시 훑지 않도록 특징별 통계를 한 번만 계산해 캐시
    def _col_stats(self, name):
        if name not in self._stats:
            col = self.flows[name]
            self._stats[name] = (np.sort(col.to_numpy(dtype=float)), len(col), col.median())
        return self._stats[name]

    def _shares(self, name):
        if name not in self._stats:
            self._stats[name] = self.X_df[name].value_counts(normalize=True).to_dict()
        return self._stats[name]

    def reasons(self, r, top_k=TOP_K):
        i = self.row_of.get(tuple(getattr(r, c) for c in META_COLS))
        if i is None:
            return []
        return [{"feature": n, "description": self.describe_feature(n, i, r), "contribution": round(d, 3)}
                for n, d in self.contributions(i)[:top_k]]


# ---- 메인: 이상 플로우별 설명 리스트 ----
def _load(x):
    return x.copy() if isinstance(x, pd.DataFrame) else pd.read_csv(x)


def explain_anomalies(anomalies, vectors=None, pcap_path=None, top_k=TOP_K, ip_domain=None):
    """
    anomalies : packet_analysis.analyze() 결과 DataFrame 또는 anomalies_*.csv 경로
                (탐지 대상 전체 플로우 + anomaly_score + is_anomaly. 출발지 맥락 계산에 전체가 필요)
    vectors   : flow_vectors_*.csv 경로 또는 DataFrame. 주면 모델 원인(model_reasons)까지 계산.
                None 이고 anomalies 가 경로면 같은 폴더의 flow_vectors_<run_id>.csv 를 자동으로 찾음
    pcap_path : 주면 캡처 안의 DNS 응답으로 IP 옆에 도메인 이름을 붙임 (판단에는 영향 없음)
    ip_domain : 이미 만든 IP -> 도메인 딕셔너리 (packet_analysis.analyze() 결과의 attrs["ip_domain"]).
                주면 pcap_path 로 캡처를 다시 읽지 않음

    반환: 이상 플로우마다 {"rank", "score", "flow": {...}, "reason": {...}} 딕셔너리 리스트
          (위험 점수 -> anomaly_score 높은 순)
    """
    attrs = anomalies.attrs if isinstance(anomalies, pd.DataFrame) else {}
    df = _load(anomalies)

    if vectors is None and not isinstance(anomalies, pd.DataFrame):
        p = Path(anomalies)
        guess = p.with_name(p.name.replace("anomalies_", "flow_vectors_", 1))
        if guess != p and guess.exists():
            vectors = guess

    ctx = build_context(df)
    explainer = (ModelExplainer(df, _load(vectors), attrs.get("iforest"), attrs.get("median"))
                 if vectors is not None else None)
    if ip_domain is None:
        ip_domain = resolve_domains(pcap_path) if pcap_path is not None else {}

    def name(ip):
        return f"{ip}({ip_domain[ip]})" if ip in ip_domain else ip

    anom = df[df["is_anomaly"] == 1]
    if explainer:
        explainer.precompute(tuple(k) for k in anom[META_COLS].itertuples(index=False))
    items = []
    for r in anom.itertuples(index=False):
        verdict, kind, explanation = judge(r, ctx)
        risk, kinds, evidence = assess(r, ctx)
        proto = IP_PROTOCOLS.get(r.protocol, f"proto {r.protocol}")
        items.append({
            "score": round(float(r.anomaly_score), 3),
            "flow": {
                "summary": f"{name(r.src)}:{r.sport} -> {name(r.dst)}:{r.dport}"
                           + (f"({svc(r.dport)})" if svc(r.dport) else "") + f" ({proto})",
                "src": r.src, "sport": int(r.sport), "dst": r.dst, "dport": int(r.dport),
                "protocol": proto, "start_time": float(r.start_time), "duration": float(r.duration),
                "fwd_pkts": int(r.fwd_pkts), "bwd_pkts": int(r.bwd_pkts),
                "fwd_bytes": int(r.fwd_bytes), "bwd_bytes": int(r.bwd_bytes),
            },
            "reason": {
                "risk_level": level(risk),        # 높음 / 중간 / 낮음
                "risk": int(risk),
                "suspected": kinds,               # 의심 유형 목록
                "evidence": evidence,             # 근거 목록
                "verdict": verdict,               # 정상 추정 / 확인 필요 / 의심
                "type": kind,
                "explanation": explanation,
                "attack": attack_techniques(kinds, kind, verdict),  # MITRE ATT&CK 기법
                "model_reasons": explainer.reasons(r, top_k) if explainer else [],
            },
        })

    items.sort(key=lambda x: (x["reason"]["risk"], x["score"]), reverse=True)
    for rank, item in enumerate(items, 1):
        item["rank"] = rank
    return [{"rank": x.pop("rank"), **x} for x in items]


def print_report(items, limit=30):
    print(f"이상 판정 {len(items)}개\n")
    for x in items[:limit]:
        r = x["reason"]
        print(f"#{x['rank']:<4} [{r['risk_level']} {r['risk']}점 / {r['verdict']}] "
              f"{', '.join(r['suspected'])}  (score={x['score']:.3f})")
        print(f"      {x['flow']['summary']}")
        for e in r["evidence"]:
            print(f"      - {e}")
        if r["attack"]:
            print("      ATT&CK: " + ", ".join(f"{t['id']} {t['name']}" for t in r["attack"]))
        print(f"      => {r['explanation']}")
        for m in r["model_reasons"]:
            print(f"      * {m['description']} [-{m['contribution']:.3f}]")
        print()


# ---- 점수 요약 / 차트 (노트북 5번) ----
TYPE_COLORS = {
    "ICMP 오류 (내부→외부)": "#2a78d6",
    "ICMP 오류 (외부→내부)": "#eb6834",
    "mDNS 유니캐스트": "#1baf7a",
    "장시간 연결": "#eda100",
    "대용량 다운로드": "#e87ba4",
    "기타": "#8a96a3",
}


def flow_type(r):
    if r.protocol == 1:
        return "ICMP 오류 (내부→외부)" if is_internal(r.src) else "ICMP 오류 (외부→내부)"
    if r.dport == 5353:
        return "mDNS 유니캐스트"
    if r.duration > 600:
        return "장시간 연결"
    if r.bwd_bytes > 1_000_000:
        return "대용량 다운로드"
    return "기타"


def summarize(anomalies, top_n=20):
    """전체 요약 + 점수 상위 top_n 플로우 표 반환"""
    df = _load(anomalies).sort_values("anomaly_score", ascending=False)
    threshold = df.loc[df["is_anomaly"] == 1, "anomaly_score"].min()  # 이상 판정 중 최저 점수
    top = df.head(top_n).copy()
    top["type"] = top.apply(flow_type, axis=1)
    top["flow"] = (top["src"] + ":" + top["sport"].astype(str) + " -> "
                   + top["dst"] + ":" + top["dport"].astype(str))
    stats = {
        "total_flows": len(df),
        "anomalies": int(df["is_anomaly"].sum()),
        "threshold": float(threshold),
        "median_score": float(df["anomaly_score"].median()),
    }
    table = (top[["anomaly_score", "flow", "type", "duration", "fwd_pkts", "bwd_pkts", "bwd_bytes"]]
             .rename(columns={"anomaly_score": "score"}).round(3))
    return stats, table


def score_histogram(anomalies, bins=30):
    """이상 점수 분포 (plot_scores 왼쪽 그래프의 데이터 버전). 웹 프론트에서 직접 그릴 때 사용"""
    df = _load(anomalies)
    scores = df["anomaly_score"].to_numpy()
    edges = np.histogram_bin_edges(scores, bins=bins)
    normal, _ = np.histogram(scores[df["is_anomaly"].to_numpy() == 0], bins=edges)
    anom, _ = np.histogram(scores[df["is_anomaly"].to_numpy() == 1], bins=edges)
    return [{"x0": float(edges[i]), "x1": float(edges[i + 1]), "normal": int(normal[i]), "anomaly": int(anom[i])}
            for i in range(len(edges) - 1)]


def plot_scores(anomalies, top_n=20):
    """이상 점수 분포 / 상위 top_n 점수 차트. matplotlib Figure 반환 (웹에서는 fig.savefig 로 이미지 저장)"""
    import matplotlib
    matplotlib.use("Agg")  # 서버(GUI 없음)에서도 동작
    import matplotlib.pyplot as plt
    plt.rcParams["font.family"] = "AppleGothic"   # macOS 한글 폰트 (Windows는 "Malgun Gothic")
    plt.rcParams["axes.unicode_minus"] = False

    df = _load(anomalies).sort_values("anomaly_score", ascending=False)
    stats, top = summarize(df, top_n)
    threshold = stats["threshold"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5), gridspec_kw={"width_ratios": [1.2, 1]})

    normal = df.loc[df["is_anomaly"] == 0, "anomaly_score"]
    anom = df.loc[df["is_anomaly"] == 1, "anomaly_score"]
    bins = [0.33 + 0.01 * i for i in range(41)]
    ax1.hist(normal, bins=bins, color="#2a78d6", rwidth=0.85, label="정상 판정")
    ax1.hist(anom, bins=bins, color="#d93b3a", rwidth=0.85, label="이상 판정")
    ax1.axvline(threshold, color="#d93b3a", lw=1.5)
    ax1.text(threshold, ax1.get_ylim()[1] * 0.95, f" 이상 판정 최저 {threshold:.3f}", color="#d93b3a", va="top")
    ax1.set_title("이상 점수 분포 (높을수록 이상)")
    ax1.set_xlabel("anomaly_score")
    ax1.set_ylabel("플로우 수")
    ax1.legend(frameon=False)

    y = range(len(top))[::-1]  # 1위가 맨 위
    ax2.barh(list(y), top["score"], color=top["type"].map(TYPE_COLORS), height=0.7)
    ax2.set_yticks(list(y))
    ax2.set_yticklabels([f"#{i + 1} {f}" for i, f in enumerate(top["flow"])], fontsize=8)
    ax2.set_xlim(threshold - 0.05, top["score"].max() + 0.01)
    ax2.axvline(threshold, color="#d93b3a", lw=1.2)
    ax2.set_title(f"상위 {top_n}개 이상 플로우")
    ax2.set_xlabel("anomaly_score")
    shown = [t for t in TYPE_COLORS if t in set(top["type"])]
    ax2.legend([plt.Rectangle((0, 0), 1, 1, color=TYPE_COLORS[t]) for t in shown], shown,
               frameon=False, fontsize=8, loc="lower right")

    for ax in (ax1, ax2):
        ax.spines[["top", "right"]].set_visible(False)

    fig.tight_layout()
    return fig


if __name__ == "__main__":
    import sys
    # 사용: python packet_anomaly.py packet_convert/anomalies_<run_id>.csv
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        found = sorted((Path(__file__).parent / "packet_convert").glob("anomalies_*.csv"))
        if not found:
            sys.exit("packet_convert/ 에 anomalies_*.csv 가 없음 -> packet_analysis.py 를 먼저 실행하세요")
        path = found[-1]
    stats, table = summarize(path)
    print(stats)
    print(table.to_string(index=False), "\n")
    print_report(explain_anomalies(path))
