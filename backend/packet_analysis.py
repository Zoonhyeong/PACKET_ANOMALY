# pcapng -> 패킷 -> 플로우 -> 특징 벡터 -> Isolation Forest 이상 탐지
#  - 백엔드에서는 analyze(pcap_path) 하나만 호출하면 됨
#  - 단독 실행 시(python packet_analysis.py) test1.pcapng 분석 + CSV 저장
import ipaddress
import socket
import struct
from datetime import datetime
from pathlib import Path

import dpkt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

BASE_DIR = Path(__file__).parent
OUT_DIR = BASE_DIR / "packet_convert"

IDLE_TIMEOUT = 60.0
CONTAMINATION = 0.02  # 전체 플로우 중 2%를 이상으로 가정
EXCLUDE_LAN_NOISE = True

META_COLS = ["src", "sport", "dst", "dport", "protocol", "start_time"]


# 1) pcap / pcapng -> 패킷 DataFrame (TCP 플래그, TTL, 윈도우, 페이로드 길이, IPv6 포함)
#  - dpkt 로 파싱 (scapy 보다 10배 이상 빠름). .pcap / .pcapng 모두 지원
#  - ip_domain 딕셔너리를 넘기면 같은 패스에서 DNS 응답(A/AAAA)으로 IP -> 도메인도 채움 (파일을 두 번 읽지 않음)
#  - progress(frac) 를 넘기면 읽은 바이트 비율(0~1)을 주기적으로 알려줌
TCP_FLAG_CHARS = "FSRPAUECN"  # scapy str(flags) 와 같은 순서 (bit 0 = FIN ... bit 8 = NS)
PROGRESS_EVERY = 20000


def tcp_flags_str(v):
    return "".join(c for i, c in enumerate(TCP_FLAG_CHARS) if v >> i & 1)


def _to_ip(buf, dlt):
    """링크 계층을 벗겨 dpkt IP / IP6 객체 반환 (IP 가 아니면 None)"""
    if dlt == dpkt.pcap.DLT_EN10MB:
        l3 = dpkt.ethernet.Ethernet(buf).data
    elif dlt in (dpkt.pcap.DLT_RAW, 12, 14, dpkt.pcap.DLT_IPV4, dpkt.pcap.DLT_IPV6):
        l3 = dpkt.ip6.IP6(buf) if buf and buf[0] >> 4 == 6 else dpkt.ip.IP(buf)
    elif dlt == dpkt.pcap.DLT_LINUX_SLL:
        l3 = dpkt.sll.SLL(buf).data
    elif dlt == dpkt.pcap.DLT_LINUX_SLL2:
        l3 = dpkt.sll2.SLL2(buf).data
    elif dlt in (dpkt.pcap.DLT_NULL, dpkt.pcap.DLT_LOOP):
        l3 = dpkt.loopback.Loopback(buf).data
    else:
        raise ValueError(f"지원하지 않는 링크 타입: {dlt}")
    return l3 if isinstance(l3, (dpkt.ip.IP, dpkt.ip6.IP6)) else None


def _collect_dns(data, ip_domain):
    try:
        dns = dpkt.dns.DNS(data)
    except Exception:
        return
    if dns.qr != dpkt.dns.DNS_R or not dns.qd:
        return
    qname = dns.qd[0].name.rstrip(".")
    for rr in dns.an:
        if rr.type == dpkt.dns.DNS_A and len(rr.rdata) == 4:
            ip_domain.setdefault(socket.inet_ntop(socket.AF_INET, rr.rdata), qname)
        elif rr.type == dpkt.dns.DNS_AAAA and len(rr.rdata) == 16:
            ip_domain.setdefault(socket.inet_ntop(socket.AF_INET6, rr.rdata), qname)


def pcap_to_packets(pcap_path, ip_domain=None, progress=None):
    cols = {c: [] for c in ["No", "Time", "Length", "IPVer", "Src", "Dst", "Protocol",
                            "Sport", "Dport", "TTL", "Flags", "Window", "PayloadLen"]}
    total = max(Path(pcap_path).stat().st_size, 1)
    ntop4 = lambda b: socket.inet_ntop(socket.AF_INET, b)
    ntop6 = lambda b: socket.inet_ntop(socket.AF_INET6, b)

    with open(pcap_path, "rb") as f:
        reader = dpkt.pcap.UniversalReader(f)
        dlt = reader.datalink()
        for i, (ts, buf) in enumerate(reader, 1):
            if progress and i % PROGRESS_EVERY == 0:
                progress(f.tell() / total)
            try:
                ip = _to_ip(buf, dlt)
            except (dpkt.UnpackError, IndexError, ValueError, struct.error):
                continue
            if ip is None:
                continue  # ARP 등 비 IP 패킷은 플로우 분석에서 제외

            # 길이는 캡처된 바이트(len(buf))가 아니라 IP 헤더의 길이 필드에서 읽음
            #  -> snaplen 으로 페이로드가 잘린 캡처(공개 데이터셋에 흔함)에서도 원래 크기를 그대로 씀
            if isinstance(ip, dpkt.ip.IP):
                ip_ver, src, dst, proto, ttl = 4, ntop4(ip.src), ntop4(ip.dst), ip.p, ip.ttl
                ip_len, ip_hdr = ip.len, ip.hl * 4
            else:
                ip_ver, src, dst, proto, ttl = 6, ntop6(ip.src), ntop6(ip.dst), ip.p, ip.hlim
                ip_len, ip_hdr = 40 + ip.plen, 40

            l4 = ip.data
            sport = dport = window = None
            flags = ""
            payload_len = 0
            if isinstance(l4, dpkt.tcp.TCP):
                sport, dport, window = l4.sport, l4.dport, l4.win
                flags = tcp_flags_str(l4.flags)
                payload_len = max(ip_len - ip_hdr - l4.off * 4, 0)
            elif isinstance(l4, dpkt.udp.UDP):
                sport, dport = l4.sport, l4.dport
                payload_len = max(l4.ulen - 8, 0)
                if ip_domain is not None and sport == 53:
                    _collect_dns(l4.data, ip_domain)

            cols["No"].append(i)
            cols["Time"].append(float(ts))
            cols["Length"].append(ip_len)
            cols["IPVer"].append(ip_ver)
            cols["Src"].append(src)
            cols["Dst"].append(dst)
            cols["Protocol"].append(proto)
            cols["Sport"].append(sport)
            cols["Dport"].append(dport)
            cols["TTL"].append(ttl)
            cols["Flags"].append(flags)
            cols["Window"].append(window)
            cols["PayloadLen"].append(payload_len)

    if not cols["No"]:
        raise ValueError("IP 패킷이 하나도 없음")

    pkt_df = pd.DataFrame(cols)
    for c in ["Sport", "Dport", "Window"]:
        pkt_df[c] = pkt_df[c].astype("Int64")  # 443.0 -> 443 (결측은 <NA>)
    return pkt_df


# 2) 패킷 -> 플로우 집계
#  - 키: 양방향 5-tuple (A:p1 -> B:p2 와 B:p2 -> A:p1 을 같은 플로우로)
#  - 종료: 마지막 패킷 이후 idle_timeout 초 동안 패킷이 없으면 / RST / 양쪽 모두 FIN
#  - fwd(정방향) = 연결을 시작한 쪽 (SYN 보낸 쪽, 없으면 포트 번호가 큰 쪽 = 클라이언트)
def flow_key(src, dst, sport, dport, proto):
    a, b = (src, sport), (dst, dport)
    return (min(a, b), max(a, b), proto)


def new_flow(p):
    syn_only = "S" in p.Flags and "A" not in p.Flags
    if syn_only or p.Sport >= p.Dport:
        client, server = (p.Src, p.Sport), (p.Dst, p.Dport)
    else:
        client, server = (p.Dst, p.Dport), (p.Src, p.Sport)
    return {"client": client, "server": server, "proto": p.Protocol,
            "times": [], "lens": [], "dirs": [], "payloads": [],
            "ttls": [], "wins": [], "flags": [], "fin_fwd": False, "fin_bwd": False}


def summarize(f):
    t = np.array(f["times"])
    lens = np.array(f["lens"])
    dirs = np.array(f["dirs"])          # 1 = fwd, 0 = bwd
    payloads = np.array(f["payloads"])
    flags = f["flags"]
    fwd, bwd = lens[dirs == 1], lens[dirs == 0]
    iat = np.diff(t) if len(t) > 1 else np.array([0.0])
    duration = t[-1] - t[0]
    dur_safe = max(duration, 1e-6)

    def stat(arr, fn):
        return float(fn(arr)) if len(arr) else 0.0

    return {
        "src": f["client"][0], "sport": f["client"][1],
        "dst": f["server"][0], "dport": f["server"][1],
        "protocol": f["proto"],
        "start_time": t[0],
        "duration": duration,
        "fwd_pkts": len(fwd), "bwd_pkts": len(bwd),
        "fwd_bytes": int(fwd.sum()), "bwd_bytes": int(bwd.sum()),
        "pkt_len_mean": lens.mean(), "pkt_len_std": lens.std(),
        "pkt_len_max": lens.max(), "pkt_len_min": lens.min(),
        "fwd_len_mean": stat(fwd, np.mean), "bwd_len_mean": stat(bwd, np.mean),
        "iat_mean": iat.mean(), "iat_std": iat.std(),
        "iat_max": iat.max(), "iat_min": iat.min(),
        "pkts_per_sec": len(lens) / dur_safe,
        "bytes_per_sec": lens.sum() / dur_safe,
        "down_up_ratio": len(bwd) / max(len(fwd), 1),
        "payload_bytes": int(payloads.sum()),
        "zero_payload_ratio": float((payloads == 0).mean()),
        "syn_cnt": sum("S" in x for x in flags),
        "ack_cnt": sum("A" in x for x in flags),
        "fin_cnt": sum("F" in x for x in flags),
        "rst_cnt": sum("R" in x for x in flags),
        "psh_cnt": sum("P" in x for x in flags),
        "urg_cnt": sum("U" in x for x in flags),
        "ttl_mean": float(np.mean(f["ttls"])),
        "win_mean": float(np.mean(f["wins"])),
    }


def packets_to_flows(pkt_df, idle_timeout=IDLE_TIMEOUT):
    pkt_df = pkt_df.sort_values("Time").reset_index(drop=True)
    pkt_df["Sport"] = pkt_df["Sport"].fillna(0).astype(int)  # ICMP 등 포트 없는 프로토콜은 0
    pkt_df["Dport"] = pkt_df["Dport"].fillna(0).astype(int)
    pkt_df["Flags"] = pkt_df["Flags"].fillna("")
    pkt_df["Window"] = pkt_df["Window"].fillna(0).astype(int)

    active, last_seen, flows = {}, {}, []

    for p in pkt_df.itertuples(index=False):
        key = flow_key(p.Src, p.Dst, p.Sport, p.Dport, p.Protocol)

        if key in active and p.Time - last_seen[key] > idle_timeout:
            flows.append(summarize(active.pop(key)))
        if key not in active:
            active[key] = new_flow(p)

        f = active[key]
        is_fwd = (p.Src, p.Sport) == f["client"]
        f["times"].append(p.Time)
        f["lens"].append(p.Length)
        f["dirs"].append(1 if is_fwd else 0)
        f["payloads"].append(p.PayloadLen)
        f["ttls"].append(p.TTL)
        f["wins"].append(p.Window)
        f["flags"].append(p.Flags)
        last_seen[key] = p.Time

        if "F" in p.Flags:
            f["fin_fwd" if is_fwd else "fin_bwd"] = True
        if "R" in p.Flags or (f["fin_fwd"] and f["fin_bwd"]):
            flows.append(summarize(active.pop(key)))

    flows.extend(summarize(f) for f in active.values())  # 캡처 종료 시점에 열려 있던 플로우

    return pd.DataFrame(flows).sort_values("start_time").reset_index(drop=True)


# 3) 플로우 -> 특징 벡터
#  - IP/포트 원본값은 모델이 특정 값을 외우지 않도록 벡터에서 제외하고 파생 특징으로 대체
#  - 꼬리가 긴 수치형(바이트, 패킷 수 등)은 log1p 변환 후 StandardScaler
def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return int(a.is_private or a.is_link_local)
    except ValueError:
        return 0


def is_multicast(ip):
    try:
        return int(ipaddress.ip_address(ip).is_multicast)
    except ValueError:
        return 0


def port_category(port):
    if port == 0:
        return "none"
    if port < 1024:
        return "well_known"
    if port < 49152:
        return "registered"
    return "ephemeral"


NUM_COLS = [
    "duration", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
    "pkt_len_mean", "pkt_len_std", "pkt_len_max", "pkt_len_min",
    "fwd_len_mean", "bwd_len_mean",
    "iat_mean", "iat_std", "iat_max", "iat_min",
    "pkts_per_sec", "bytes_per_sec", "down_up_ratio",
    "payload_bytes", "zero_payload_ratio",
    "syn_cnt", "ack_cnt", "fin_cnt", "rst_cnt", "psh_cnt", "urg_cnt",
    "ttl_mean", "win_mean",
]


# 원-핫 컬럼을 고정해 둠. 캡처에 없는 값(예: ICMP 가 하나도 없음)이어도 같은 컬럼 구성이 나와야
# 저장해 둔 기준선 모델에 그대로 넣을 수 있음
CAT_COLS = ["src_internal", "dst_internal", "dst_multicast",
            "proto_icmp", "proto_other", "proto_tcp", "proto_udp",
            "dport_ephemeral", "dport_none", "dport_registered", "dport_well_known"]
FEATURE_COLS = NUM_COLS + CAT_COLS
LOG_COLS = [c for c in NUM_COLS if c not in ("zero_payload_ratio", "ttl_mean")]


def _numeric(flow_df):
    num = flow_df[NUM_COLS].astype(float).fillna(0)
    num[LOG_COLS] = np.log1p(num[LOG_COLS].clip(lower=0))
    return num


def flows_to_vectors(flow_df, scaler=None):
    """특징 벡터 DataFrame 반환 (flow_df 와 같은 index, 메타 컬럼 미포함)
    scaler 를 주면 그 기준(=기준선 모델 학습 데이터)으로 정규화하고, 없으면 이 캡처로 새로 맞춤"""
    feat = pd.DataFrame(index=flow_df.index)

    # 파생 범주형 특징
    feat["src_internal"] = flow_df["src"].map(is_private)
    feat["dst_internal"] = flow_df["dst"].map(is_private)
    feat["dst_multicast"] = flow_df["dst"].map(is_multicast)
    proto_name = flow_df["protocol"].map({6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}).fillna("other")
    dport_cat = flow_df["dport"].map(port_category)
    feat = feat.join(pd.get_dummies(proto_name, prefix="proto", dtype=int))
    feat = feat.join(pd.get_dummies(dport_cat, prefix="dport", dtype=int))
    feat = feat.reindex(columns=CAT_COLS, fill_value=0)

    # 수치형 특징 (꼬리가 긴 값은 log1p 후 표준화)
    num = _numeric(flow_df)
    if scaler is None:
        scaler = StandardScaler().fit(num)
    num_scaled = pd.DataFrame(scaler.transform(num), columns=NUM_COLS, index=flow_df.index)

    return pd.concat([num_scaled, feat], axis=1)[FEATURE_COLS]


# 4) Isolation Forest 이상 탐지
#  - 라벨이 없으므로 contamination(이상 비율)은 가정값. 상위 몇 %를 이상으로 볼지 정하는 값
#  - anomaly_score: 클수록 이상 (sklearn score_samples 부호 반전)
#  - exclude_lan_noise: IGMP·멀티캐스트·브로드캐스트(mDNS, SSDP 등)는 수가 적어서 이상치로 뽑히기 쉬움
#    -> 학습/탐지에서 제외해야 실제로 볼 만한 플로우가 상위에 올라옴
def is_lan_noise(ip):
    a = ipaddress.ip_address(ip)
    return a.is_multicast or ip == "255.255.255.255" or ip.endswith(".255")


def lan_noise_mask(flow_df):
    """True = 분석 대상 (LAN 브로드캐스트·멀티캐스트·IGMP 가 아님)"""
    return ~(flow_df["dst"].map(is_lan_noise) | (flow_df["protocol"] == 2))  # 2 = IGMP


def _new_iforest(contamination="auto"):
    return IsolationForest(n_estimators=300, contamination=contamination, random_state=42, n_jobs=-1)


# ---- 기준선(baseline) 모델 ----
#  캡처마다 새로 학습하면 "그 캡처 안에서 드문 것"만 찾게 되고, contamination 비율만큼은
#  깨끗한 트래픽에서도 무조건 이상으로 뽑힘 (= 오탐).
#  정상 기간 트래픽으로 한 번 학습해 저장해 두고, 새 캡처는 그 기준으로 점수를 매기면
#  - 공격이 많아 캡처 안에서 흔해져도(스캔·DDoS) 정상 기준과 다르면 잡을 수 있고
#  - 임계값을 "정상 트래픽에서 목표 오탐률(target_fpr)"로 정할 수 있음
DEFAULT_MODEL = BASE_DIR / "models" / "baseline.joblib"


def fit_baseline(flow_df, target_fpr=0.01, exclude_lan_noise=EXCLUDE_LAN_NOISE):
    """정상 트래픽 플로우로 기준선 모델 학습. {scaler, iforest, threshold, median, ...} 딕셔너리 반환"""
    if exclude_lan_noise:
        flow_df = flow_df.loc[lan_noise_mask(flow_df)]
    scaler = StandardScaler().fit(_numeric(flow_df))
    X = flows_to_vectors(flow_df, scaler).to_numpy(dtype=np.float32)
    iforest = _new_iforest().fit(X)
    scores = -iforest.score_samples(X)
    return {
        "scaler": scaler,
        "iforest": iforest,
        "threshold": float(np.quantile(scores, 1 - target_fpr)),  # 학습 데이터의 target_fpr 만큼만 넘는 점수
        "median": np.median(X, axis=0),                             # 원인 설명에서 "정상값"으로 씀
        "target_fpr": target_fpr,
        "n_train": len(X),
        "features": FEATURE_COLS,
        "trained_at": datetime.now().isoformat(timespec="seconds"),
    }


def save_model(model, path=DEFAULT_MODEL):
    import joblib
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


def load_model(path=DEFAULT_MODEL):
    """저장된 기준선 모델을 읽음. 파일이 없으면 None (-> 캡처별 학습 모드)"""
    import joblib
    path = Path(path)
    if not path.exists():
        return None
    model = joblib.load(path)
    if model.get("features") != FEATURE_COLS:
        raise ValueError(f"{path} 의 특징 구성이 현재 코드와 달라요. 기준선 모델을 다시 학습하세요")
    return model


def detect_anomalies(flow_df, X_df, contamination=CONTAMINATION, exclude_lan_noise=EXCLUDE_LAN_NOISE, model=None):
    """model 이 있으면 기준선 모델로 점수/임계값 적용, 없으면 이 캡처로 Isolation Forest 학습
    (contamination 비율만큼 이상 판정)"""
    mask = lan_noise_mask(flow_df) if exclude_lan_noise else pd.Series(True, index=flow_df.index)
    if mask.sum() == 0:
        raise ValueError("노이즈 제외 후 남은 플로우가 없음 -> exclude_lan_noise=False로 다시 실행")

    X = X_df.loc[mask].to_numpy(dtype=np.float32)

    if model is not None:
        iforest, median = model["iforest"], model["median"]
        scores = -iforest.score_samples(X)
        is_anom = scores > model["threshold"]
        mode = "baseline"
    else:
        iforest = _new_iforest(contamination).fit(X)
        median = np.median(X, axis=0)
        scores = -iforest.score_samples(X)
        is_anom = iforest.predict(X) == -1
        mode = "per_capture"

    result = flow_df.loc[mask].copy()
    result["anomaly_score"] = scores
    result["is_anomaly"] = is_anom.astype(int)
    result = result.sort_values("anomaly_score", ascending=False).reset_index(drop=True)
    result.attrs["excluded"] = int((~mask).sum())
    # 원인 설명(packet_anomaly.ModelExplainer)이 모델을 다시 학습하지 않고 그대로 쓰도록 넘김
    result.attrs["iforest"] = iforest
    result.attrs["median"] = median
    result.attrs["mode"] = mode
    return result


# 전체 파이프라인
def analyze(pcap_path, save_dir=None, run_id=None,
            contamination=CONTAMINATION, exclude_lan_noise=EXCLUDE_LAN_NOISE,
            save_packets=True, progress=None, model=None):
    """pcap 파일 하나를 분석해 플로우별 anomaly_score 가 붙은 DataFrame 반환.
    save_dir 를 주면 중간 결과(패킷/플로우/벡터/이상탐지) CSV 를 저장.
    save_packets=False 면 패킷 CSV 는 건너뜀 (패킷 수백만 개면 CSV 저장만 수십 초).
    progress(stage, frac) 를 주면 단계("parse", "flows", "vectors", "detect", "save")와 진행률을 알려줌.
    반환 DataFrame 의 attrs: excluded(제외 플로우 수), ip_domain(DNS 응답으로 얻은 IP -> 도메인),
                             flow_vectors(식별 정보 + 특징 벡터 DataFrame), mode(baseline / per_capture)
    model 에 fit_baseline() 결과를 주면 기준선 모드, None 이면 캡처별 학습 모드"""
    step = progress or (lambda stage, frac=None: None)
    ip_domain = {}

    step("parse", 0.0)
    pkt_df = pcap_to_packets(pcap_path, ip_domain, progress=lambda frac: step("parse", frac))
    step("flows")
    flow_df = packets_to_flows(pkt_df)
    step("vectors")
    X_df = flows_to_vectors(flow_df, model["scaler"] if model else None)
    step("detect")
    result = detect_anomalies(flow_df, X_df, contamination, exclude_lan_noise, model=model)
    vectors = pd.concat([flow_df[META_COLS], X_df], axis=1)
    result.attrs["ip_domain"] = ip_domain
    result.attrs["flow_vectors"] = vectors

    if save_dir is not None:
        step("save")
        save_dir = Path(save_dir)
        save_dir.mkdir(parents=True, exist_ok=True)
        run_id = run_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        if save_packets:
            pkt_df.to_csv(save_dir / f"packets_{run_id}.csv", index=False, encoding="utf-8-sig")
        flow_df.to_csv(save_dir / f"flows_{run_id}.csv", index=False, encoding="utf-8-sig")
        # 벡터 + 어떤 플로우인지 알 수 있는 식별 정보를 같이 저장 (이상 탐지 결과 해석용)
        vectors.to_csv(save_dir / f"flow_vectors_{run_id}.csv", index=False, encoding="utf-8-sig")
        result.to_csv(save_dir / f"anomalies_{run_id}.csv", index=False, encoding="utf-8-sig")

    print(f"패킷 {len(pkt_df)}개 -> 플로우 {len(flow_df)}개 -> 특징 벡터 {X_df.shape}")
    print(f"분석 대상 플로우 {len(result)}개 (제외 {result.attrs['excluded']}개) 중 "
          f"이상 {result['is_anomaly'].sum()}개 [{result.attrs['mode']}]")
    return result


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="pcap 이상 탐지 / 기준선 모델 학습")
    ap.add_argument("pcap", nargs="+", type=Path)
    ap.add_argument("--fit-baseline", action="store_true",
                    help="주어진 pcap(정상 트래픽)으로 기준선 모델을 학습해 models/baseline.joblib 에 저장")
    ap.add_argument("--target-fpr", type=float, default=0.01, help="기준선 임계값의 목표 오탐률 (기본 1%%)")
    args = ap.parse_args()
    if args.fit_baseline:
        flows = pd.concat([packets_to_flows(pcap_to_packets(p)) for p in args.pcap], ignore_index=True)
        m = fit_baseline(flows, args.target_fpr)
        save_model(m)
        print(f"기준선 모델 저장: {DEFAULT_MODEL} (학습 플로우 {m['n_train']}개, 임계값 {m['threshold']:.4f})")
    else:
        for p in args.pcap:
            analyze(p, save_dir=OUT_DIR, model=load_model())
