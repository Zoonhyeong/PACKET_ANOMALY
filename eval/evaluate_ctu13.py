# CTU-13 공개 데이터셋으로 탐지 성능 평가
#
#  데이터: https://www.stratosphereips.org/datasets-ctu13 (CC-BY)
#   - 시나리오마다 전체 트래픽 pcap(페이로드 잘림) + 플로우별 라벨(binetflow: Botnet / Normal / Background)
#   - 다운로드: eval/download_ctu13.sh
#
#  평가 방법
#   - 우리 파이프라인으로 pcap -> 플로우를 만들고, binetflow 라벨을 5-tuple 로 붙임
#     (ICMP 는 포트가 없으니 IP 쌍 + 프로토콜로 매칭)
#   - 정확도 지표는 Botnet(양성) vs Normal(음성)만으로 계산. Background 는 데이터셋 저자도 "라벨 없음(미확인)"으로
#     두는 트래픽이라(다른 공격·스캔이 섞여 있음) 정답으로 쓰지 않고, 경보 수(관제 업무량)로만 따로 집계
#   - 기준선 모델은 학습용 시나리오(기본 s48)에서 Botnet 라벨을 뺀 트래픽으로만 학습
#     -> 테스트 시나리오(s46, s52)는 학습에 전혀 쓰지 않음 (다른 날 캡처)
#   - 비교 구성
#       A. 캡처별 IF        : 기존 방식. 업로드한 캡처로 바로 학습, 상위 2%를 이상으로
#       B. 기준선 IF        : 정상 기준선 모델, 임계값 = 학습 데이터 기준 오탐률 1%
#       C. 규칙만           : 모든 플로우에 assess() 적용, 위험 점수 2점(중간) 이상
#       D. 하이브리드       : B 의 이상 플로우 중 규칙 위험 2점 이상 (화면에서 "중간/높음"으로 보이는 것)
#       E. 하이브리드(합집합) : B 이상 OR 규칙 위험 4점(높음) 이상
#   - 지표: 플로우 단위 Precision / Recall / F1 / FPR (Botnet vs Normal), 전체 경보 수,
#           호스트 단위 = 경보를 출발지 IP 로 묶었을 때 감염 호스트가 상위 몇 위에 오는지
#
# 사용: python eval/evaluate_ctu13.py            (결과: eval/results/)
import argparse
import csv
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))
import packet_analysis as pa  # noqa: E402
import packet_anomaly as pan  # noqa: E402

DATA = ROOT / "data"
CACHE = ROOT / "cache"
RESULTS = ROOT / "results"

SCENARIOS = {
    # id: (파일 이름, 봇넷 이름, 주요 행위)
    "s46": ("capture20110815-2", "Virut", "IRC C2, 스팸(SMTP), HTTP"),
    "s48": ("capture20110816-2", "Sogou", "HTTP C2"),
    "s52": ("capture20110818-2", "Rbot (3대)", "IRC C2, ICMP DDoS"),
}
PROTO = {"tcp": 6, "udp": 17, "icmp": 1, "ipv6-icmp": 58, "igmp": 2}
RANK = {"Background": 0, "Normal": 1, "Botnet": 2}


# ---- 라벨 ----
def _port(x, proto):
    if proto in (1, 58) or not x:
        return 0
    try:
        return int(x, 0)
    except ValueError:
        return 0


def load_labels(path):
    """binetflow -> {(끝점1, 끝점2, proto): 라벨}. 같은 키가 여러 번 나오면 Botnet > Normal > Background"""
    labels = {}
    infected = set()
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            proto = PROTO.get(row["Proto"])
            if proto is None:
                continue
            L = row["Label"]
            cls = "Botnet" if "Botnet" in L else ("Normal" if "Normal" in L else "Background")
            if cls == "Botnet":
                infected.add(row["SrcAddr"])
            a = (row["SrcAddr"], _port(row["Sport"], proto))
            b = (row["DstAddr"], _port(row["Dport"], proto))
            key = (min(a, b), max(a, b), proto)
            if RANK[cls] > RANK.get(labels.get(key), -1):
                labels[key] = cls
    return labels, infected


def attach_labels(flow_df, labels):
    keys = zip(zip(flow_df["src"], flow_df["sport"].where(~flow_df["protocol"].isin([1, 58]), 0)),
               zip(flow_df["dst"], flow_df["dport"].where(~flow_df["protocol"].isin([1, 58]), 0)),
               flow_df["protocol"])
    out = []
    for a, b, p in keys:
        out.append(labels.get((min(a, b), max(a, b), p), "Unmatched"))
    return pd.Series(out, index=flow_df.index)


# ---- 플로우 (pcap 파싱은 오래 걸리니 캐시) ----
def flows_for(sid):
    name = SCENARIOS[sid][0]
    cache = CACHE / f"{sid}_flows.pkl"
    if cache.exists():
        return pd.read_pickle(cache)
    t = time.time()
    pkt = pa.pcap_to_packets(DATA / sid / f"{name}.truncated.pcap")
    flows = pa.packets_to_flows(pkt)
    labels, _ = load_labels(DATA / sid / f"{name}.binetflow")
    flows["label"] = attach_labels(flows, labels)
    CACHE.mkdir(exist_ok=True)
    flows.to_pickle(cache)
    print(f"[{sid}] 패킷 {len(pkt):,} -> 플로우 {len(flows):,} ({time.time() - t:.0f}s)")
    return flows


# ---- 지표 ----
def metrics(y, pred):
    y, pred = np.asarray(y, bool), np.asarray(pred, bool)
    tp, fp = int((y & pred).sum()), int((~y & pred).sum())
    fn, tn = int((y & ~pred).sum()), int((~y & ~pred).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"alerts": tp + fp, "tp": tp, "fp": fp, "fn": fn,
            "precision": prec, "recall": rec,
            "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
            "fpr": fp / (fp + tn) if fp + tn else 0.0}


def host_rank(df, pred, infected):
    """경보를 출발지 IP 로 묶어 경보 수 순으로 정렬했을 때 감염 호스트들의 순위"""
    counts = df.loc[np.asarray(pred, bool), "src"].value_counts()
    ranks = {ip: (int(np.where(counts.index == ip)[0][0]) + 1 if ip in counts.index else None)
             for ip in sorted(infected)}
    return ranks, len(counts)


def risk_scores(df):
    """모든 플로우에 규칙 기반 위험 점수(assess) 계산"""
    ctx = pan.build_context(df)
    return np.array([pan.assess(r, ctx)[0] for r in df.itertuples(index=False)])


def evaluate(sid, model, contamination):
    flows = flows_for(sid)
    _, infected = load_labels(DATA / sid / f"{SCENARIOS[sid][0]}.binetflow")

    t = time.time()
    per_cap = pa.detect_anomalies(flows, pa.flows_to_vectors(flows), contamination=contamination)
    t_per_cap = time.time() - t
    t = time.time()
    base = pa.detect_anomalies(flows, pa.flows_to_vectors(flows, model["scaler"]), model=model)
    t_base = time.time() - t

    # detect_anomalies 가 점수순으로 재정렬하므로 같은 순서(base 기준)로 맞춤
    key = pa.META_COLS
    per_cap = base[key].merge(per_cap[key + ["is_anomaly"]], on=key, how="left")
    y = (base["label"] == "Botnet").to_numpy()
    scored = base["label"].isin(["Botnet", "Normal"]).to_numpy()  # 정답이 있는 플로우만 정확도 계산
    risk = risk_scores(base)

    preds = {
        "A. 캡처별 IF (상위 2%)": per_cap["is_anomaly"].to_numpy() == 1,
        "B. 기준선 IF (목표 FPR 1%)": base["is_anomaly"].to_numpy() == 1,
        "C. 규칙만 (위험 2점 이상)": risk >= 2,
        "D. 하이브리드 (B 이상 AND 위험 2점 이상)": (base["is_anomaly"].to_numpy() == 1) & (risk >= 2),
        "E. 하이브리드 (B 이상 OR 위험 4점 이상)": (base["is_anomaly"].to_numpy() == 1) | (risk >= 4),
    }
    rows = []
    for name, p in preds.items():
        m = metrics(y[scored], p[scored])
        m["alerts_total"] = int(p.sum())                                      # Background 포함 전체 경보 수
        m["alerts_background"] = int(p[(base["label"] == "Background").to_numpy()].sum())
        m["host_rank"], m["alerting_hosts"] = host_rank(base, p, infected)
        rows.append({"config": name, **m})

    # 봇넷 행위별 탐지율 (B, D 기준)
    labels_full = per_label_recall(sid, base, preds)

    info = {
        "scenario": sid, "botnet": SCENARIOS[sid][1], "behavior": SCENARIOS[sid][2],
        "flows": len(flows), "analyzed": len(base), "excluded_noise": base.attrs["excluded"],
        "label_counts": base["label"].value_counts().to_dict(),
        "infected_hosts": sorted(infected),
        "seconds": {"per_capture": round(t_per_cap, 1), "baseline": round(t_base, 1)},
    }
    return info, rows, labels_full


def per_label_recall(sid, base, preds):
    """봇넷 라벨의 세부 유형(binetflow Label) 별로 B / D 가 몇 % 잡았는지. 5-tuple 로 원래 라벨 문자열을 다시 붙임"""
    name = SCENARIOS[sid][0]
    detail = {}
    with open(DATA / sid / f"{name}.binetflow", newline="") as f:
        for row in csv.DictReader(f):
            proto = PROTO.get(row["Proto"])
            if proto is None or "Botnet" not in row["Label"]:
                continue
            a = (row["SrcAddr"], _port(row["Sport"], proto))
            b = (row["DstAddr"], _port(row["Dport"], proto))
            # 라벨 문자열에서 봇 번호를 빼고 행위만 남김 (From-Botnet-V52-1-ICMP -> ICMP)
            parts = row["Label"].split("-")
            kind = "-".join(p for p in parts[3:] if not p.isdigit()) or row["Label"]
            detail.setdefault((min(a, b), max(a, b), proto), kind)
    ks = attach_labels(base, detail)
    out = {}
    for kind in ks[ks != "Unmatched"].unique():
        m = (ks == kind).to_numpy()
        out[kind] = {"flows": int(m.sum()),
                     **{cfg[:2].strip(". "): float(p[m].mean()) for cfg, p in preds.items()}}
    return dict(sorted(out.items(), key=lambda kv: -kv[1]["flows"]))


def fmt_pct(v):
    return "-" if v is None else f"{v * 100:.1f}%"


def write_markdown(meta, results, path):
    L = ["# CTU-13 평가 결과", "",
         f"- 기준선 학습: {meta['train']} (Botnet 라벨 제외 {meta['n_train']:,}개 플로우), "
         f"목표 FPR {meta['target_fpr'] * 100:.0f}% -> 임계값 {meta['threshold']:.4f}",
         f"- 생성: {meta['generated']}", ""]
    for info, rows, by_kind in results:
        lc = info["label_counts"]
        L += [f"## {info['scenario']} — {info['botnet']} ({info['behavior']})", "",
              f"분석 플로우 {info['analyzed']:,}개 (Botnet {lc.get('Botnet', 0):,} / Normal {lc.get('Normal', 0):,} / "
              f"Background {lc.get('Background', 0):,} / 라벨 없음 {lc.get('Unmatched', 0):,}), "
              f"감염 호스트 {', '.join(info['infected_hosts'])}", "",
              "정확도는 Botnet vs Normal 플로우만으로 계산 / 경보 수·호스트는 Background 포함 전체",
              "",
              "| 구성 | Precision | Recall | F1 | FPR | 전체 경보 수 | 경보 호스트 수 | 감염 호스트 순위 |",
              "|---|---:|---:|---:|---:|---:|---:|---|"]
        for r in rows:
            ranks = ", ".join(f".{ip.split('.')[-1]} {'-' if v is None else str(v) + '위'}"
                              for ip, v in r["host_rank"].items())
            L.append(f"| {r['config']} | {fmt_pct(r['precision'])} | {fmt_pct(r['recall'])} | {r['f1']:.3f} | "
                     f"{fmt_pct(r['fpr'])} | {r['alerts_total']:,} | {r['alerting_hosts']:,} | {ranks} |")
        L += ["", "봇넷 행위별 탐지율", "", "| 행위 | 플로우 | A | B | C | D | E |", "|---|---:|---:|---:|---:|---:|---:|"]
        for k, v in list(by_kind.items())[:12]:
            L.append(f"| {k} | {v['flows']:,} | " + " | ".join(fmt_pct(v[c]) for c in "ABCDE") + " |")
        L.append("")
    path.write_text("\n".join(L), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", default="s48")
    ap.add_argument("--test", nargs="+", default=["s46", "s52"])
    ap.add_argument("--target-fpr", type=float, default=0.01)
    ap.add_argument("--contamination", type=float, default=pa.CONTAMINATION)
    args = ap.parse_args()

    train = flows_for(args.train)
    clean = train[train["label"] != "Botnet"]
    model = pa.fit_baseline(clean, args.target_fpr)
    pa.save_model(model, CACHE / f"baseline_{args.train}.joblib")
    meta = {"train": args.train, "n_train": model["n_train"], "target_fpr": args.target_fpr,
            "threshold": model["threshold"], "generated": time.strftime("%Y-%m-%d %H:%M")}

    results = [evaluate(sid, model, args.contamination) for sid in args.test]

    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "ctu13_results.json").write_text(
        json.dumps({"meta": meta, "results": [{"info": i, "rows": r, "by_behavior": k} for i, r, k in results]},
                   ensure_ascii=False, indent=2, default=float), encoding="utf-8")
    write_markdown(meta, results, RESULTS / "ctu13_results.md")
    print((RESULTS / "ctu13_results.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
