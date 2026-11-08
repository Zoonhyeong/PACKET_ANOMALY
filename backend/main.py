import math
import shutil
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile

import packet_analysis
import packet_anomaly

BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
OUT_DIR = BASE_DIR / "packet_convert"
ALLOWED_EXT = {".pcap", ".pcapng"}
TOP_N = 20
MAX_WORKERS = 2  # 동시에 돌릴 분석 작업 수 (나머지는 대기열)

UPLOAD_DIR.mkdir(exist_ok=True)

# 기준선 모델 (models/baseline.joblib). 있으면 정상 기준 대비 점수, 없으면 캡처마다 학습
#  만들기: python packet_analysis.py --fit-baseline <정상 트래픽 pcap...>
BASELINE = packet_analysis.load_model()

app = FastAPI()

# ---- 백그라운드 분석 작업 ----
#  POST /analyze      : 파일 저장 후 바로 job_id 반환 (분석은 백그라운드 스레드에서)
#  GET  /jobs/{id}    : 상태(queued / running / done / error), 현재 단계, 진행률, 끝나면 결과
#  작업 목록은 메모리에만 있으므로 서버를 재시작하면 사라짐
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
jobs = {}
jobs_lock = threading.Lock()

# 단계별 전체 진행률 구간 (start, end). 실행 순서대로이며 패킷 파싱이 대부분의 시간을 차지
STAGES = {
    "parse":   (0.00, 0.60, "패킷 파싱"),
    "flows":   (0.60, 0.80, "플로우 집계"),
    "vectors": (0.80, 0.81, "특징 벡터"),
    "detect":  (0.81, 0.86, "이상 탐지"),
    "save":    (0.86, 0.90, "결과 저장"),
    "explain": (0.90, 1.00, "원인 설명"),
}


def _update(job_id, **fields):
    with jobs_lock:
        jobs[job_id].update(fields)


def _clean(v):
    # NaN / inf 는 JSON 으로 못 보내므로 None 으로
    return None if isinstance(v, float) and not math.isfinite(v) else v


def _run(job_id, pcap_path, filename):
    def progress(stage, frac=None):
        start, end, label = STAGES[stage]
        _update(job_id, stage=stage, stage_label=label,
                progress=round(start + (end - start) * (frac or 0.0), 4))

    _update(job_id, status="running", started_at=time.time())
    try:
        # 1) packet_analysis: 패킷 -> 플로우 -> 벡터 -> Isolation Forest (+ DNS 로 IP -> 도메인)
        result = packet_analysis.analyze(pcap_path, save_dir=OUT_DIR, run_id=job_id,
                                         save_packets=False, progress=progress, model=BASELINE)

        # 2) packet_anomaly: 요약 + 이상 플로우별 설명 (캡처 재파싱 없이 attrs 재사용)
        progress("explain")
        stats, table = packet_anomaly.summarize(result, TOP_N)
        items = packet_anomaly.explain_anomalies(result, vectors=result.attrs["flow_vectors"],
                                                 ip_domain=result.attrs["ip_domain"])

        _update(job_id, status="done", stage=None, stage_label="완료", progress=1.0,
                finished_at=time.time(), result={
                    "run_id": job_id,
                    "filename": filename,
                    "excluded_flows": result.attrs.get("excluded", 0),
                    "mode": result.attrs["mode"],  # baseline / per_capture
                    "stats": {k: _clean(v) for k, v in stats.items()},
                    "top": [{k: _clean(v) for k, v in row.items()} for row in table.to_dict(orient="records")],
                    "histogram": packet_anomaly.score_histogram(result),
                    "flow_types": list(packet_anomaly.TYPE_COLORS),  # 상위 플로우 차트의 유형 순서 (색 고정용)
                    "anomalies": items,
                })
    except Exception as e:
        traceback.print_exc()
        _update(job_id, status="error", error=f"패킷 분석 실패: {e}", finished_at=time.time())


@app.get("/")
def root():
    return {"status": "ok"}


@app.post("/analyze", status_code=202)
def analyze(file: UploadFile = File(...)):
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(400, f"pcap / pcapng 파일만 업로드할 수 있어요 (받은 확장자: {ext or '없음'})")

    job_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
    pcap_path = UPLOAD_DIR / f"{job_id}{ext}"
    with pcap_path.open("wb") as f:
        shutil.copyfileobj(file.file, f, length=8 * 1024 * 1024)

    with jobs_lock:
        jobs[job_id] = {"job_id": job_id, "filename": file.filename, "size": pcap_path.stat().st_size,
                        "status": "queued", "stage": None, "stage_label": "대기 중", "progress": 0.0,
                        "created_at": time.time(), "result": None, "error": None}
    executor.submit(_run, job_id, pcap_path, file.filename)
    return {"job_id": job_id}


@app.get("/jobs/{job_id}")
def job_status(job_id: str):
    with jobs_lock:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "작업을 찾을 수 없어요 (서버가 재시작되면 작업 목록이 사라져요)")
        job = dict(job)
    now = job.get("finished_at") or time.time()
    job["elapsed"] = round(now - job.get("started_at", now), 1)
    return job
