import math
import shutil
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile

import packet_analysis
import packet_anomaly

BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
OUT_DIR = BASE_DIR / "packet_convert"
ALLOWED_EXT = {".pcap", ".pcapng"}

UPLOAD_DIR.mkdir(exist_ok=True)

app = FastAPI()


@app.get("/")
def root():
    return {"status": "ok"}


def _clean(v):
    # NaN / inf 는 JSON 으로 못 보내므로 None 으로
    return None if isinstance(v, float) and not math.isfinite(v) else v


@app.post("/analyze")
def analyze(file: UploadFile = File(...), top_n: int = 20):
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(400, f"pcap / pcapng 파일만 업로드할 수 있어요 (받은 확장자: {ext or '없음'})")

    # 1) 업로드 파일 저장
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
    pcap_path = UPLOAD_DIR / f"{run_id}{ext}"
    with pcap_path.open("wb") as f:
        shutil.copyfileobj(file.file, f)

    # 2) packet_analysis: 패킷 -> 플로우 -> 벡터 -> Isolation Forest
    try:
        result = packet_analysis.analyze(pcap_path, save_dir=OUT_DIR, run_id=run_id)
    except Exception as e:
        raise HTTPException(422, f"패킷 분석 실패: {e}")

    # 3) packet_anomaly: 요약 + 이상 플로우별 설명
    vectors = OUT_DIR / f"flow_vectors_{run_id}.csv"
    stats, table = packet_anomaly.summarize(result, top_n)
    items = packet_anomaly.explain_anomalies(result, vectors=vectors, pcap_path=pcap_path)

    return {
        "run_id": run_id,
        "filename": file.filename,
        "excluded_flows": result.attrs.get("excluded", 0),
        "stats": {k: _clean(v) for k, v in stats.items()},
        "top": [{k: _clean(v) for k, v in row.items()} for row in table.to_dict(orient="records")],
        "anomalies": items,
    }
