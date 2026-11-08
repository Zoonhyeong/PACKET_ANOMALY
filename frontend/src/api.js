// FastAPI 호출 (vite.config.js 의 /api 프록시 경유)

// 파일 업로드 -> { job_id }. fetch 는 업로드 진행률을 못 주므로 XMLHttpRequest 사용
export function uploadPcap(file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/analyze");
    xhr.responseType = "json";
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total);
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve(xhr.response);
      else reject(new Error(xhr.response?.detail || `업로드 실패 (${xhr.status})`));
    };
    xhr.onerror = () => reject(new Error("서버에 연결할 수 없어요. 백엔드가 켜져 있는지 확인하세요."));
    const form = new FormData();
    form.append("file", file);
    xhr.send(form);
  });
}

export async function getJob(jobId) {
  const res = await fetch(`/api/jobs/${jobId}`);
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || `상태 조회 실패 (${res.status})`);
  return data;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 업로드 -> 작업이 끝날 때까지 상태 폴링. onStatus({ phase, progress, stage, label, elapsed })
export async function analyzePcap(file, onStatus) {
  onStatus({ phase: "upload", progress: 0, stage: "upload", label: "업로드" });
  const { job_id } = await uploadPcap(file, (p) =>
    onStatus({ phase: "upload", progress: p, stage: "upload", label: "업로드" })
  );

  for (;;) {
    const job = await getJob(job_id);
    if (job.status === "done") return job.result;
    if (job.status === "error") throw new Error(job.error);
    onStatus({
      phase: "analyze",
      progress: job.progress,
      stage: job.stage ?? "queued",
      label: job.stage_label,
      elapsed: job.elapsed,
    });
    await sleep(700);
  }
}
