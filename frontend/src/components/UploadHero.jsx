import { useRef, useState } from "react";

// 진행 단계 (백엔드 job.stage 와 매칭). 여러 백엔드 단계를 하나로 묶어서 보여줌
const STEPS = [
  { label: "업로드", stages: ["upload"] },
  { label: "패킷 파싱", stages: ["queued", "parse"] },
  { label: "플로우 집계", stages: ["flows"] },
  { label: "이상 탐지", stages: ["vectors", "detect", "save"] },
  { label: "원인 설명", stages: ["explain"] },
];

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

function Progress({ status }) {
  const active = STEPS.findIndex((s) => s.stages.includes(status.stage));
  const pct = Math.round(status.progress * 100);
  const title = status.phase === "upload" ? "파일 업로드 중" : status.stage === "queued" ? "대기 중" : status.label;
  return (
    <div className="progress" role="status" aria-live="polite">
      <div className="progress-head">
        <span><span className="spinner" aria-hidden="true" /> {title}</span>
        <span className="num">
          {pct}%{status.elapsed != null && <span className="muted"> · {status.elapsed.toFixed(0)}초</span>}
        </span>
      </div>
      <div className="progress-track"><div className="progress-fill" style={{ width: `${pct}%` }} /></div>
      <ol className="steps live">
        {STEPS.map((s, i) => (
          <li key={s.label} className={i < active ? "done" : i === active ? "active" : ""}>
            <span>{i < active ? "✓" : i + 1}</span>{s.label}
          </li>
        ))}
      </ol>
    </div>
  );
}

export default function UploadHero({ onAnalyze, status, error }) {
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef(null);
  const busy = status != null;

  function pick(f) {
    if (f && !busy) setFile(f);
  }

  function onDrop(e) {
    e.preventDefault();
    setDragging(false);
    pick(e.dataTransfer.files[0]);
  }

  function openPicker() {
    if (!busy) inputRef.current.click();
  }

  return (
    <section className="hero">
      <p className="eyebrow">PCAP · Isolation Forest</p>
      <h1>네트워크 이상 트래픽 탐지 서비스</h1>
      <p className="lead">
        pcap / pcapng 파일 속 플로우를 비지도 학습으로 점수화하고,
        이상 플로우마다 왜 이상한지 근거와 함께 설명합니다.
      </p>

      <div
        className={`dropzone${dragging ? " dragging" : ""}${file ? " has-file" : ""}${busy ? " busy" : ""}`}
        onDragOver={(e) => { e.preventDefault(); setDragging(!busy); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={openPicker}
        role="button"
        tabIndex={busy ? -1 : 0}
        aria-disabled={busy}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && openPicker()}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng"
          hidden
          onChange={(e) => pick(e.target.files[0])}
        />
        <svg className="drop-icon" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 16V4m0 0-4 4m4-4 4 4M4 16v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" />
        </svg>
        {file ? (
          <>
            <strong>{file.name}</strong>
            <span className="muted">{formatSize(file.size)}{!busy && " · 클릭해서 다른 파일 선택"}</span>
          </>
        ) : (
          <>
            <strong>파일을 끌어다 놓거나 클릭해서 선택</strong>
            <span className="muted">.pcap, .pcapng</span>
          </>
        )}
      </div>

      {busy ? (
        <Progress status={status} />
      ) : (
        <button className="primary" disabled={!file} onClick={() => onAnalyze(file)}>
          분석 시작
        </button>
      )}

      {error && <p className="error" role="alert">{error}</p>}

      {!busy && (
        <ol className="steps">
          {STEPS.map((s, i) => (
            <li key={s.label}><span>{i + 1}</span>{s.label}</li>
          ))}
        </ol>
      )}
    </section>
  );
}
