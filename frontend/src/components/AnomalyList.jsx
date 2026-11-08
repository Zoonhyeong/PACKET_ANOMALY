import { useEffect, useState } from "react";

const RISK = {
  높음: { cls: "critical", icon: "▲" },
  중간: { cls: "warning", icon: "●" },
  낮음: { cls: "good", icon: "▼" },
};

// 이상 플로우를 한 번에 하나씩 보여줌 (이전/다음 버튼, 드롭다운, 키보드 ← →)
export default function AnomalyList({ items }) {
  const [idx, setIdx] = useState(0);
  const last = items.length - 1;
  const go = (i) => setIdx(Math.min(Math.max(i, 0), last));

  useEffect(() => setIdx(0), [items]);

  useEffect(() => {
    function onKey(e) {
      if (["INPUT", "SELECT", "TEXTAREA"].includes(e.target.tagName)) return;
      if (e.key === "ArrowLeft") go(idx - 1);
      if (e.key === "ArrowRight") go(idx + 1);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  return (
    <section className="anomalies">
      <div className="anomalies-head">
        <h2>이상 플로우 상세 <span className="count">{items.length}</span></h2>
        {items.length > 0 && (
          <div className="pager">
            <button className="ghost" onClick={() => go(idx - 1)} disabled={idx === 0} aria-label="이전 이상 플로우">
              ‹ 이전
            </button>
            <select value={idx} onChange={(e) => go(Number(e.target.value))} aria-label="이상 플로우 선택">
              {items.map((a, i) => (
                <option key={a.rank} value={i}>
                  #{a.rank} · {a.reason.risk_level} · {a.flow.src} → {a.flow.dst}:{a.flow.dport}
                </option>
              ))}
            </select>
            <span className="num muted">{idx + 1} / {items.length}</span>
            <button className="ghost" onClick={() => go(idx + 1)} disabled={idx === last} aria-label="다음 이상 플로우">
              다음 ›
            </button>
          </div>
        )}
      </div>
      {items.length === 0 && <p className="muted">이상으로 판정된 플로우가 없어요.</p>}

      {items.slice(idx, idx + 1).map((a) => {
        const r = a.reason;
        const risk = RISK[r.risk_level] ?? RISK["낮음"];
        return (
          <article key={a.rank} className="card anomaly">
            <header>
              <span className="rank">#{a.rank}</span>
              <span className={`badge ${risk.cls}`}>
                <span aria-hidden="true">{risk.icon}</span> 위험 {r.risk_level} · {r.risk}점
              </span>
              <span className="verdict">{r.verdict}</span>
              <span className="score">score {a.score.toFixed(3)}</span>
            </header>

            <div className="flow mono">{a.flow.summary}</div>
            <div className="tags">
              {r.suspected.map((s) => <span key={s} className="tag">{s}</span>)}
              {(r.attack ?? []).map((t) => (
                <a key={t.id} className="tag attack" href={t.url} target="_blank" rel="noreferrer"
                   title={`${t.tactic} · ${t.name}`}>
                  ATT&CK {t.id} · {t.name}
                </a>
              ))}
            </div>

            <p className="explanation">{r.explanation}</p>

            {r.evidence.length > 0 && (
              <ul className="evidence">
                {r.evidence.map((e, i) => <li key={i}>{e}</li>)}
              </ul>
            )}

            {r.model_reasons.length > 0 && (
              <div className="model">
                <div className="model-title">모델이 본 원인</div>
                <ul>
                  {r.model_reasons.map((m) => (
                    <li key={m.feature}>
                      <span>{m.description}</span>
                      <span className="num muted">−{m.contribution.toFixed(3)}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <dl className="flow-meta">
              <div><dt>프로토콜</dt><dd>{a.flow.protocol}</dd></div>
              <div><dt>지속</dt><dd>{a.flow.duration.toFixed(1)}s</dd></div>
              <div><dt>보낸</dt><dd>{a.flow.fwd_pkts}개 · {a.flow.fwd_bytes.toLocaleString()}B</dd></div>
              <div><dt>받은</dt><dd>{a.flow.bwd_pkts}개 · {a.flow.bwd_bytes.toLocaleString()}B</dd></div>
            </dl>
          </article>
        );
      })}

    </section>
  );
}
