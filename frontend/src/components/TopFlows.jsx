import { useState } from "react";

// 유형 -> 색 슬롯 (백엔드 flow_types 순서 고정, 순위와 무관하게 같은 유형은 같은 색)
const SLOTS = ["var(--c1)", "var(--c2)", "var(--c3)", "var(--c4)", "var(--c5)"];

function typeColor(type, types) {
  if (type === "기타") return "var(--c-other)";
  const i = types.indexOf(type);
  return i >= 0 && i < SLOTS.length ? SLOTS[i] : "var(--c-other)";
}

export default function TopFlows({ rows, types, threshold }) {
  const [hover, setHover] = useState(null);
  const [showTable, setShowTable] = useState(false);

  const scores = rows.map((r) => r.score);
  const lo = Math.min(...scores, threshold ?? Infinity) - 0.02;
  const hi = Math.max(...scores) + 0.01;
  const pos = (v) => `${((v - lo) / (hi - lo)) * 100}%`;
  const shownTypes = types.filter((t) => rows.some((r) => r.type === t));

  return (
    <figure className="card chart">
      <figcaption>
        <h2>점수 상위 {rows.length}개 플로우</h2>
        <p className="muted">점 위치 = 이상 점수, 색 = 플로우 유형</p>
      </figcaption>
      <div className="legend-row">
        <ul className="legend">
          {shownTypes.map((t) => (
            <li key={t}><span className="dot" style={{ background: typeColor(t, types) }} />{t}</li>
          ))}
        </ul>
        <button className="link" onClick={() => setShowTable((v) => !v)}>
          {showTable ? "차트로 보기" : "표로 보기"}
        </button>
      </div>

      {showTable ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>#</th><th>점수</th><th>플로우</th><th>유형</th><th>지속(s)</th><th>보낸/받은 패킷</th></tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i}>
                  <td>{i + 1}</td><td className="num">{r.score.toFixed(3)}</td><td className="mono">{r.flow}</td>
                  <td>{r.type}</td><td className="num">{r.duration}</td><td className="num">{r.fwd_pkts} / {r.bwd_pkts}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <ol className="dotplot">
          {rows.map((r, i) => (
            <li key={i} tabIndex={0}
              className={hover !== null && hover !== i ? "dim" : ""}
              onPointerEnter={() => setHover(i)} onPointerLeave={() => setHover(null)}
              onFocus={() => setHover(i)} onBlur={() => setHover(null)}>
              <span className="dp-label"><span className="rank">#{i + 1}</span><span className="mono">{r.flow}</span></span>
              <span className="dp-track">
                {threshold != null && <span className="dp-threshold" style={{ left: pos(threshold) }} />}
                <span className="dp-dot" style={{ left: pos(r.score), background: typeColor(r.type, types) }} />
                {hover === i && (
                  <span className="tooltip inline" style={{ left: pos(r.score) }}>
                    <span className="tt-title"><strong>{r.score.toFixed(3)}</strong> {r.type}</span>
                    <span className="tt-row">지속 {r.duration}s · 패킷 {r.fwd_pkts}/{r.bwd_pkts} · 받은 {r.bwd_bytes.toLocaleString()}B</span>
                  </span>
                )}
              </span>
            </li>
          ))}
        </ol>
      )}
    </figure>
  );
}
