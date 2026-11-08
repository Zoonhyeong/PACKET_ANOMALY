import { useState } from "react";
import useWidth from "./useWidth.js";

const H = 240;
const M = { top: 16, right: 12, bottom: 32, left: 36 };
const GAP = 2;

// 위쪽 모서리만 4px 둥근 막대 (바닥은 직각)
function topRounded(x, y, w, h, r = 4) {
  r = Math.min(r, w / 2, h);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

// 눈금 3개(0, 절반, 최대)가 모두 정수가 되도록 짝수로 올림
function niceMax(v) {
  if (v <= 4) return 4;
  const p = 10 ** Math.floor(Math.log10(v));
  const m = Math.ceil(v / p) * p;
  return m % 2 ? m + p : m;
}

export default function ScoreHistogram({ bins, threshold }) {
  const [ref, width] = useWidth();
  const [hover, setHover] = useState(null);

  const iw = Math.max(width - M.left - M.right, 100);
  const ih = H - M.top - M.bottom;
  const x0 = bins[0].x0;
  const x1 = bins[bins.length - 1].x1;
  const sx = (v) => M.left + ((v - x0) / (x1 - x0)) * iw;
  const yMax = niceMax(Math.max(...bins.map((b) => b.normal + b.anomaly)));
  const sy = (v) => M.top + ih - (v / yMax) * ih;
  const ticks = [0, yMax / 2, yMax];
  const xTicks = [x0, (x0 + x1) / 2, x1];

  return (
    <figure className="card chart">
      <figcaption>
        <h2>이상 점수 분포</h2>
        <p className="muted">점수가 높을수록 이상. 빨간 선 오른쪽이 이상 판정</p>
      </figcaption>
      <ul className="legend">
        <li><span className="swatch" style={{ background: "var(--normal)" }} />정상 판정</li>
        <li><span className="swatch" style={{ background: "var(--anomaly)" }} />이상 판정</li>
      </ul>

      <div className="chart-box" ref={ref}>
        <svg width={width} height={H} role="img" aria-label="이상 점수 히스토그램">
          {ticks.map((t) => (
            <g key={t}>
              <line className="grid" x1={M.left} x2={M.left + iw} y1={sy(t)} y2={sy(t)} />
              <text className="tick" x={M.left - 6} y={sy(t)} dy="0.32em" textAnchor="end">{t}</text>
            </g>
          ))}
          {xTicks.map((t, i) => (
            <text key={i} className="tick" x={sx(t)} y={H - 10}
              textAnchor={i === 0 ? "start" : i === 2 ? "end" : "middle"}>{t.toFixed(2)}</text>
          ))}

          {bins.map((b, i) => {
            const x = sx(b.x0) + GAP / 2;
            const w = Math.max(sx(b.x1) - sx(b.x0) - GAP, 1);
            const hn = sy(0) - sy(b.normal);
            const ha = sy(0) - sy(b.anomaly);
            const total = b.normal + b.anomaly;
            const dim = hover !== null && hover !== i;
            return (
              <g key={i} opacity={dim ? 0.45 : 1}>
                {b.normal > 0 && (
                  <path fill="var(--normal)"
                    d={b.anomaly > 0 ? `M${x},${sy(0)}h${w}v${-hn}h${-w}Z` : topRounded(x, sy(0) - hn, w, hn)} />
                )}
                {b.anomaly > 0 && (
                  <path fill="var(--anomaly)"
                    d={topRounded(x, sy(0) - hn - ha - (b.normal > 0 ? GAP : 0), w, ha)} />
                )}
                {/* 막대보다 넓은 히트 영역 */}
                <rect x={sx(b.x0)} y={M.top} width={sx(b.x1) - sx(b.x0)} height={ih} fill="transparent"
                  tabIndex={total ? 0 : -1}
                  onPointerEnter={() => setHover(i)} onPointerLeave={() => setHover(null)}
                  onFocus={() => setHover(i)} onBlur={() => setHover(null)} />
              </g>
            );
          })}

          <line className="baseline" x1={M.left} x2={M.left + iw} y1={sy(0)} y2={sy(0)} />
          {threshold != null && (
            <g pointerEvents="none">
              <line className="threshold" x1={sx(threshold)} x2={sx(threshold)} y1={M.top} y2={sy(0)} />
              <text className="threshold-label" x={sx(threshold) - 6} y={M.top + 4} dy="0.7em" textAnchor="end">
                기준 {threshold.toFixed(3)}
              </text>
            </g>
          )}
        </svg>

        {hover !== null && (
          <div className="tooltip"
            style={{ left: Math.min(Math.max(sx((bins[hover].x0 + bins[hover].x1) / 2), 80), width - 80), top: 8 }}>
            <div className="tt-title">{bins[hover].x0.toFixed(3)} – {bins[hover].x1.toFixed(3)}</div>
            <div className="tt-row"><span className="key" style={{ background: "var(--normal)" }} />
              <strong>{bins[hover].normal}</strong> 정상</div>
            <div className="tt-row"><span className="key" style={{ background: "var(--anomaly)" }} />
              <strong>{bins[hover].anomaly}</strong> 이상</div>
          </div>
        )}
      </div>
    </figure>
  );
}
