export default function StatTiles({ stats, excluded }) {
  const rate = stats.total_flows ? (stats.anomalies / stats.total_flows) * 100 : 0;
  const tiles = [
    { label: "분석 플로우", value: stats.total_flows.toLocaleString() },
    { label: "이상 플로우", value: stats.anomalies.toLocaleString(), sub: `전체의 ${rate.toFixed(1)}%` },
    { label: "제외 플로우", value: excluded.toLocaleString(), sub: "멀티캐스트·브로드캐스트" },
    {
      label: "이상 판정 기준 점수",
      value: stats.threshold == null ? "-" : stats.threshold.toFixed(3),
      sub: `중앙값 ${stats.median_score.toFixed(3)}`,
    },
  ];
  return (
    <div className="tiles">
      {tiles.map((t) => (
        <div className="tile" key={t.label}>
          <div className="tile-label">{t.label}</div>
          <div className="tile-value">{t.value}</div>
          {t.sub && <div className="tile-sub">{t.sub}</div>}
        </div>
      ))}
    </div>
  );
}
