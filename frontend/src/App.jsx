import { useState } from "react";
import { analyzePcap } from "./api.js";
import UploadHero from "./components/UploadHero.jsx";
import StatTiles from "./components/StatTiles.jsx";
import ScoreHistogram from "./components/ScoreHistogram.jsx";
import TopFlows from "./components/TopFlows.jsx";
import AnomalyList from "./components/AnomalyList.jsx";

export default function App() {
  const [status, setStatus] = useState(null); // 진행 중일 때만 값 있음
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  async function run(file) {
    setError("");
    setStatus({ phase: "upload", progress: 0, stage: "upload", label: "업로드" });
    try {
      setResult(await analyzePcap(file, setStatus));
    } catch (err) {
      setError(err.message);
    } finally {
      setStatus(null);
    }
  }

  return (
    <div className="page">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          패킷 이상 탐지
        </div>
        {result && (
          <button className="ghost" onClick={() => setResult(null)}>
            새 파일 분석
          </button>
        )}
      </header>

      <main>
        {!result && <UploadHero onAnalyze={run} status={status} error={error} />}

        {result && (
          <div className="results">
            <div className="results-head">
              <h1>{result.filename}</h1>
              <span className="muted">run {result.run_id}</span>
            </div>
            <StatTiles stats={result.stats} excluded={result.excluded_flows} />
            <div className="chart-grid">
              <ScoreHistogram bins={result.histogram} threshold={result.stats.threshold} />
              <TopFlows rows={result.top} types={result.flow_types} threshold={result.stats.threshold} />
            </div>
            <AnomalyList items={result.anomalies} />
          </div>
        )}
      </main>
    </div>
  );
}
