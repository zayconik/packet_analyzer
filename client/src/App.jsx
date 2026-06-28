import { useState, useEffect, useCallback } from "react";
import Header from "./components/Header.jsx";
import DropZone from "./components/DropZone.jsx";
import BlockingRules from "./components/BlockingRules.jsx";
import Results from "./components/Results.jsx";
import Loading from "./components/Loading.jsx";
import { API_BASE } from "./config.js";

export default function App() {
  const [engineReady, setEngineReady] = useState(null);
  const [currentFile, setCurrentFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [rules, setRules] = useState({
    block_apps: [],
    block_ips: "",
    block_domains: "",
  });

  useEffect(() => {
    fetch(`${API_BASE}/status`)
      .then((r) => r.json())
      .then((d) => setEngineReady(d.ready))
      .catch(() => setEngineReady(false));
  }, []);

  const updateRules = useCallback((patch) => {
    setRules((prev) => ({ ...prev, ...patch }));
  }, []);

  async function analyze(url, body) {
    setLoading(true);
    setError(null);
    setResults(null);
    try {
      const res = await fetch(url, body);
      const data = await res.json();
      if (!res.ok && !data.error) data.error = "Request failed.";
      if (data.success) setResults(data);
      else setError(data.error || "Analysis failed.");
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  function handleAnalyze() {
    if (!currentFile) return;
    const form = new FormData();
    form.append("pcap", currentFile);
    form.append("block_apps", rules.block_apps.join(","));
    form.append("block_ips", rules.block_ips);
    form.append("block_domains", rules.block_domains);
    analyze(`${API_BASE}/analyze`, {
      method: "POST",
      body: form,
    });
  }

  function handleSample() {
    analyze(`${API_BASE}/sample`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        block_apps: rules.block_apps.join(","),
        block_ips: rules.block_ips,
        block_domains: rules.block_domains,
      }),
    });
  }

  return (
    <div className="app">
      <Header engineReady={engineReady} />
      <main className="main">
        <section className="panel upload-panel">
          <h2>Analyze Capture</h2>
          <DropZone
            currentFile={currentFile}
            onFileSelect={setCurrentFile}
          />
          <BlockingRules
            rules={rules}
            onRulesChange={updateRules}
          />
          <div className="actions">
            <button
              type="button"
              className="btn btn-primary"
              disabled={loading || !currentFile}
              onClick={handleAnalyze}
            >
              Analyze PCAP (apply rules)
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              disabled={loading}
              onClick={handleSample}
            >
              Try sample with rules
            </button>
          </div>
        </section>
        {error && (
          <section className="panel">
            <div className="error-banner">{error}</div>
          </section>
        )}
        {results && <Results data={results} />}
      </main>
      <Loading visible={loading} />
      <footer className="footer">
        <p>C++ DPI engine · TLS SNI & HTTP Host classification · Blocking by IP, app, or domain</p>
      </footer>
    </div>
  );
}
