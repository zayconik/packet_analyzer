function esc(str) {
  if (str == null) return "";
  const div = document.createElement("div");
  div.textContent = String(str);
  return div.innerHTML;
}

import { API_BASE } from "../config.js";

export default function Results({ data }) {
  const apps = data.app_breakdown || [];
  const domains = data.domains || [];
  const flows = data.flows || [];
  const maxCount = Math.max(...apps.map((a) => a.count), 1);

  return (
    <section className="panel results-panel">
      <div className="results-header">
        <h2>Results</h2>
        <div className="results-actions">
          <span className="filename">{data.input_filename || ""}</span>
          {data.job_id && (
            <a className="btn btn-secondary" href={`${API_BASE}/download/${data.job_id}`} download>
              Download filtered PCAP
            </a>
          )}
        </div>
      </div>
      <div className="stats-grid">
        <div className="stat-card">
          <span className="stat-label">Total packets</span>
          <span className="stat-value">{data.total_packets ?? "—"}</span>
        </div>
        <div className="stat-card stat-forward">
          <span className="stat-label">Forwarded</span>
          <span className="stat-value">{data.forwarded ?? "—"}</span>
        </div>
        <div className="stat-card stat-drop">
          <span className="stat-label">Dropped</span>
          <span className="stat-value">{data.dropped ?? "—"}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Active flows</span>
          <span className="stat-value">{data.active_flows ?? "—"}</span>
        </div>
      </div>
      <div className="results-columns">
        <div className="results-col">
          <h3>Application breakdown</h3>
          <div className="app-chart">
            {apps.length === 0 ? (
              <p className="empty-msg">No classified traffic</p>
            ) : (
              apps.map((app) => {
                const pct = (app.count / maxCount) * 100;
                return (
                  <div key={app.name} className="app-row">
                    <span className={`app-name${app.blocked ? " blocked" : ""}`}>
                      {esc(app.name)}
                    </span>
                    <div className="app-bar-bg">
                      <div className={`app-bar${app.blocked ? " blocked" : ""}`} style={{ width: `${pct}%` }} />
                    </div>
                    <span className="app-count">{app.count}</span>
                  </div>
                );
              })
            )}
          </div>
        </div>
        <div className="results-col">
          <h3>Detected domains</h3>
          <div className="domain-list">
            {domains.length === 0 ? (
              <p className="empty-msg">No domains detected</p>
            ) : (
              domains.map((d) => (
                <div key={d.domain} className={`domain-item${d.blocked ? " blocked" : ""}`}>
                  <span className="domain-name">{esc(d.domain)}</span>
                  <span className="domain-app">{esc(d.app)}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
      <div className="flows-section">
        <h3>Connection flows</h3>
        <div className="table-wrap">
          <table className="flows-table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Destination</th>
                <th>App</th>
                <th>Domain</th>
                <th>Pkts</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {flows.map((f, i) => (
                <tr key={i} className={f.blocked ? "blocked" : ""}>
                  <td>{esc(f.src_ip)}:{f.src_port}</td>
                  <td>{esc(f.dst_ip)}:{f.dst_port}</td>
                  <td>{esc(f.app)}</td>
                  <td>{esc(f.sni || "—")}</td>
                  <td>{f.packets}</td>
                  <td>
                    <span className={`badge ${f.blocked ? "badge-drop" : "badge-forward"}`}>
                      {f.blocked ? "Blocked" : "Forwarded"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
