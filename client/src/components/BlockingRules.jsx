import { useState, useEffect } from "react";

const SUPPORTED_APPS = [
  "Amazon", "Apple", "Cloudflare", "Discord", "DNS", "Facebook", "GitHub",
  "Google", "HTTP", "HTTPS", "Instagram", "Microsoft", "Netflix", "Spotify",
  "Telegram", "TikTok", "Twitter/X", "WhatsApp", "YouTube", "Zoom",
];

export default function BlockingRules({ rules, onRulesChange }) {
  const [apps, setApps] = useState(SUPPORTED_APPS);

  useEffect(() => {
    fetch("/api/apps")
      .then((r) => r.json())
      .then((d) => { if (d.apps?.length) setApps(d.apps); })
      .catch(() => {});
  }, []);

  function toggleApp(app) {
    const next = rules.block_apps.includes(app)
      ? rules.block_apps.filter((a) => a !== app)
      : [...rules.block_apps, app];
    onRulesChange({ block_apps: next });
  }

  const summaryParts = [];
  if (rules.block_apps.length) summaryParts.push(`Apps: ${rules.block_apps.join(", ")}`);
  if (rules.block_ips) summaryParts.push(`IPs: ${rules.block_ips}`);
  if (rules.block_domains) summaryParts.push(`Domains: ${rules.block_domains}`);

  return (
    <div className="rules-section">
      <div className="rules-heading">
        <h3>Blocking rules</h3>
        <p className="rules-note">
          Choose what to block, then click <strong>Analyze PCAP</strong> or <strong>Try sample</strong> below. Rules are applied during analysis — there is no separate submit step.
        </p>
      </div>
      <div className="rules-grid">
        <div className="field field-apps">
          <label>Block applications</label>
          <div id="block-apps" className="app-checkboxes">
            {apps.map((app) => (
              <label
                key={app}
                className={`app-check${rules.block_apps.includes(app) ? " checked" : ""}`}
              >
                <input
                  type="checkbox"
                  name="block-app"
                  value={app}
                  checked={rules.block_apps.includes(app)}
                  onChange={() => toggleApp(app)}
                />
                <span>{app}</span>
              </label>
            ))}
          </div>
          <span className="hint">Select apps to block — detected via SNI/TLS fingerprint</span>
        </div>
        <div className="field">
          <label htmlFor="block-ips">Block source IPs</label>
          <input
            type="text"
            id="block-ips"
            placeholder="192.168.1.50, 10.0.0.5"
            value={rules.block_ips}
            onChange={(e) => onRulesChange({ block_ips: e.target.value })}
            spellCheck={false}
          />
        </div>
        <div className="field">
          <label htmlFor="block-domains">Block domains</label>
          <input
            type="text"
            id="block-domains"
            placeholder="facebook, tiktok"
            value={rules.block_domains}
            onChange={(e) => onRulesChange({ block_domains: e.target.value })}
            spellCheck={false}
          />
          <span className="hint">Substring match on SNI / Host header</span>
        </div>
      </div>
      {summaryParts.length > 0 && (
        <p id="rules-summary" className="rules-summary">
          Will block — {summaryParts.join(" · ")}
        </p>
      )}
    </div>
  );
}
