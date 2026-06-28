(() => {
  const dropZone = document.getElementById("drop-zone");
  const fileInput = document.getElementById("pcap-input");
  const browseBtn = document.getElementById("browse-btn");
  const selectedFile = document.getElementById("selected-file");
  const analyzeBtn = document.getElementById("analyze-btn");
  const sampleBtn = document.getElementById("sample-btn");
  const loading = document.getElementById("loading");
  const resultsSection = document.getElementById("results-section");
  const errorBanner = document.getElementById("error-banner");
  const engineStatus = document.getElementById("engine-status");

  let currentFile = null;

  function setLoading(on) {
    loading.classList.toggle("hidden", !on);
    analyzeBtn.disabled = on || !currentFile;
    sampleBtn.disabled = on;
  }

  function getRules() {
    const selectedApps = Array.from(
      document.querySelectorAll('#block-apps input[name="block-app"]:checked')
    ).map((el) => el.value);
    return {
      block_apps: selectedApps.join(","),
      block_ips: document.getElementById("block-ips").value.trim(),
      block_domains: document.getElementById("block-domains").value.trim(),
    };
  }

  function updateRulesSummary() {
    const rules = getRules();
    const parts = [];
    if (rules.block_apps) parts.push(`Apps: ${rules.block_apps.replace(/,/g, ", ")}`);
    if (rules.block_ips) parts.push(`IPs: ${rules.block_ips}`);
    if (rules.block_domains) parts.push(`Domains: ${rules.block_domains}`);

    const summary = document.getElementById("rules-summary");
    if (parts.length) {
      summary.textContent = `Will block — ${parts.join(" · ")}`;
      summary.classList.remove("hidden");
    } else {
      summary.textContent = "";
      summary.classList.add("hidden");
    }
  }

  function showError(msg) {
    errorBanner.textContent = msg;
    errorBanner.classList.remove("hidden");
  }

  function hideError() {
    errorBanner.classList.add("hidden");
  }

  function renderResults(data) {
    resultsSection.classList.remove("hidden");
    hideError();

    if (!data.success) {
      showError(data.error || "Analysis failed.");
      return;
    }

    document.getElementById("results-filename").textContent = data.input_filename || "";
    document.getElementById("stat-total").textContent = data.total_packets ?? "—";
    document.getElementById("stat-forwarded").textContent = data.forwarded ?? "—";
    document.getElementById("stat-dropped").textContent = data.dropped ?? "—";
    document.getElementById("stat-flows").textContent = data.active_flows ?? "—";

    const downloadBtn = document.getElementById("download-btn");
    if (data.job_id) {
      downloadBtn.href = `/api/download/${data.job_id}`;
      downloadBtn.classList.remove("hidden");
    } else {
      downloadBtn.classList.add("hidden");
    }

    const appChart = document.getElementById("app-chart");
    appChart.innerHTML = "";
    const apps = data.app_breakdown || [];
    if (apps.length === 0) {
      appChart.innerHTML = '<p class="empty-msg">No classified traffic</p>';
    } else {
      const maxCount = Math.max(...apps.map((a) => a.count), 1);
      for (const app of apps) {
        const row = document.createElement("div");
        row.className = "app-row";
        const pct = (app.count / maxCount) * 100;
        row.innerHTML = `
          <span class="app-name${app.blocked ? " blocked" : ""}">${escapeHtml(app.name)}</span>
          <div class="app-bar-bg"><div class="app-bar${app.blocked ? " blocked" : ""}" style="width:${pct}%"></div></div>
          <span class="app-count">${app.count}</span>
        `;
        appChart.appendChild(row);
      }
    }

    const domainList = document.getElementById("domain-list");
    domainList.innerHTML = "";
    const domains = data.domains || [];
    if (domains.length === 0) {
      domainList.innerHTML = '<p class="empty-msg">No domains detected</p>';
    } else {
      for (const d of domains) {
        const item = document.createElement("div");
        item.className = `domain-item${d.blocked ? " blocked" : ""}`;
        item.innerHTML = `
          <span class="domain-name">${escapeHtml(d.domain)}</span>
          <span class="domain-app">${escapeHtml(d.app)}</span>
        `;
        domainList.appendChild(item);
      }
    }

    const flowsBody = document.getElementById("flows-body");
    flowsBody.innerHTML = "";
    const flows = data.flows || [];
    for (const f of flows) {
      const tr = document.createElement("tr");
      if (f.blocked) tr.classList.add("blocked");
      tr.innerHTML = `
        <td>${escapeHtml(f.src_ip)}:${f.src_port}</td>
        <td>${escapeHtml(f.dst_ip)}:${f.dst_port}</td>
        <td>${escapeHtml(f.app)}</td>
        <td>${escapeHtml(f.sni || "—")}</td>
        <td>${f.packets}</td>
        <td><span class="badge ${f.blocked ? "badge-drop" : "badge-forward"}">${f.blocked ? "Blocked" : "Forwarded"}</span></td>
      `;
      flowsBody.appendChild(tr);
    }

    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  async function checkStatus() {
    try {
      const res = await fetch("/api/status");
      const data = await res.json();
      if (data.ready) {
        engineStatus.textContent = "Engine ready";
        engineStatus.className = "status-badge status-ready";
      } else {
        engineStatus.textContent = "Engine not built";
        engineStatus.className = "status-badge status-error";
      }
    } catch {
      engineStatus.textContent = "Server error";
      engineStatus.className = "status-badge status-error";
    }
  }

  async function analyzeWithFile(file) {
    setLoading(true);
    const rules = getRules();
    const form = new FormData();
    form.append("pcap", file);
    form.append("block_apps", rules.block_apps);
    form.append("block_ips", rules.block_ips);
    form.append("block_domains", rules.block_domains);

    try {
      const res = await fetch("/api/analyze", { method: "POST", body: form });
      const data = await res.json();
      if (!res.ok && !data.error) data.error = "Request failed.";
      renderResults(data);
    } catch (err) {
      showError(String(err));
      resultsSection.classList.remove("hidden");
    } finally {
      setLoading(false);
    }
  }

  async function analyzeSample() {
    setLoading(true);
    const rules = getRules();
    try {
      const res = await fetch("/api/sample", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(rules),
      });
      const data = await res.json();
      if (!res.ok && !data.error) data.error = "Request failed.";
      renderResults(data);
    } catch (err) {
      showError(String(err));
      resultsSection.classList.remove("hidden");
    } finally {
      setLoading(false);
    }
  }

  function setFile(file) {
    currentFile = file;
    selectedFile.textContent = file ? file.name : "";
    analyzeBtn.disabled = !file;
  }

  dropZone.addEventListener("click", () => fileInput.click());
  browseBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    fileInput.click();
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files.length) setFile(fileInput.files[0]);
  });

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("dragover");
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    const file = e.dataTransfer.files[0];
    if (file && (file.name.endsWith(".pcap") || file.name.endsWith(".pcapng"))) {
      setFile(file);
    }
  });

  analyzeBtn.addEventListener("click", () => {
    if (currentFile) analyzeWithFile(currentFile);
  });

  sampleBtn.addEventListener("click", analyzeSample);

  document.getElementById("block-apps").addEventListener("change", updateRulesSummary);
  document.getElementById("block-ips").addEventListener("input", updateRulesSummary);
  document.getElementById("block-domains").addEventListener("input", updateRulesSummary);

  checkStatus();
})();
