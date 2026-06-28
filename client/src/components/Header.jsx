export default function Header({ engineReady }) {
  let statusText, statusClass;
  if (engineReady === null) {
    statusText = "Checking engine…";
    statusClass = "status-unknown";
  } else if (engineReady) {
    statusText = "Engine ready";
    statusClass = "status-ready";
  } else {
    statusText = "Engine not built";
    statusClass = "status-error";
  }

  return (
    <header className="header">
      <div className="header-inner">
        <div className="brand">
          <div className="logo">DPI</div>
          <div>
            <h1>Packet Analyzer</h1>
            <p className="subtitle">Deep Packet Inspection — upload a PCAP, classify traffic, apply blocking rules</p>
          </div>
        </div>
        <span className={`status-badge ${statusClass}`}>{statusText}</span>
      </div>
    </header>
  );
}
