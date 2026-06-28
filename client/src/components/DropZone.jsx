import { useRef, useState } from "react";

export default function DropZone({ currentFile, onFileSelect }) {
  const inputRef = useRef(null);
  const [dragover, setDragover] = useState(false);

  function handleFile(file) {
    if (file && (file.name.endsWith(".pcap") || file.name.endsWith(".pcapng"))) {
      onFileSelect(file);
    }
  }

  function onDrop(e) {
    e.preventDefault();
    setDragover(false);
    handleFile(e.dataTransfer.files[0]);
  }

  return (
    <div
      id="drop-zone"
      className={`drop-zone${dragover ? " dragover" : ""}`}
      onClick={() => inputRef.current?.click()}
      onDragOver={(e) => { e.preventDefault(); setDragover(true); }}
      onDragLeave={() => setDragover(false)}
      onDrop={onDrop}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".pcap,.pcapng"
        hidden
        onChange={(e) => {
          if (e.target.files.length) handleFile(e.target.files[0]);
        }}
      />
      <div className="drop-icon">📦</div>
      <p className="drop-title">Drop a <strong>.pcap</strong> file here</p>
      <p className="drop-hint">
        or <button type="button" className="link-btn" onClick={(e) => { e.stopPropagation(); inputRef.current?.click(); }}>browse files</button>
      </p>
      <p id="selected-file" className="selected-file">
        {currentFile ? currentFile.name : ""}
      </p>
    </div>
  );
}
