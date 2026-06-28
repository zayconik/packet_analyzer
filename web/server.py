#!/usr/bin/env python3
"""Web UI server for the DPI Packet Analyzer."""

import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = WEB_DIR / "uploads"
OUTPUT_DIR = WEB_DIR / "outputs"

API_BINARY_NAMES = ["dpi_api.exe", "dpi_api"]

SUPPORTED_APPS = [
    "Amazon", "Apple", "Cloudflare", "Discord", "DNS", "Facebook", "GitHub",
    "Google", "HTTP", "HTTPS", "Instagram", "Microsoft", "Netflix", "Spotify",
    "Telegram", "TikTok", "Twitter/X", "WhatsApp", "YouTube", "Zoom",
]


def parse_engine_json(stdout: str) -> dict:
    """Parse JSON from engine stdout (handles any stray log lines)."""
    start = stdout.find("{")
    if start < 0:
        raise json.JSONDecodeError("No JSON object in engine output", stdout, 0)
    return json.loads(stdout[start:])


def find_api_binary() -> Path | None:
    for name in API_BINARY_NAMES:
        candidate = ROOT / name
        if candidate.is_file():
            return candidate
    return None


def ensure_dirs() -> None:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MB


@app.route("/")
def index():
    return render_template("index.html", apps=SUPPORTED_APPS)


@app.route("/api/status")
def api_status():
    binary = find_api_binary()
    return jsonify({
        "ready": binary is not None,
        "binary": str(binary) if binary else None,
    })


@app.route("/api/apps")
def api_apps():
    binary = find_api_binary()
    if binary:
        try:
            result = subprocess.run(
                [str(binary), "--list-apps"],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=ROOT,
            )
            if result.returncode == 0 and result.stdout.strip():
                apps = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                return jsonify({"apps": apps})
        except (subprocess.SubprocessError, OSError):
            pass
    return jsonify({"apps": SUPPORTED_APPS})


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    binary = find_api_binary()
    if not binary:
        return jsonify({
            "success": False,
            "error": (
                "DPI API binary not found. Build it first:\n"
                "g++ -std=c++17 -O2 -I include -o dpi_api.exe "
                "src/main_json.cpp src/dpi_processor.cpp src/pcap_reader.cpp "
                "src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp"
            ),
        }), 503

    if "pcap" not in request.files:
        return jsonify({"success": False, "error": "No PCAP file uploaded."}), 400

    upload = request.files["pcap"]
    if not upload.filename:
        return jsonify({"success": False, "error": "Empty filename."}), 400

    if not upload.filename.lower().endswith((".pcap", ".pcapng")):
        return jsonify({
            "success": False,
            "error": "Please upload a .pcap file.",
        }), 400

    job_id = uuid.uuid4().hex[:12]
    input_path = UPLOAD_DIR / f"{job_id}_input.pcap"
    output_path = OUTPUT_DIR / f"{job_id}_output.pcap"

    upload.save(input_path)

    block_ips = request.form.get("block_ips", "").strip()
    block_apps = request.form.get("block_apps", "").strip()
    block_domains = request.form.get("block_domains", "").strip()

    cmd = [str(binary), str(input_path), str(output_path), "--json"]
    if block_ips:
        cmd.extend(["--block-ip", block_ips])
    if block_apps:
        cmd.extend(["--block-app", block_apps])
    if block_domains:
        cmd.extend(["--block-domain", block_domains])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=ROOT,
        )
    except subprocess.TimeoutExpired:
        input_path.unlink(missing_ok=True)
        return jsonify({"success": False, "error": "Processing timed out."}), 504
    except OSError as exc:
        input_path.unlink(missing_ok=True)
        return jsonify({"success": False, "error": str(exc)}), 500

    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip() or "Processing failed."
        input_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)
        return jsonify({"success": False, "error": error}), 500

    try:
        data = parse_engine_json(result.stdout)
    except json.JSONDecodeError:
        input_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)
        return jsonify({
            "success": False,
            "error": "Invalid JSON from DPI engine.",
        }), 500

    data["job_id"] = job_id
    data["input_filename"] = upload.filename
    return jsonify(data)


@app.route("/api/download/<job_id>")
def api_download(job_id: str):
    if not job_id.isalnum():
        return jsonify({"error": "Invalid job ID."}), 400

    output_path = OUTPUT_DIR / f"{job_id}_output.pcap"
    if not output_path.is_file():
        return jsonify({"error": "Output file not found or expired."}), 404

    return send_file(
        output_path,
        as_attachment=True,
        download_name=f"filtered_{job_id}.pcap",
        mimetype="application/octet-stream",
    )


@app.route("/api/sample", methods=["POST"])
def api_sample():
    """Analyze the bundled test_dpi.pcap without uploading."""
    sample = ROOT / "test_dpi.pcap"
    if not sample.is_file():
        return jsonify({"success": False, "error": "test_dpi.pcap not found."}), 404

    binary = find_api_binary()
    if not binary:
        return jsonify({"success": False, "error": "DPI API binary not built."}), 503

    job_id = uuid.uuid4().hex[:12]
    input_path = UPLOAD_DIR / f"{job_id}_input.pcap"
    output_path = OUTPUT_DIR / f"{job_id}_output.pcap"
    shutil.copy(sample, input_path)

    block_apps = request.json.get("block_apps", "") if request.is_json else ""
    block_ips = request.json.get("block_ips", "") if request.is_json else ""
    block_domains = request.json.get("block_domains", "") if request.is_json else ""

    cmd = [str(binary), str(input_path), str(output_path), "--json"]
    if block_ips:
        cmd.extend(["--block-ip", block_ips])
    if block_apps:
        cmd.extend(["--block-app", block_apps])
    if block_domains:
        cmd.extend(["--block-domain", block_domains])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd=ROOT)
    if result.returncode != 0:
        input_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)
        return jsonify({"success": False, "error": result.stderr or "Failed."}), 500

    data = parse_engine_json(result.stdout)
    data["job_id"] = job_id
    data["input_filename"] = "test_dpi.pcap"
    return jsonify(data)


def main() -> None:
    ensure_dirs()
    binary = find_api_binary()

    print("=" * 50)
    print("  DPI Packet Analyzer - Web UI")
    print("=" * 50)
    if binary:
        print(f"  Engine: {binary.name} [OK]")
    else:
        print("  Engine: NOT FOUND — build dpi_api.exe first")
        print("  Run: python web/build_api.py")
    print(f"  Open: http://127.0.0.1:5000")
    print("=" * 50)

    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
