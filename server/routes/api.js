import { Router } from "express";
import multer from "multer";
import { execFile } from "child_process";
import { v4 as uuidv4 } from "uuid";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..");
const UPLOAD_DIR = path.resolve(__dirname, "..", "uploads");
const OUTPUT_DIR = path.resolve(__dirname, "..", "outputs");

fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: 64 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    const ok = file.originalname.toLowerCase().endsWith(".pcap") ||
               file.originalname.toLowerCase().endsWith(".pcapng");
    cb(null, ok);
  },
});

const SUPPORTED_APPS = [
  "Amazon", "Apple", "Cloudflare", "Discord", "DNS", "Facebook", "GitHub",
  "Google", "HTTP", "HTTPS", "Instagram", "Microsoft", "Netflix", "Spotify",
  "Telegram", "TikTok", "Twitter/X", "WhatsApp", "YouTube", "Zoom",
];

const BINARY_NAMES = process.platform === "win32"
  ? ["dpi_api.exe", "dpi_api"]
  : ["dpi_api", "dpi_api.exe"];

function findBinary() {
  for (const name of BINARY_NAMES) {
    const candidate = path.join(ROOT, name);
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

function findSample() {
  const candidate = path.join(ROOT, "test_dpi.pcap");
  return fs.existsSync(candidate) ? candidate : null;
}

function parseEngineJSON(stdout) {
  const start = stdout.indexOf("{");
  if (start < 0) throw new Error("No JSON in engine output");
  return JSON.parse(stdout.slice(start));
}

function runEngine(inputPath, outputPath, rules) {
  return new Promise((resolve, reject) => {
    const binary = findBinary();
    if (!binary) return reject(new Error("DPI binary not found"));

    const cmd = [inputPath, outputPath, "--json"];
    if (rules.block_apps) cmd.push("--block-app", rules.block_apps);
    if (rules.block_ips) cmd.push("--block-ip", rules.block_ips);
    if (rules.block_domains) cmd.push("--block-domain", rules.block_domains);

    execFile(binary, cmd, { cwd: ROOT, timeout: 120000 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr || stdout || err.message));
      try {
        resolve(parseEngineJSON(stdout));
      } catch (e) {
        reject(new Error("Invalid JSON from engine"));
      }
    });
  });
}

const router = Router();

router.get("/status", (_, res) => {
  const binary = findBinary();
  res.json({ ready: binary !== null, binary });
});

router.get("/apps", (_, res) => {
  res.json({ apps: SUPPORTED_APPS });
});

router.post("/analyze", upload.single("pcap"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: "No PCAP file uploaded" });

    const jobId = uuidv4().slice(0, 12);
    const inputPath = path.join(UPLOAD_DIR, `${jobId}_input.pcap`);
    const outputPath = path.join(OUTPUT_DIR, `${jobId}_output.pcap`);

    fs.renameSync(req.file.path, inputPath);

    const rules = {
      block_apps: (req.body.block_apps || "").trim(),
      block_ips: (req.body.block_ips || "").trim(),
      block_domains: (req.body.block_domains || "").trim(),
    };

    const data = await runEngine(inputPath, outputPath, rules);
    data.job_id = jobId;
    data.input_filename = req.file.originalname;
    res.json(data);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.post("/sample", async (req, res) => {
  try {
    const sample = findSample();
    if (!sample) return res.status(404).json({ success: false, error: "test_dpi.pcap not found" });

    const jobId = uuidv4().slice(0, 12);
    const inputPath = path.join(UPLOAD_DIR, `${jobId}_input.pcap`);
    const outputPath = path.join(OUTPUT_DIR, `${jobId}_output.pcap`);

    fs.copyFileSync(sample, inputPath);

    const rules = {
      block_apps: (req.body.block_apps || "").trim(),
      block_ips: (req.body.block_ips || "").trim(),
      block_domains: (req.body.block_domains || "").trim(),
    };

    const data = await runEngine(inputPath, outputPath, rules);
    data.job_id = jobId;
    data.input_filename = "test_dpi.pcap";
    res.json(data);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.get("/download/:jobId", (req, res) => {
  const { jobId } = req.params;
  if (!/^[a-f0-9]+$/i.test(jobId)) return res.status(400).json({ error: "Invalid job ID" });

  const filePath = path.join(OUTPUT_DIR, `${jobId}_output.pcap`);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "File not found" });

  res.download(filePath, `filtered_${jobId}.pcap`);
});

export default router;
