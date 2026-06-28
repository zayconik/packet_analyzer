import express from "express";
import cors from "cors";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import apiRouter from "./routes/api.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

app.use("/api", apiRouter);

const clientDist = path.resolve(ROOT, "client", "dist");
if (process.env.NODE_ENV === "production" && fs.existsSync(clientDist)) {
  app.use(express.static(clientDist));
  app.get("*", (_, res) => {
    res.sendFile(path.join(clientDist, "index.html"));
  });
}

app.listen(PORT, () => {
  console.log("=".repeat(50));
  console.log("  DPI Packet Analyzer — API Server");
  console.log("=".repeat(50));
  console.log(`  Server: http://localhost:${PORT}`);
  console.log("=".repeat(50));
});
