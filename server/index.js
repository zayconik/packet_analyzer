import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import apiRouter from "./routes/api.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

app.use("/api", apiRouter);

if (process.env.NODE_ENV === "production") {
  app.use(express.static(path.resolve(ROOT, "client", "dist")));
  app.get("*", (_, res) => {
    res.sendFile(path.resolve(ROOT, "client", "dist", "index.html"));
  });
}

app.listen(PORT, () => {
  console.log("=".repeat(50));
  console.log("  DPI Packet Analyzer — API Server");
  console.log("=".repeat(50));
  console.log(`  Server: http://localhost:${PORT}`);
  console.log("=".repeat(50));
});
