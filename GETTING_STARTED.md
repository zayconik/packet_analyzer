# DPI Packet Analyzer — Getting Started Guide

> **What is this?**  
> A Deep Packet Inspection (DPI) engine that reads `.pcap` network capture files, identifies applications (YouTube, Facebook, Zoom, etc.) via TLS/SNI analysis, optionally blocks traffic by IP/app/domain, and writes a filtered output `.pcap`.  
> Comes with both a **CLI engine** (C++) and a **MERN web dashboard** (React + Express + C++ backend).

---

## Table of Contents

- [Project Structure](#project-structure)
- [Windows Setup (C++ Engine)](#windows-setup-c-engine)
- [macOS Setup (C++ Engine)](#macos-setup-c-engine)
- [Running the CLI Engine](#running-the-cli-engine)
- [Web Dashboard (MERN Stack)](#web-dashboard-mern-stack)
- [Generating a Test PCAP](#generating-a-test-pcap)
- [Deploying to Production](#deploying-to-production)
- [All CLI Options](#all-cli-options)
- [Troubleshooting](#troubleshooting)

---

## Project Structure

```
Packet_analyzer/
├── server/              # Express API (replaces Flask)
│   ├── index.js         # Server entry point
│   ├── routes/api.js    # API endpoints
│   ├── uploads/         # Uploaded PCAP files
│   ├── outputs/         # Filtered output PCAPs
│   └── package.json
├── client/              # React frontend (Vite)
│   ├── src/
│   │   ├── App.jsx      # Main app component
│   │   ├── components/  # DropZone, BlockingRules, Results
│   │   └── ...
│   └── package.json
├── src/                 # C++ DPI engine source
├── include/             # C++ headers
├── dpi_api.exe          # Compiled API binary (used by Express)
├── test_dpi.pcap        # Sample capture for testing
└── package.json         # Root scripts
```

---

## Windows Setup (C++ Engine)

### Step 1 — Install GCC

You need a C++17-capable GCC compiler. Check if you already have one:

```powershell
gcc --version
```

If that prints a version number (e.g. `gcc 16.1.0`), skip to **Step 2**.

If not, download **WinLibs**:

1. Go to https://winlibs.com/
2. Download the latest **GCC + LLVM/Clang** release for **Win64 (UCRT)** as a `.zip`
3. Extract it to `C:\gcc`
4. Add `C:\gcc\bin` to your system PATH:
   - Press `Win + R` → `sysdm.cpl` → **Advanced** → **Environment Variables**
   - Under **System variables**, find `Path` → **Edit** → **New** → paste `C:\gcc\bin`
5. Open a **new** PowerShell and confirm: `gcc --version`

---

### Step 2 — Build the API Binary (used by the web dashboard)

```powershell
g++ -std=c++17 -O2 -I include -static-libgcc -static-libstdc++ -static `
    -o dpi_api.exe `
    src/main_json.cpp src/dpi_processor.cpp src/pcap_reader.cpp `
    src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

> **Why `-static-*` flags?**  
> Without them the `.exe` depends on `libstdc++-6-x64.dll` which Windows can't find at runtime. Static linking bundles the runtime into the `.exe`.

---

### Step 3 — Build the Multi-Threaded CLI Engine (optional)

```powershell
g++ -std=c++17 -O2 -I include -static-libgcc -static-libstdc++ -static `
    -o dpi_engine.exe `
    src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp `
    src/sni_extractor.cpp src/types.cpp
```

---

### Step 4 — Enable UTF-8 in Your Terminal

The CLI engine uses box-drawing characters. Run this once per session before using it:

```powershell
chcp 65001
```

---

## macOS Setup (C++ Engine)

### Step 1 — Install the C++ Compiler

```bash
xcode-select --install
```

Confirm with:

```bash
clang++ --version
```

### Step 2 — Build the API Binary

```bash
g++ -std=c++17 -O2 -I include \
    -o dpi_api \
    src/main_json.cpp src/dpi_processor.cpp src/pcap_reader.cpp \
    src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

### Step 3 — Build the CLI Engine (optional)

```bash
g++ -std=c++17 -O2 -I include \
    -o dpi_engine \
    src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp \
    src/sni_extractor.cpp src/types.cpp
chmod +x dpi_engine
```

---

## Running the CLI Engine

The project includes `test_dpi.pcap` — a sample capture with TLS/HTTP/DNS traffic.

### Windows

```powershell
chcp 65001
.\dpi_engine.exe test_dpi.pcap output.pcap
```

### macOS

```bash
./dpi_engine test_dpi.pcap output.pcap
```

---

## Web Dashboard (MERN Stack)

A browser-based dashboard for uploading PCAPs, configuring blocking rules, and viewing results visually.

### Prerequisites

- **Node.js** v18+ (download from https://nodejs.org)
- **C++ binary** — build `dpi_api.exe` (Windows) or `dpi_api` (macOS/Linux) — see [Windows Setup](#windows-setup-c-engine) or [macOS Setup](#macos-setup-c-engine)

### Quick Start

```bash
# 1. Install dependencies for both server and client
npm run install:all

# 2. Start the Express API server (Terminal 1)
npm start

# 3. Start the React dev server with hot reload (Terminal 2)
cd client && npm run dev
```

Then open **http://localhost:5173** in your browser (Vite dev server proxies API calls to Express on port 5000).

### Production Build

```bash
# Build the React app
cd client && npm run build

# Start the server in production mode (serves built React files)
NODE_ENV=production node server/index.js
```

Open **http://localhost:5000** to see the dashboard.

### Features

- Drag-and-drop PCAP upload
- Block by application (YouTube, Facebook, TikTok, etc.)
- Block by source IP or domain substring
- Live stats: forwarded vs dropped packets, app breakdown, detected domains
- Download the filtered output PCAP
- **Try sample** button to analyze `test_dpi.pcap` instantly

---

## Generating a Test PCAP

A Python script is included to regenerate `test_dpi.pcap` with synthetic TLS Client Hello packets:

```bash
python generate_test_pcap.py
```

No extra libraries required (uses only the Python standard library).

---

## Deploying to Production

The project is deployed as two separate services:

### 1. Backend — Render (Web Service)

The Express API server + C++ DPI engine runs on **Render** using Docker.

**Setup:**
1. Push the repo to GitHub (or GitLab/Bitbucket).
2. On [Render Dashboard](https://dashboard.render.com), create a **New Web Service**.
3. Connect your repository.
4. Render auto-detects the `Dockerfile`. Use these settings:
   - **Name:** `packet-analyzer-api`
   - **Runtime:** Docker
   - **Branch:** `main` (or your deployment branch)
   - **Health Check Path:** `/api/status`
   - **Auto-Deploy:** Yes
5. No environment variables are required (defaults to `NODE_ENV=production`, port `5000`).
6. Deploy. Once live, note the URL (e.g. `https://packet-analyzer-api.onrender.com`).

The `Dockerfile` handles everything: it installs CMake, builds the C++ `dpi_api` binary, installs Node dependencies, and starts the Express server.

### 2. Frontend — Netlify

The React + Vite client is deployed on **Netlify**.

**Setup:**
1. On [Netlify](https://app.netlify.com), add a **New site** → **Import an existing project**.
2. Connect your repository.
3. Use these settings (matches `netlify.toml`):
   - **Build command:** `cd client && npm ci && npm run build`
   - **Publish directory:** `client/dist`
4. Add environment variable:
   - **Key:** `VITE_API_URL`
   - **Value:** Your Render backend URL (e.g. `https://packet-analyzer-api.onrender.com/api`)
5. Deploy. Netlify will build the client and serve it, with SPA redirects handled by the `netlify.toml`.

> **Note:** The `VITE_API_URL` variable must be set at build time so the client knows where to send API requests. In development it defaults to `/api` (proxied by Vite to `localhost:5000`).

---

## All CLI Options

```
dpi_engine <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Drop all packets from this source IP
  --block-app <app>      Drop all packets classified as this app
  --block-domain <dom>   Drop packets whose SNI contains this string
  --json                 Output JSON report to stdout (used by web API)
  --lbs <n>              Number of load balancer threads  (default: 2)
  --fps <n>              Fast-path threads per LB thread  (default: 2)
```

**Supported app names** for `--block-app`:  
`YouTube`, `Facebook`, `Instagram`, `Twitter/X`, `TikTok`, `Zoom`, `Discord`,  
`Telegram`, `Spotify`, `Netflix`, `Google`, `Amazon`, `GitHub`, `Cloudflare`,  
`Apple`, `Microsoft`, `WhatsApp`, `HTTP`, `HTTPS`, `DNS`

### Examples

```bash
# Block YouTube and TikTok
./dpi_engine capture.pcap filtered.pcap --block-app YouTube --block-app TikTok

# Block a specific IP
./dpi_engine capture.pcap filtered.pcap --block-ip 192.168.1.50

# Block any SNI containing "facebook"
./dpi_engine capture.pcap filtered.pcap --block-domain facebook

# Combine rules
./dpi_engine capture.pcap filtered.pcap \
    --block-app YouTube \
    --block-ip 10.0.0.5 \
    --block-domain tiktok

# JSON output (used by the web dashboard API)
./dpi_api test_dpi.pcap output.pcap --json --block-app YouTube
```

---

## Troubleshooting

### Windows: Program crashes instantly with no output
- **Cause:** Missing runtime DLL (`libstdc++-6-x64.dll`)
- **Fix:** Use the static-linking compile flags (`-static-libgcc -static-libstdc++ -static`)

### Windows: Output is garbled / box characters look like `Ôòö`
- **Cause:** PowerShell is using the wrong encoding
- **Fix:** Run `chcp 65001` before using the CLI engine

### macOS: `g++: command not found`
- **Fix:** Run `xcode-select --install` and try again

### Web UI: "Engine not built"
- **Cause:** `dpi_api.exe` or `dpi_api` binary is missing
- **Fix:** Build it using the C++ compile command above

### Web UI: API calls fail with 404
- **Cause:** The React dev server is not proxying to Express
- **Fix:** Make sure Express is running on port 5000, and Vite's `vite.config.js` has the proxy configured

### `Error: Could not open file: test_dpi.pcap`
- **Cause:** Running from the wrong directory
- **Fix:** Your terminal should be inside the `Packet_analyzer` folder
