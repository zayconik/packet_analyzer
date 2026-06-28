# DPI Engine — Getting Started Guide

> **What is this?**  
> A multi-threaded Deep Packet Inspection (DPI) engine that reads `.pcap` network capture files, identifies applications (YouTube, Facebook, Zoom, etc.) via TLS/SNI analysis, optionally blocks traffic by IP/app/domain, and writes a filtered output `.pcap`.

---

## Table of Contents

- [Windows Setup](#windows-setup)
- [macOS Setup](#macos-setup)
- [Running the Engine](#running-the-engine)
- [Generating a Test PCAP](#generating-a-test-pcap)
- [Understanding the Output](#understanding-the-output)
- [All CLI Options](#all-cli-options)
- [Troubleshooting](#troubleshooting)

---

## Windows Setup

### Step 1 — Install GCC (if not already installed)

You need a C++17-capable GCC compiler. Check if you already have one:

```powershell
gcc --version
```

If that prints a version number (e.g. `gcc 16.1.0`), skip to **Step 2**.

If not, download **WinLibs** (a standalone GCC for Windows, no install needed):

1. Go to → https://winlibs.com/
2. Download the latest **GCC + LLVM/Clang** release for **Win64 (UCRT)** as a `.zip`
3. Extract it somewhere simple, e.g. `C:\gcc`
4. Add `C:\gcc\bin` to your system PATH:
   - Press `Win + R` → type `sysdm.cpl` → **Advanced** → **Environment Variables**
   - Under **System variables**, find `Path` → **Edit** → **New** → paste `C:\gcc\bin`
   - Click OK on all dialogs
5. Open a **new** PowerShell and confirm: `gcc --version`

---

### Step 2 — Get the Project

If you have Git:
```powershell
git clone <your-repo-url>
cd Packet_analyzer
```

Or just download and extract the ZIP from GitHub, then `cd` into the folder.

---

### Step 3 — Compile

Open **PowerShell** in the project folder (right-click inside the folder → *Open in Terminal*) and run:

```powershell
g++ -std=c++17 -O2 -I include -static-libgcc -static-libstdc++ -static `
    -o dpi_engine.exe `
    src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

> **Why `-static-libgcc -static-libstdc++ -static`?**  
> Without these flags the `.exe` depends on `libstdc++-6-x64.dll` which Windows can't find at runtime (exit code -1073741515). Static linking bundles the runtime directly into the `.exe` so it just works.

If successful, you'll see **no output** and a new `dpi_engine.exe` will appear in the folder. That's correct.

---

### Step 4 — Enable UTF-8 in Your Terminal

The engine's output uses box-drawing characters (╔, ║, ╚). Without this step they appear as garbage (`Ôòö`, `Ôòæ`):

```powershell
chcp 65001
```

Run this **once per PowerShell session** before running the engine.

---

## macOS Setup

### Step 1 — Install the C++ Compiler

macOS comes with **Clang** via Xcode Command Line Tools, which fully supports C++17.

```bash
xcode-select --install
```

A dialog will pop up — click **Install** and wait (~5 minutes). Then confirm:

```bash
clang++ --version
```

You should see something like `Apple clang version 15.0.0`.

> **Alternatively**, if you prefer GCC via Homebrew:
> ```bash
> brew install gcc
> ```
> Then use `g++-14` (or whichever version installed) instead of `g++` in the compile command.

---

### Step 2 — Get the Project

```bash
git clone <your-repo-url>
cd Packet_analyzer
```

---

### Step 3 — Compile

```bash
g++ -std=c++17 -O2 -I include \
    -o dpi_engine \
    src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

> On macOS, no static-linking flags are needed. The system C++ runtime is always available.

If successful, you'll see **no output** and a new `dpi_engine` file will appear. Make it executable if needed:

```bash
chmod +x dpi_engine
```

---

## Running the Engine

The project includes `test_dpi.pcap` — a sample capture with TLS/HTTP/DNS traffic — so you can test immediately without capturing real traffic.

### Windows

```powershell
# 1. Enable UTF-8 output (once per session)
chcp 65001

# 2. Run with the included test file
.\dpi_engine.exe test_dpi.pcap output.pcap
```

### macOS

```bash
./dpi_engine test_dpi.pcap output.pcap
```

You should see the processing report printed to the terminal, and `output.pcap` will be written to the same folder.

---

## Web UI (Browser Interface)

Instead of using the console, you can run a local web dashboard to upload PCAP files, configure blocking rules, and view results visually.

### Setup

```powershell
# 1. Build the web API binary
python web/build_api.py

# 2. Install Python dependencies
pip install -r web/requirements.txt

# 3. Start the server
python web/server.py
```

Then open **http://127.0.0.1:5000** in your browser.

### Features

- Drag-and-drop PCAP upload
- Block by application, IP, or domain
- Live stats: forwarded vs dropped packets, app breakdown, detected domains
- Download the filtered output PCAP
- **Try sample** button to analyze the bundled `test_dpi.pcap` instantly

The console CLI (`dpi_engine.exe`) still works as before — the web UI is an optional layer on top.

---

## Generating a Test PCAP

If you want to regenerate the `test_dpi.pcap` file (or create your own), a Python script is included. You need Python 3 (no extra libraries required):

```bash
# macOS / Windows
python3 generate_test_pcap.py
```

This creates a new `test_dpi.pcap` with synthetic TLS Client Hello packets containing real SNI names (youtube.com, facebook.com, zoom.us, etc.) alongside HTTP and DNS packets.

---

## Understanding the Output

After running the engine you'll see a report like this:

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4     ║
╚══════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                           ║
║ Total Bytes:                5738                           ║
║ TCP Packets:                  73                           ║
║ UDP Packets:                   4                           ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    77                           ║
║ Dropped:                       0                           ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########            ║
║ YouTube               1   1.3%                       ║
║ ...                                                   ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - zoom.us -> Zoom
  - www.facebook.com -> Facebook
```

| Field | Meaning |
|---|---|
| **Total Packets** | Number of packets read from the input `.pcap` |
| **Forwarded** | Packets allowed through (written to output `.pcap`) |
| **Dropped** | Packets that matched a block rule and were excluded |
| **Application Breakdown** | % of traffic per detected application |
| **Detected Domains/SNIs** | TLS Server Name Indication values extracted from handshakes |
| **LB0/LB1 dispatched** | How many packets each Load Balancer thread routed |
| **FP0–FP3 processed** | How many packets each Fast-Path worker thread handled |

---

## All CLI Options

```
dpi_engine <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Drop all packets from this source IP
  --block-app <app>      Drop all packets classified as this app
  --block-domain <dom>   Drop packets whose SNI contains this string
  --lbs <n>              Number of load balancer threads  (default: 2)
  --fps <n>              Fast-path threads per LB thread  (default: 2)
```

**Supported app names** for `--block-app`:  
`YouTube`, `Facebook`, `Instagram`, `Twitter/X`, `TikTok`, `Zoom`, `Discord`,  
`Telegram`, `Spotify`, `Netflix`, `Google`, `Amazon`, `GitHub`, `Cloudflare`,  
`Apple`, `HTTP`, `HTTPS`, `DNS`

### Examples

```bash
# Block YouTube and TikTok
./dpi_engine capture.pcap filtered.pcap --block-app YouTube --block-app TikTok

# Block a specific IP address
./dpi_engine capture.pcap filtered.pcap --block-ip 192.168.1.50

# Block any SNI containing "facebook"
./dpi_engine capture.pcap filtered.pcap --block-domain facebook

# Combine multiple rules
./dpi_engine capture.pcap filtered.pcap \
    --block-app YouTube \
    --block-ip 10.0.0.5 \
    --block-domain tiktok

# Use more threads for large captures (e.g. 4 LBs × 4 FPs = 16 workers)
./dpi_engine big_capture.pcap output.pcap --lbs 4 --fps 4
```

---

## Troubleshooting

### Windows: Program crashes instantly with no output
- **Cause:** Missing runtime DLL (`libstdc++-6-x64.dll`)
- **Fix:** Use the static-linking compile command shown in [Step 3](#step-3--compile)

### Windows: Output is garbled / box characters look like `Ôòö`
- **Cause:** PowerShell is using the wrong character encoding (CP1252 instead of UTF-8)
- **Fix:** Run `chcp 65001` before running the engine

### macOS: `g++: command not found`
- **Fix:** Run `xcode-select --install` and wait for it to finish, then try again

### macOS: `permission denied` when running `./dpi_engine`
- **Fix:** `chmod +x dpi_engine` then try again

### `Error: Could not open file: test_dpi.pcap`
- **Cause:** You're running the command from the wrong directory
- **Fix:** Make sure your terminal is inside the `Packet_analyzer` folder. Run `ls` (Mac) or `dir` (Windows) — you should see `test_dpi.pcap` listed

### `Error: Invalid PCAP magic number`
- **Cause:** The input file is not a valid `.pcap` (might be `.pcapng` format)
- **Fix:** The engine only supports classic `.pcap` format. Convert with Wireshark: *File → Save As → Wireshark/tcpdump pcap*

### Build errors mentioning `#include` or missing headers
- **Cause:** Missing the `-I include` flag or wrong working directory
- **Fix:** Make sure you run the compile command from the **root** of the project folder (where `include/` and `src/` are visible)
