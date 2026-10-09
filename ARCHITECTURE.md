# PNet architecture (Fing-style)

## 1. Core network scanner — C / C++

Location: `engine/`

| Piece | Role |
|---|---|
| `include/pnet_scan.h` | C API |
| `src/pnet_scan.c` | ICMP sweep, ARP/neighbor merge, NetBIOS, optional TCP ports, OUI + type guess, JSON export |
| `include/pnet_monitor.h` | Live traffic / app snapshot API |
| `src/pnet_monitor.c` | Adapter byte counters + TCP/UDP owners → app list |
| `src/main.cpp` | CLI (`pnet_scan.exe`) |
| `build.bat` | MinGW or MSVC one-shot build |

```bat
cd engine
build.bat
build\pnet_scan.exe --json
build\pnet_scan.exe --monitor --json
```

Live usage (`#traffic` or Devices → **Live**):

| Source | What you get |
|---|---|
| **This PC** | Full speed + app names via `pnet_scan.exe --monitor` |
| **PNet agent** | Same on any Windows PC — run `scripts\install-pnet-agent.bat TOKEN` |
| **Router** | Per-device speed when supported. **ZTE F627** (and similar `.gch` ONTs) plus ASUS-style APIs. Older ZTE models may only list clients without live rates. |

Create an agent: open a device → **Install agent** → copy the command onto that computer.

For your ZTE: open **Router**, set admin URL to `http://192.168.1.1`, save username/password, then **Connect**.

Install a compiler if needed:

```bat
winget install BrechtSanders.WinLibs.POSIX.UCRT
```

## 2. Desktop UI — Electron (JS)

Location: `desktop/`

Talks to the native engine over JSON (same pattern as Fing Desktop → Fing Agent).

### Easy Windows installer (.exe)

**For normal use:** double-click `install/PNet-Setup.exe` (also copied to `PNet-Setup.exe` in the project root when you build locally).

Rebuild (developers):

```bat
scripts\build-setup.bat
```

Or run without installing:

```bat
desktop\dist\win-unpacked\PNet.exe
```

Dev mode:

```bat
cd desktop
npm install
npm start
```

## 3. Web console — PHP

Location: `index.php` + `assets/`

**Discover devices** prefers `engine/build/pnet_scan.exe` when present, then falls back to PHP ARP/ping.
