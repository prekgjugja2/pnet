# PNet

PNet is a Windows home Wi-Fi console. It scans the local network, lists phones, computers, TVs, and the router, shows live internet use, and can block ads and websites for the whole house.

It stays on your LAN. There is no cloud account. Device lists, router login, and block rules are stored in a SQLite database on the computer that runs PNet.

**Suggested GitHub About text**

> Windows home Wi-Fi console. Scan devices, watch live traffic, and block ads and sites for the whole network.

## What you can do

| Screen | What it is for |
|---|---|
| **Overview** | Security score, devices online, open defender items, and shortcuts to scan, connect the router, and turn on blocking. |
| **Router** | Save the router admin URL and login, open the real admin page, and keep a plan for Wi-Fi name, guest network, DNS, DHCP reservations, schedules, MAC filter, port forwards, and speed caps. |
| **Devices** | Everyone on the LAN: name, brand, IP, MAC, trust, access, ping, and a live speed column. Wake-on-LAN, quarantine, and per-device speed limits. |
| **Traffic** | Download and upload speed, plus which apps are using the network. |
| **Firewall** | Named allow and block rules (direction, protocol, source, destination, port). These are records in PNet; apply the same idea on the router when the model does not take the rule itself. |
| **Blocking** | AdGuard DNS filter, adult-site list, social / games / streaming categories, bedtime windows, per-device exceptions, and custom domains. |
| **IP list** | Address book for gateway, DNS, reserved, guest, public, VPN, and blocked addresses. |
| **Defender** | Log suspicious events and run a check for duplicate addresses, blocked-address clashes, cameras missing an IP, and inbound allow-all rules. |
| **Cameras** | Saved IP cameras with snapshot and stream links. |
| **Settings** | Home name, optional LAN label, and JSON backup / restore. |

## How live traffic works

Speed and app names come from three places. PNet uses whichever ones are available.

1. **This PC.** The native scanner (`pnet_scan.exe --monitor`) reads adapter byte counters and which Windows process owns each TCP or UDP connection.
2. **Other Windows PCs.** Open a device, choose **Install agent**, and run the printed command on that computer. The agent posts a snapshot to `agent.php` every few seconds.
3. **The router.** After you save the admin URL and password, PNet can pull the client list and, on supported models, live rates.
   - **TP-Link** — client list, and live speed when the firmware exposes it.
   - **ZTE** (including `.gch` ONTs such as the F627) — client list; older models may list clients without rates.
   - **ASUS-style** admin APIs — client traffic when that endpoint responds.

Other brands can still be scanned on the LAN. Their admin pages open in the desktop app, but live per-device rates need an agent or a supported router API.

## How site blocking works

Blocking runs on the PC that hosts PNet, using [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome). The binary is downloaded into `%LOCALAPPDATA%\PNet\AdGuardHome` the first time you start the network blocker. It is not stored in this repository.

1. Turn on the AdGuard list, the adult list, category lists, or your own domains.
2. Start the network blocker from the desktop app.
3. **Push to this Wi-Fi** points this PC’s DNS at PNet.
4. **Push to router** (or set the router DNS by hand) points phones, TVs, and other devices at the same PC.

Bedtime can turn social, games, or streaming lists on only between the hours you set. One device can be allowed through a category. The adult list stays on for the whole house.

## How the pieces fit

```
Desktop app (Electron)
    │  loads the web console and starts AdGuard Home / DNS helpers
    ▼
Web console (PHP + SQLite)          api.php  ·  agent.php
    │  prefers the native scanner, falls back to PHP ARP / ping
    ▼
Scanner (C / C++)                   engine/build/pnet_scan.exe
    ICMP sweep, ARP / neighbor table, NetBIOS names,
    optional common TCP ports, OUI vendor guess, JSON out
```

The console only answers clients that are on the same home network. Pages are `noindex`. Session cookies are HTTP-only.

## Requirements

- Windows 10 or 11, 64-bit
- [XAMPP](https://www.apachefriends.org/) (Apache + PHP) with `pdo_sqlite` and `sqlite3` enabled, **or** PHP on `PATH` if you only need the API
- For the desktop window: [Node.js](https://nodejs.org/)
- For the scanner: MinGW (`winget install BrechtSanders.WinLibs.POSIX.UCRT`) or Visual Studio Build Tools with the “Desktop development with C++” workload
- A C compiler is optional for browsing the UI. Discovery is more complete when `engine/build/pnet_scan.exe` is present

## Run it

**Installed app.** Double-click `PNet-Setup.exe` after you build it (see below). It installs a desktop shortcut named PNet. Apache (XAMPP) needs to be running; the app tries to start it.

**From this folder.**

```bat
Open PNet.bat
```

That starts Electron from `desktop\` when `npm install` has already been run, otherwise the unpacked build or the installed app.

**Web console only.** Put this folder under the Apache document root (for example `C:\xampp\htdocs\pnet`) and open `http://localhost/pnet` from a device on the same Wi-Fi.

**Developer desktop window.**

```bat
cd desktop
npm install
npm start
```

## Build from source

One shot (compiler check, scanner, Electron installer):

```bat
scripts\build-setup.bat
```

The installer is written to `desktop\dist\` and copied to `PNet-Setup.exe` in the project root. That exe, `desktop\node_modules\`, `desktop\dist\`, and `engine\build\` are gitignored.

Scanner only:

```bat
cd engine
build.bat
build\pnet_scan.exe --json
build\pnet_scan.exe --monitor --json
```

```text
pnet_scan [--json] [--monitor] [--ports] [--cidr x.x.x.x/24] [--timeout ms] [--no-netbios]
```

`--ports` checks a short list of common TCP ports. `--cidr` overrides the detected LAN (example: `192.168.1.0/24`).

CMake is also available (`engine/CMakeLists.txt`) if you prefer that to `build.bat`.

## Layout

| Path | Role |
|---|---|
| `index.php`, `api.php`, `agent.php` | Web console, JSON API, Windows agent intake |
| `lib/app.php` | Database, devices, blocking, router settings |
| `lib/traffic_sources.php` | This-PC, agent, and router traffic |
| `assets/` | Console CSS, JS, and device / brand icons |
| `engine/` | C/C++ scanner and traffic monitor |
| `desktop/` | Electron shell, DNS helper, installer config |
| `scripts/` | Build, compiler/PHP checks, agent installer, hosts and DNS helpers |
| `data/` | SQLite database (not committed) |
| `setup/pnet_setup.cpp` | Native setup helper |

## What stays off GitHub

`.gitignore` already excludes:

- `data/*.sqlite` and router session files (device list, block rules, router username and password)
- `engine/build/`, `desktop/node_modules/`, `desktop/dist/`, `PNet-Setup.exe`
- AdGuard Home (downloaded at runtime into `%LOCALAPPDATA%\PNet`)

Do not commit a backup JSON from **Settings → Download backup**. It contains the same local data.

`scripts/_*.php` and `scripts/_*.txt` are local probes used while wiring specific router firmwares. They are not part of the app.

## License

PNet is released under the [MIT License](LICENSE).

AdGuard Home is a separate project. PNet downloads it on first use and does not redistribute its binary. Brand icons under `assets/brands/` are simple marks for the device list.
