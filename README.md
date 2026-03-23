# NetMole v1

A Wi-Fi passive monitoring and deauth tool for the **ESP32-2432S028 (CYD)** — featuring an animated mole mascot, per-AP PCAP capture, EAPOL handshake logging, probe request logging, suspicious/evil-twin AP detection, and optional periodic deauth bursting.

> **For authorized use only. Only use on networks you own or have explicit permission to test.**

---

## Hardware

| Component | Details |
|-----------|---------|
| Board | ESP32-2432S028R (Cheap Yellow Display) |
| Display | 320x240 TFT via TFT_eSPI |
| Storage | MicroSD card (SPI) |
| SD CS Pin | GPIO 5 (configurable in `config.h`) |

---

## Arduino IDE Settings

| Setting | Value |
|---------|-------|
| Board | Lolin D32 |
| Partition | Default |
| CPU Frequency | 80MHz |
| Core | ESP32 Arduino 2.0.10 |

---

## Features

### Passive Scanning
- Sweeps Wi-Fi channels 1–13, learning APs from beacon frames
- Sticky dwell on active channels when interesting traffic is detected
- Resting mode after configurable inactivity timeout — slow sweep continues in the background
- Automatically wakes from Resting when new APs or EAPOL traffic is detected

### PCAP Capture (SD Card)
- Creates two separate PCAP files per discovered AP:
  - `SSID_BSSID_beacon.pcap` — first beacon frame
  - `SSID_BSSID_eapol.pcap` — WPA/WPA2 4-way handshake packets
- EAPOL files are Hashcat-ready for offline password auditing
- EAPOL logging can be toggled independently in `config.h`

### Probe Request Logging
- Captures probe requests from nearby devices — MAC address and requested SSID
- Logged to `/probes.txt` on SD as CSV (`MAC, SSID, Channel, RSSI`)
- Optional logging of wildcard probes (empty SSID) — configurable in `config.h`

### Suspicious / Evil-Twin Detection
- Flags APs whose SSID matches a configurable watchlist (honeypots, common rogue AP names)
- Detects evil-twin APs — same SSID as a known AP but a different BSSID
- Logged to `/suspicious.txt` on SD (`Reason, SSID, BSSID, Channel, RSSI`)
- Evil-twin entries are clearly labeled `(Evil-Twin)` in the log
- Triggers the red alert flash on detection

### Deauth Burst (Dirty Diggler Mode)
- Periodically sends 802.11 deauth frames to all learned APs
- Spoofs the AP's own BSSID as source — clients believe the AP sent the deauth
- Configurable burst count, interval, and minimum activity threshold
- Only targets APs that have reached the minimum observed packet count
- Disabled by default — enable in `config.h`

### Display & UI
- 320x240 TFT info panel with live State, AP count, Mode, SD status, and TX count
- Footer shows the most active AP and its live packet count
- Boot splash screen with configurable display duration (0 = skip)
- Animated mole mascot (Diggler) reflects current state:

| Frame | State |
|-------|-------|
| Green forward | Idle / Resting |
| Left / Right | Scanning |
| Red forward | Alert — packet logged or suspicious AP detected |
| Orange | Deauth burst in progress |

### States & Modes

| State | Description |
|-------|-------------|
| IDLE | Resting — no interesting activity, slow background sweep |
| SCANNING | Active sweep, mole animates left/right |
| ALERT | Packet logged or suspicious AP found — red mole flash |
| DEAUTH | Deauth burst in progress — orange mole, "Blasting" mode label |

| Mode | Description |
|------|-------------|
| Crawling | Standard channel sweep |
| Digging | Sticky dwell on active channel |
| Blasting | Deauth burst firing |

---

## File Structure

Place all files in the same Arduino sketch folder:

```
NetMole/
├── NetMole.ino
├── config.h
├── netmole-splash.h
├── mole_left.h
├── mole_right.h
├── mole_forward_green.h
├── mole_forward_red.h
└── mole_deauth_orange.h
```

SD card output structure:
```
/
├── pcap/
│   ├── MyNetwork_AABBCCDDEEFF_beacon.pcap
│   ├── MyNetwork_AABBCCDDEEFF_eapol.pcap
│   └── ...
├── probes.txt
└── suspicious.txt
```

---

<div class="config">

## Configuration

All settings live in `config.h` — no need to dig into the sketch.

```cpp
// Boot splash
SPLASH_DURATION_MS        // Display time in ms. 0 = skip

// Display / Animation
SPRITE_BRIGHTNESS         // Mole brightness multiplier
ANIM_INTERVAL_MS          // Left/right animation speed
UI_REFRESH_MS             // Info panel refresh rate

// Channel sweep
SWEEP_HOP_MS              // Dwell per channel (active)
REST_SWEEP_HOP_MS         // Dwell per channel (resting)
STICKY_DWELL_MS           // Sticky dwell on active channel
REST_AFTER_QUIET_MS       // Inactivity timeout before resting

// Capture
EAPOL_LOGGING_ENABLED     // Save EAPOL handshakes to SD
PROBE_LOGGING_ENABLED     // Save probe requests to probes.txt
PROBE_LOG_HIDDEN          // Include wildcard (empty SSID) probes

// Suspicious detection
SUSPICIOUS_DETECTION_ENABLED  // Enable evil-twin and SSID watchlist
SUSPICIOUS_SSIDS[]            // List of flagged SSID names

// Deauth burst
DEAUTH_ENABLED            // Master on/off (default: false)
DEAUTH_BURST_COUNT        // Packets per AP per burst
DEAUTH_INTERVAL_MS        // Time between bursts
DEAUTH_MIN_PACKETS        // Min observed packets to target an AP

// Hardware
SD_CS_PIN                 // SD card chip select pin
FIRST_CHANNEL             // First channel to sweep
LAST_CHANNEL              // Last channel to sweep
MAX_PACKET_LEN            // Max bytes stored per packet
MAX_APS                   // Max APs held in cache
```
</div>

---

## Dependencies

- [TFT_eSPI](https://github.com/Bodmer/TFT_eSPI)
- ESP32 Arduino Core 2.0.10
- SD (bundled with ESP32 core)
- esp_wifi / esp_timer (bundled with ESP32 core)

---

## Legal

This tool is intended for **authorized penetration testing and security research on networks you own or have written permission to test**. Unauthorized use against third-party networks is illegal under the CFAA and equivalent laws worldwide. The author assumes no liability for misuse.
