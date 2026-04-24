![Header](Images/mainheader.png)

# NetMole Firmware

A Wi-Fi passive monitoring and deauth tool for the **ESP32-2432S028 (CYD)** — featuring an animated mole mascot, per-AP PCAP capture, EAPOL handshake logging, probe request logging, suspicious/evil-twin AP detection, and optional periodic deauth bursting. 

<br>

<a href="https://atomnft.github.io/NetMole/flash0.html" target="_blank" rel="noopener noreferrer">
  <img src="Images/flash-button.png" alt="Flash Now" width="200" height="140">
</a>

---

<details>
  <summary>A rundown of the Hardware</summary>
  
## Hardware

| Component | Details |
|-----------|---------|
| Board | ESP32-2432S028R (Cheap Yellow Display) |
| Display | 320x240 TFT via TFT_eSPI |
| Storage | MicroSD card (SPI) |
| SD CS Pin | GPIO 5 (configurable in `config.h`) |

</details>

---

<details>
  <summary>Simple setup in Arduino IDE</summary>

## Arduino IDE Settings

| Setting | Value |
|---------|-------|
| Board | Lolin D32 |
| Partition | Default |
| CPU Frequency | 80MHz |
| Core | ESP32 Arduino 2.0.10 |

</details>

---

<details>
  <summary>Check out all the features</summary>

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

</details>

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

<details>
  <summary>Easy configuration in one file</summary>

## Configuration

All settings live in `config.h` — no need to dig into the sketch.

```cpp
// ---- Boot splash screen ----
const unsigned long  SPLASH_DURATION_MS         = 3000;   // How long the splash screen shows on boot (ms). 0 = skip splash

// ---- Ui/Animation Settings ----
const float          SPRITE_BRIGHTNESS          = 1.25f;  // Mole sprite brightness multiplier
const unsigned long  ANIM_INTERVAL_MS           = 2000;   // Mole left/right animation speed (ms)
const unsigned long  UI_REFRESH_MS              = 250;    // Info panel refresh rate (ms)
const unsigned long  INFO_ROTATE_MS            = 2500;   // Top-right Session Findings rotation interval (ms)

// ---- Channel sweep ----
const unsigned long  SWEEP_HOP_MS               = 600;    // Dwell time per channel during active sweep (ms)
const unsigned long  REST_SWEEP_HOP_MS          = 3000;   // Dwell time per channel while Resting (ms)
const unsigned long  FIRST_AP_DISCOVERY_DWELL_MS = 500;   // Short sticky dwell on first AP discovery (ms)
const unsigned long  STICKY_DWELL_MS            = 1800;   // Sticky dwell time when interesting traffic is seen (ms)
const unsigned long  REST_AFTER_QUIET_MS        = 30000;  // Idle timeout before entering Resting mode (ms)

// SSIDs flagged as suspicious when seen (common honeypots, rogue AP names) Add more with "KNOWNSSID",
const char* const    SUSPICIOUS_SSIDS[] = {
  "Free WiFi",
  "FreeWiFi",
  "Free_WiFi",
  "xfinitywifi",
  "attwifi",
  "Starbucks",
  "linksys",
  "default",
  "NETGEAR",
  "dlink",
  "TP-Link",
};
const int            SUSPICIOUS_SSID_COUNT = sizeof(SUSPICIOUS_SSIDS) / sizeof(SUSPICIOUS_SSIDS[0]);

// ---- Logging Settings ----
const bool           EAPOL_LOGGING_ENABLED      = true;   // Set false to skip saving EAPOL handshakes to SD
const bool           PROBE_LOGGING_ENABLED      = true;   // Set false to skip saving probe requests to probes.txt
const bool           PROBE_LOG_HIDDEN           = false;   // Set false to skip wildcard probes (empty SSID)

// ---- Alert Duration ----
const unsigned long  ALERT_DURATION_MS          = 1200;   // How long the alert state stays visible (ms)
const unsigned long  ALERT_COOLDOWN_MS          = 300;    // Minimum gap between consecutive alerts (ms)

// ---- Suspicious AP detection ----
const bool           SUSPICIOUS_DETECTION_ENABLED = true;  // Set false to disable suspicious/evil-twin detection

// ---- Deauth burst ----
const bool           DEAUTH_ENABLED             = false;  // Set true to enable periodic deauth bursts (Dirty Diggler)
const int            DEAUTH_BURST_COUNT         = 500;    // Packets sent per AP per burst
const unsigned long  DEAUTH_INTERVAL_MS         = 30000;  // Time between bursts (ms)
const uint32_t       DEAUTH_MIN_PACKETS         = 10;     // Min observed packets before an AP is targeted (0 = all)

// ---- Hardware ----
static const int     SD_CS_PIN                  = 5;      // SD card chip select pin
static const uint8_t FIRST_CHANNEL              = 1;      // First channel to sweep
static const uint8_t LAST_CHANNEL               = 13;     // Last channel to sweep

// ---- Capture limits ----
static const uint16_t MAX_PACKET_LEN            = 512;    // Max bytes stored per packet
static const int      MAX_APS                   = 64;     // Max number of APs held in cache
```

</details>

---

## Dependencies

- [TFT_eSPI](https://github.com/Bodmer/TFT_eSPI)
- ESP32 Arduino Core 2.0.10
- SD (bundled with ESP32 core)
- esp_wifi / esp_timer (bundled with ESP32 core)

---

## Legal

This tool is intended for **authorized penetration testing and security research on networks you own or have written permission to test**. Unauthorized use against third-party networks is illegal under the CFAA and equivalent laws worldwide. The author assumes no liability for misuse.
