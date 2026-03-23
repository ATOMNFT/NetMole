#pragma once

// ============================================================
// NetMole Config
// All tunable settings live here.
// ============================================================

// ---- Boot splash screen ----
const unsigned long  SPLASH_DURATION_MS         = 3000;   // How long the splash screen shows on boot (ms). 0 = skip splash

// ---- Ui/Animation Settings ----
const float          SPRITE_BRIGHTNESS          = 1.25f;  // Mole sprite brightness multiplier
const unsigned long  ANIM_INTERVAL_MS           = 2000;   // Mole left/right animation speed (ms)
const unsigned long  UI_REFRESH_MS              = 250;    // Info panel refresh rate (ms)

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
