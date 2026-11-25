/*
  ELEC 290 optical text link  -  with Heatshrink compression and Ascon-128 encryption
  Board:  Arduino Uno WiFi Rev2 (ATmega4809, 5 V logic)
  Parts:  850 nm IR laser module (switched by an NPN) + IR detector with a digital output

  Both devices run THIS SAME sketch. Either one can send; the other receives.
  Type a message in the Serial Monitor (115200 baud, "Newline" line ending) to send it.

  BEFORE YOU FLASH (two things that differ from the plain link):
    1. DEVICE_ID must be 0 on one board and 1 on the other. The ID is part of the encryption nonce,
       so two boards with the same ID would reuse nonces. (A receiver also rejects messages that
       claim its own ID, so a mix-up shows up as INVALID MESSAGE instead of failing silently.)
    2. Change KEY to your own 16 random bytes, identical on both boards. Do not publish it.
  Libraries: "Ascon128" (Library Manager, by Hauke D). Heatshrink is bundled in this folder.

  Protocol (Section 4.3 of the portfolio, plus the new payload format):
    - Manchester coding, 500 bit/s (HALF_US = 1000 us per half-bit)
    - Frame: preamble 0xAA 0xAA | sync 0x7E | type | session | length | payload | CRC-16  (8 bytes overhead)
    - DATA payload = meta | counter(4) | Ascon-128 ciphertext of (Heatshrink-compressed or raw text) | tag(16)
      compress first, then encrypt (ciphertext does not compress); raw text is sent if compression would not shrink it
    - Handshake: DATA -> ECHO (CRC of the payload) -> CONFIRM, up to 3 attempts
    - The receiver checks the Ascon tag BEFORE it echoes, so a forged or damaged message never gets an ECHO
    - The receiver shows a message only after it has received CONFIRM

  Manchester rule used here (laser ON = detector reads HIGH):
    bit 1 = OFF then ON  (rising edge in the middle of the bit)
    bit 0 = ON  then OFF (falling edge in the middle of the bit)

  SAFETY (R6, R16, Section 5.1): the laser is OFF at power-up and the sketch will NOT drive the
  laser pin until you type "arm". Only arm with the beam enclosed, 850 nm eyewear on, and TA sign-off.
  For a safe bench test, DISCONNECT the laser and jumper LASER_PIN to DET_PIN, then type "arm", "selftest".

  Serial commands:
    arm / disarm   enable / disable the laser pin
    selftest       send one encrypted frame and decode it on the same board (needs the LASER_PIN -> DET_PIN jumper)
    burst          send 24 bytes of all-1s bits (edges every half-bit) to test detector speed
    help           list commands
    anything else  is sent as a message (max 100 characters)
*/
#include <Arduino.h>
#include <EEPROM.h>
#include <Ascon128.h>          // listed here so the IDE finds the library; used in secure_payload.cpp
#include "secure_payload.h"

// ------------------------- Pins and polarity (change to match your wiring) -------------------------
const uint8_t LASER_PIN = 3;          // HIGH = NPN on = laser on
const uint8_t DET_PIN = 2;            // detector digital output
const bool DET_ACTIVE_HIGH = true;    // true if the detector output is HIGH when it sees light

// ------------------------- Security settings -------------------------
const uint8_t DEVICE_ID = 0;          // 0 on one board, 1 on the other (see above)
const uint8_t KEY[16] = {             // CHANGE ME: same 16 bytes on both boards
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};
const int EEPROM_CTR_ADDR = 0;        // 4 bytes of EEPROM hold the message-counter reservation
const uint32_t CTR_RESERVE = 32;      // EEPROM is written once per boot and once per 32 messages

// ------------------------- Link settings -------------------------
const uint32_t HALF_US = 1000;        // half-bit time in microseconds (1000 -> 500 bit/s)
const uint8_t MAX_PAYLOAD = PAYLOAD_MAX;  // bytes in one frame payload (100 chars + 21 bytes crypto overhead)
const uint8_t MAX_ATTEMPTS = 3;       // R4
const uint16_t ECHO_TIMEOUT_MS = 1000;    // sender waits this long for the ECHO
const uint16_t CONFIRM_TIMEOUT_MS = 1500; // receiver waits this long for CONFIRM
const uint16_t TURNAROUND_MS = 30;    // pause before replying so the other side is listening

const uint8_t PREAMBLE_BYTE = 0xAA;
const uint8_t SYNC_BYTE = 0x7E;
enum : uint8_t { T_DATA = 1, T_ECHO = 2, T_CONFIRM = 3 };
enum : uint8_t { F_NONE = 0, F_INVALID = 1, F_NOSIGNAL = 2 };

struct Frame {
  uint8_t type;
  uint8_t session;
  uint8_t len;
  uint8_t payload[MAX_PAYLOAD];
};

// ------------------------- CRC-16 (CCITT, poly 0x1021, init 0xFFFF) -------------------------
uint16_t crcAdd(uint16_t crc, uint8_t b) {
  crc ^= (uint16_t)b << 8;
  for (uint8_t i = 0; i < 8; i++) crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
  return crc;
}
uint16_t payloadCrc(const uint8_t *p, uint8_t n) {
  uint16_t c = 0xFFFF;
  for (uint8_t i = 0; i < n; i++) c = crcAdd(c, p[i]);
  return c;
}
uint16_t frameCrc(uint8_t type, uint8_t session, uint8_t len, const uint8_t *p) {
  uint16_t c = 0xFFFF;
  c = crcAdd(c, type);
  c = crcAdd(c, session);
  c = crcAdd(c, len);
  for (uint8_t i = 0; i < len; i++) c = crcAdd(c, p[i]);
  return c;
}

// ------------------------- State -------------------------
bool armed = false;
volatile bool rxEnabled = true;
uint8_t sessionId = 0;

// ------------------------- Message counter (nonce) -------------------------
// Ascon-128 breaks if a (key, nonce) pair is ever used twice, and the 8-bit session ID wraps after 256
// messages, so the nonce uses a 32-bit counter instead. EEPROM stores an upper bound on the counters
// that may have been used, so even a power cut mid-session can never make the counter go backwards.
uint32_t ctrNext = 0, ctrLimit = 0;

void ctrInit() {
  uint32_t s;
  EEPROM.get(EEPROM_CTR_ADDR, s);
  if (s == 0xFFFFFFFFUL) s = 0;                  // blank EEPROM
  ctrNext = s;
  ctrLimit = s + CTR_RESERVE;
  EEPROM.put(EEPROM_CTR_ADDR, ctrLimit);
}

uint32_t ctrTake() {
  if (ctrNext >= ctrLimit) { ctrLimit += CTR_RESERVE; EEPROM.put(EEPROM_CTR_ADDR, ctrLimit); }
  return ctrNext++;
}

// Replay protection (RAM only: a receiver reboot forgets it). Counters from each sender must increase.
bool seenAny[2] = { false, false };
uint32_t lastCtr[2] = { 0, 0 };

bool counterFresh(uint8_t who, uint32_t ctr) {
  if (who > 1 || who == DEVICE_ID) return false;       // wrong ID, or our own ID (mis-flashed board / reflection)
  return !seenAny[who] || ctr > lastCtr[who];
}

// ------------------------- Receive: edge capture (interrupt) -------------------------
const uint8_t RING_SIZE = 64;         // must be a power of two
volatile uint32_t ringT[RING_SIZE];
volatile uint8_t ringL[RING_SIZE];
volatile uint8_t ringHead = 0, ringTail = 0;
volatile bool ringOverflow = false;

bool readDetector() { return (digitalRead(DET_PIN) == HIGH) == DET_ACTIVE_HIGH; }

void edgeISR() {
  if (!rxEnabled) return;
  uint32_t t = micros();
  uint8_t lvl = readDetector() ? 1 : 0;
  uint8_t n = (ringHead + 1) & (RING_SIZE - 1);
  if (n == ringTail) { ringOverflow = true; return; }
  ringT[ringHead] = t;
  ringL[ringHead] = lvl;
  ringHead = n;
}

// ------------------------- Receive: Manchester + frame decoder -------------------------
enum DState : uint8_t { D_IDLE, D_MID, D_BOUND };
enum FState : uint8_t { FS_HUNT, FS_HEADER, FS_PAYLOAD, FS_CRC };

DState dstate = D_IDLE;
FState fstate = FS_HUNT;
uint32_t lastT = 0;
uint8_t lastLevel = 0;
uint16_t shiftReg = 0;
uint8_t nBits = 0, curByte = 0, bitInByte = 0, byteIdx = 0;
uint16_t rxCrc = 0;
Frame rxf;
Frame readyFrame;
bool readyFlag = false;
uint8_t badEvents = 0;                // frames that started (sync seen) but were damaged

void resetDecoder(bool report) {
  if (report && fstate != FS_HUNT && badEvents < 255) badEvents++;
  dstate = D_IDLE;
  fstate = FS_HUNT;
  shiftReg = 0;
  nBits = 0; curByte = 0; bitInByte = 0; byteIdx = 0;
  lastLevel = 0;
}

void finishFrame() {
  if (rxCrc == frameCrc(rxf.type, rxf.session, rxf.len, rxf.payload)) {
    readyFrame = rxf;
    readyFlag = true;
  } else if (badEvents < 255) {
    badEvents++;
  }
  resetDecoder(false);
}

void byteDone(uint8_t v) {
  switch (fstate) {
    case FS_HEADER:
      if (byteIdx == 0) rxf.type = v;
      else if (byteIdx == 1) rxf.session = v;
      else {
        rxf.len = v;
        if (v > MAX_PAYLOAD) { resetDecoder(true); return; }
      }
      byteIdx++;
      if (byteIdx == 3) { byteIdx = 0; fstate = rxf.len ? FS_PAYLOAD : FS_CRC; }
      break;
    case FS_PAYLOAD:
      rxf.payload[byteIdx++] = v;
      if (byteIdx == rxf.len) { byteIdx = 0; fstate = FS_CRC; }
      break;
    case FS_CRC:
      if (byteIdx == 0) { rxCrc = (uint16_t)v << 8; byteIdx = 1; }
      else { rxCrc |= v; finishFrame(); }
      break;
    default: break;
  }
}

void pushBit(uint8_t b) {
  if (fstate == FS_HUNT) {
    shiftReg = (uint16_t)((shiftReg << 1) | b);
    if (nBits < 255) nBits++;
    if (nBits >= 12 && (shiftReg & 0xFF) == SYNC_BYTE) {
      fstate = FS_HEADER; bitInByte = 0; curByte = 0; byteIdx = 0;
    } else if (nBits > 64) {
      resetDecoder(false);              // no sync found: ignore as noise
    }
  } else {
    curByte = (uint8_t)((curByte << 1) | b);
    if (++bitInByte == 8) {
      uint8_t v = curByte;
      bitInByte = 0; curByte = 0;
      byteDone(v);
    }
  }
}

// 1 = about one half-bit, 2 = about two half-bits, 0 = out of range
uint8_t classify(uint32_t dt) {
  if (dt >= HALF_US / 2 && dt < (HALF_US * 3) / 2) return 1;
  if (dt >= (HALF_US * 3) / 2 && dt < (HALF_US * 5) / 2) return 2;
  return 0;
}

void onEdge(uint32_t t, uint8_t level) {
  if (level == lastLevel && dstate != D_IDLE) return;   // spurious repeat of the same level
  if (dstate == D_IDLE) {
    if (level) { lastT = t; lastLevel = 1; dstate = D_MID; pushBit(1); }  // first edge = middle of a '1'
    return;
  }
  uint32_t dt = t - lastT;
  lastT = t;
  lastLevel = level;
  uint8_t c = classify(dt);
  if (c == 0) { resetDecoder(true); return; }
  if (dstate == D_MID) {
    if (c == 1) dstate = D_BOUND;                       // boundary edge, no bit yet
    else pushBit(level);                                // middle edge
  } else {                                              // D_BOUND
    if (c == 1) { dstate = D_MID; pushBit(level); }     // middle edge after a boundary edge
    else resetDecoder(true);
  }
}

void flushRx() {
  noInterrupts();
  ringTail = ringHead;
  ringOverflow = false;
  interrupts();
  resetDecoder(false);
  readyFlag = false;
}

void pollRx() {
  for (;;) {
    noInterrupts();
    if (ringTail == ringHead) { interrupts(); break; }
    uint32_t t = ringT[ringTail];
    uint8_t l = ringL[ringTail];
    ringTail = (ringTail + 1) & (RING_SIZE - 1);
    interrupts();
    onEdge(t, l);
  }
  if (ringOverflow) { ringOverflow = false; resetDecoder(true); }
  if (dstate != D_IDLE && (int32_t)(micros() - lastT) > (int32_t)(4 * HALF_US)) resetDecoder(true); // frame cut off
}

bool waitFrame(Frame &out, uint16_t timeoutMs) {
  uint32_t t0 = millis();
  while ((uint32_t)(millis() - t0) < timeoutMs) {
    pollRx();
    if (readyFlag) { out = readyFrame; readyFlag = false; return true; }
  }
  return false;
}

// ------------------------- Transmit -------------------------
inline void laser(bool on) { digitalWrite(LASER_PIN, on ? HIGH : LOW); }

static void emitHalf(uint32_t &next, bool level, bool keepRx) {
  while ((int32_t)(micros() - next) < 0) { if (keepRx) pollRx(); }
  laser(level);
  next += HALF_US;
}

// Sends raw bytes MSB first, Manchester coded. keepRx is only used by the loopback self-test.
bool txBytes(const uint8_t *b, uint8_t n, bool keepRx) {
  if (!armed) { Serial.println(F("Laser pin not armed. Type 'arm' first.")); return false; }
  if (!keepRx) rxEnabled = false;
  uint32_t next = micros() + 50;
  for (uint8_t i = 0; i < n; i++) {
    for (int8_t k = 7; k >= 0; k--) {
      bool bit = (b[i] >> k) & 1;
      emitHalf(next, !bit, keepRx);   // first half: bit 1 -> OFF, bit 0 -> ON
      emitHalf(next, bit, keepRx);    // second half: bit 1 -> ON,  bit 0 -> OFF
    }
  }
  while ((int32_t)(micros() - next) < 0) { if (keepRx) pollRx(); }
  laser(false);                       // idle = laser off
  if (!keepRx) { delay(5); flushRx(); rxEnabled = true; }
  return true;
}

bool txFrame(uint8_t type, uint8_t session, const uint8_t *p, uint8_t len, bool keepRx) {
  uint8_t out[3 + 3 + MAX_PAYLOAD + 2];
  uint8_t n = 0;
  out[n++] = PREAMBLE_BYTE; out[n++] = PREAMBLE_BYTE; out[n++] = SYNC_BYTE;
  out[n++] = type; out[n++] = session; out[n++] = len;
  for (uint8_t i = 0; i < len; i++) out[n++] = p[i];
  uint16_t c = frameCrc(type, session, len, p);
  out[n++] = (uint8_t)(c >> 8);
  out[n++] = (uint8_t)(c & 0xFF);
  return txBytes(out, n, keepRx);
}

// ------------------------- Sender -------------------------
bool sendMessage(const uint8_t *msg, uint8_t len) {
  sessionId++;

  // Compress + encrypt once. Retries resend the identical payload (same nonce, same ciphertext).
  uint8_t sealed[MAX_PAYLOAD];
  bool compressed = false;
  uint8_t slen = sp_seal(KEY, DEVICE_ID, ctrTake(), sessionId, msg, len, sealed, &compressed);
  if (!slen) { Serial.println(F("Could not encrypt message.")); return false; }
  Serial.print(F("TX: ")); Serial.print(len); Serial.print(F(" chars -> "));
  Serial.print(slen); Serial.print(F(" B payload ("));
  Serial.print(compressed ? F("compressed") : F("not compressed")); Serial.println(F(")"));

  uint16_t crc = payloadCrc(sealed, slen);
  for (uint8_t attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    Serial.print(F("SENDING (attempt ")); Serial.print(attempt); Serial.println(F(")"));
    if (!txFrame(T_DATA, sessionId, sealed, slen, false)) return false;
    bool matched = false;
    uint32_t t0 = millis();
    for (;;) {
      uint32_t el = millis() - t0;
      if (el >= ECHO_TIMEOUT_MS) break;
      Frame f;
      if (!waitFrame(f, ECHO_TIMEOUT_MS - el)) break;
      if (f.type == T_ECHO && f.session == sessionId) {
        matched = (f.len == 2) && ((((uint16_t)f.payload[0] << 8) | f.payload[1]) == crc);
        break;
      }
    }
    if (matched) {
      delay(TURNAROUND_MS);
      txFrame(T_CONFIRM, sessionId, NULL, 0, false);
      badEvents = 0;
      Serial.println(F("SENT"));
      return true;
    }
    Serial.println(F("  no matching echo"));
  }
  badEvents = 0;
  Serial.println(F("FAILED"));
  return false;
}

// ------------------------- Receiver -------------------------
uint8_t pending[TEXT_MAX + 1];        // decrypted text waiting for CONFIRM
uint8_t pendLen = 0;
uint8_t pendWho = 0;
uint32_t pendCtr = 0;
uint8_t failCount = 0, lastFail = F_NONE;

void clearPending() { memset(pending, 0, sizeof(pending)); pendLen = 0; }   // R10: do not keep the message

void noteFailure(uint8_t kind) {
  failCount++;
  lastFail = kind;
  if (failCount >= MAX_ATTEMPTS) {
    Serial.println(kind == F_INVALID ? F("INVALID MESSAGE") : F("NO SIGNAL"));
    failCount = 0;
  }
}

void deliver() {
  Serial.print(F("MESSAGE RECEIVED: "));
  for (uint8_t i = 0; i < pendLen; i++) {
    uint8_t c = pending[i];
    Serial.write((uint8_t)((c >= 32 && c <= 126) ? c : '?'));
  }
  Serial.println();
  failCount = 0;
  clearPending();
}

void handleData(Frame f) {
  for (;;) {                                   // loops again if the sender retries
    uint8_t s = f.session;

    // Verify the Ascon tag and decrypt BEFORE echoing. A damaged, forged or replayed frame gets no ECHO.
    uint8_t who = 0;
    uint32_t ctr = 0;
    int16_t n = sp_open(KEY, s, f.payload, f.len, pending, &who, &ctr);
    if (n < 0 || !counterFresh(who, ctr)) { clearPending(); noteFailure(F_INVALID); return; }
    pendLen = (uint8_t)n; pendWho = who; pendCtr = ctr;

    uint16_t c = payloadCrc(f.payload, f.len);       // ECHO still carries the CRC of the on-air payload
    uint8_t e[2] = { (uint8_t)(c >> 8), (uint8_t)(c & 0xFF) };
    delay(TURNAROUND_MS);
    txFrame(T_ECHO, s, e, 2, false);
    Frame g;
    if (!waitFrame(g, CONFIRM_TIMEOUT_MS)) { clearPending(); noteFailure(F_NOSIGNAL); return; }
    if (g.type == T_CONFIRM && g.session == s) {
      seenAny[pendWho] = true; lastCtr[pendWho] = pendCtr;   // only a delivered message advances the replay window
      deliver();
      return;
    }
    if (g.type == T_DATA) { f = g; continue; }
    clearPending(); noteFailure(F_NOSIGNAL); return;
  }
}

// ------------------------- Commands -------------------------
void selfTest() {
  if (!armed) { Serial.println(F("Type 'arm' first (laser disconnected, LASER_PIN jumpered to DET_PIN).")); return; }
  // Repetitive on purpose so that Heatshrink has something to compress.
  const char *m = "HELLO ELEC290 HELLO ELEC290";
  uint8_t n = strlen(m);
  uint8_t sealed[MAX_PAYLOAD];
  bool compressed = false;
  uint8_t slen = sp_seal(KEY, DEVICE_ID, ctrTake(), 0x55, (const uint8_t *)m, n, sealed, &compressed);
  Serial.print(F("selftest payload: ")); Serial.print(n); Serial.print(F(" chars -> ")); Serial.print(slen);
  Serial.println(compressed ? F(" B (compressed)") : F(" B (not compressed)"));
  flushRx();
  badEvents = 0;
  txFrame(T_DATA, 0x55, sealed, slen, true);
  Frame f;
  if (waitFrame(f, 100) && f.type == T_DATA && f.len == slen && memcmp(f.payload, sealed, slen) == 0) {
    uint8_t txt[TEXT_MAX + 1], who; uint32_t ctr;
    int16_t r = sp_open(KEY, 0x55, f.payload, f.len, txt, &who, &ctr);
    if (r == n && memcmp(txt, m, n) == 0)
      Serial.println(F("SELFTEST PASS: frame decoded, CRC ok, tag ok, decrypted and decompressed"));
    else
      Serial.println(F("SELFTEST FAIL: frame arrived but decrypt/decompress failed"));
    memset(txt, 0, sizeof(txt));
  } else if (badEvents) {
    Serial.println(F("SELFTEST FAIL: frame damaged (bad CRC or timing)"));
  } else {
    Serial.println(F("SELFTEST FAIL: nothing decoded. Check the jumper and DET_ACTIVE_HIGH."));
  }
  flushRx();
  badEvents = 0;
}

void burst() {
  uint8_t b[24];
  memset(b, 0xFF, sizeof(b));
  Serial.println(F("Sending burst..."));
  txBytes(b, sizeof(b), false);
  Serial.println(F("Done."));
}

void printHelp() {
  Serial.println(F("Commands: arm, disarm, selftest, burst, help. Anything else is sent as a message."));
}

void handleLine(char *line) {
  uint8_t n = strlen(line);
  while (n && (line[n - 1] == '\r' || line[n - 1] == ' ')) line[--n] = 0;
  if (!n) return;
  if (!strcmp(line, "arm")) {
    armed = true;
    Serial.println(F("ARMED: laser pin is active. Beam enclosed? Eyewear on? TA sign-off (R16)?"));
  } else if (!strcmp(line, "disarm")) {
    armed = false; laser(false);
    Serial.println(F("Disarmed."));
  } else if (!strcmp(line, "selftest")) selfTest();
  else if (!strcmp(line, "burst")) burst();
  else if (!strcmp(line, "help")) printHelp();
  else {
    if (n > TEXT_MAX) { n = TEXT_MAX; Serial.println(F("Message cut to 100 characters.")); }
    sendMessage((const uint8_t *)line, n);
  }
}

void readSerial() {
  static char line[TEXT_MAX + 8];
  static uint8_t pos = 0;
  while (Serial.available()) {
    char ch = Serial.read();
    if (ch == '\n') { line[pos] = 0; pos = 0; handleLine(line); }
    else if (pos < sizeof(line) - 1) line[pos++] = ch;
  }
}

// ------------------------- Arduino entry points -------------------------
void setup() {
  pinMode(LASER_PIN, OUTPUT);
  laser(false);                                       // laser OFF at power-up
  pinMode(DET_PIN, INPUT);                            // use INPUT_PULLUP if your detector output is open-collector
  Serial.begin(115200);
  delay(300);
  ctrInit();
  attachInterrupt(digitalPinToInterrupt(DET_PIN), edgeISR, CHANGE);
  Serial.print(F("ELEC290 optical link ready (encrypted, DEVICE_ID="));
  Serial.print(DEVICE_ID);
  Serial.println(F("). Laser is OFF (not armed). Type 'help'."));
}

void loop() {
  pollRx();
  if (readyFlag) {
    Frame f = readyFrame;
    readyFlag = false;
    if (f.type == T_DATA) handleData(f);
  }
  while (badEvents) { badEvents--; noteFailure(F_INVALID); }
  readSerial();
}
