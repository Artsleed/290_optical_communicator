/*
  ELEC 290 detector speed check (the laser is NOT used by this sketch)

  Purpose: find out whether the IR detector can follow 1 ms pulses (Design investigation row 3, EDR-5).
  How to use:
    1. Load THIS sketch on the board that has the detector. Open the Serial Monitor at 115200 baud.
    2. Load ir_link.ino on the OTHER board, arm it (laser enclosed, eyewear on, TA sign-off), and type: burst
       The burst is 24 bytes of all-1s bits, which makes an edge every half-bit (1000 us at the default rate).
    3. Read the line printed each second:
         edges   how many light/dark changes were seen (a burst should give about 192 edges)
         min     shortest time between two edges, in microseconds (should be close to 1000)
         avg     average time between edges that are less than 50 ms apart
    A detector that is too slow gives far fewer edges than expected, or a min/avg much larger than 1000.
    Keep DET_PIN and DET_ACTIVE_HIGH the same as in ir_link.ino.
*/
#include <Arduino.h>

const uint8_t DET_PIN = 2;
const bool DET_ACTIVE_HIGH = true;

volatile uint32_t lastT = 0;
volatile uint32_t edges = 0;
volatile uint32_t minDt = 0xFFFFFFFF;
volatile uint32_t sumDt = 0;
volatile uint32_t nDt = 0;
volatile bool haveLast = false;

void edgeISR() {
  uint32_t t = micros();
  if (haveLast) {
    uint32_t dt = t - lastT;
    if (dt < 50000UL) {                 // ignore the gaps between bursts
      if (dt < minDt) minDt = dt;
      sumDt += dt;
      nDt++;
    }
  }
  haveLast = true;
  lastT = t;
  edges++;
}

void setup() {
  pinMode(DET_PIN, INPUT);              // use INPUT_PULLUP if your detector output is open-collector
  Serial.begin(115200);
  attachInterrupt(digitalPinToInterrupt(DET_PIN), edgeISR, CHANGE);
  Serial.println(F("Detector test ready. Send a burst from the other board."));
}

void loop() {
  static uint32_t lastPrint = 0;
  if (millis() - lastPrint < 1000) return;
  lastPrint = millis();
  noInterrupts();
  uint32_t e = edges, mn = minDt, s = sumDt, n = nDt;
  edges = 0; minDt = 0xFFFFFFFF; sumDt = 0; nDt = 0; haveLast = false;
  interrupts();
  bool level = (digitalRead(DET_PIN) == HIGH) == DET_ACTIVE_HIGH;
  Serial.print(F("level=")); Serial.print(level ? 1 : 0);
  Serial.print(F("  edges=")); Serial.print(e);
  if (n) {
    Serial.print(F("  min=")); Serial.print(mn);
    Serial.print(F(" us  avg=")); Serial.print(s / n);
    Serial.println(F(" us"));
  } else {
    Serial.println();
  }
}
