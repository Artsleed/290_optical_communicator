/*
  ELEC 290 detector test  (receiver side only, never drives the laser)
  Board: Arduino Uno WiFi Rev2.  Detector digital output -> DET_PIN.

  What it does:
    1. The on-board LED follows the detector, so you can see it react without opening the Serial Monitor.
    2. Once a second while idle it prints the detector level. Check the polarity first:
         beam on the detector  -> level should read 1 (if DET_ACTIVE_HIGH is true)
         beam blocked          -> level should read 0
       If these are swapped, flip DET_ACTIVE_HIGH. If the level jumps around with no beam,
       the detector is picking up ambient light or the pin is floating (try INPUT_PULLUP).
    3. After any burst of edges (quiet for 50 ms) it prints a summary: edge count and the time between
       edges (min / average / max, microseconds).

  How to test the detector's speed:
    Put the link sketch on the OTHER board (laser armed, beam aligned and enclosed, eyewear on, TA sign-off),
    run this sketch here, and type "burst" on the other board. A burst with HALF_US = 1000 is
    24 bytes of 1-bits: 384 edges, each 1000 us apart.
      good:  edges = 384, min/avg/max all close to 1000
      slow detector or weak signal:  fewer edges, and min/avg/max near 2000 (pulses merged or dropped)
    Normal data frames show 1000 and 2000 us gaps, so only use the numbers for the burst.
  Serial Monitor: 115200 baud.
*/
#include <Arduino.h>

const uint8_t DET_PIN = 2;            // same pin as the link sketch
const bool DET_ACTIVE_HIGH = true;    // true if the detector output is HIGH when it sees light
const uint32_t GAP_US = 50000;        // this much silence ends a burst
const uint32_t EXPECT_EDGES = 384;    // what the link sketch's "burst" produces

volatile uint32_t lastT = 0;
volatile uint32_t gaps = 0;           // number of intervals measured (= edges - 1)
volatile uint32_t dtMin = 0xFFFFFFFFUL, dtMax = 0, dtSum = 0;
volatile bool haveLast = false;

void edgeISR() {
  uint32_t t = micros();
  if (haveLast) {
    uint32_t dt = t - lastT;
    gaps++;
    dtSum += dt;
    if (dt < dtMin) dtMin = dt;
    if (dt > dtMax) dtMax = dt;
  }
  haveLast = true;
  lastT = t;
}

bool level() { return (digitalRead(DET_PIN) == HIGH) == DET_ACTIVE_HIGH; }

void setup() {
  pinMode(DET_PIN, INPUT);            // use INPUT_PULLUP if your detector output is open-collector
  pinMode(LED_BUILTIN, OUTPUT);
  Serial.begin(115200);
  delay(300);
  attachInterrupt(digitalPinToInterrupt(DET_PIN), edgeISR, CHANGE);
  Serial.println(F("Detector test ready. Idle level is printed once a second; bursts are summarised."));
}

void loop() {
  static uint32_t lastIdle = 0;
  digitalWrite(LED_BUILTIN, level() ? HIGH : LOW);

  noInterrupts();
  bool have = haveLast;
  uint32_t lt = lastT;
  interrupts();

  if (have && (uint32_t)(micros() - lt) > GAP_US) {         // burst finished: take a snapshot and reset
    noInterrupts();
    uint32_t g = gaps, mn = dtMin, mx = dtMax, sum = dtSum;
    gaps = 0; dtMin = 0xFFFFFFFFUL; dtMax = 0; dtSum = 0; haveLast = false;
    interrupts();
    uint32_t edges = g + 1;
    Serial.print(F("burst: edges="));
    Serial.print(edges);
    Serial.print(F(" (burst gives "));
    Serial.print(EXPECT_EDGES);
    Serial.print(F(")"));
    if (g) {
      Serial.print(F("  gap us min/avg/max = "));
      Serial.print(mn); Serial.print('/'); Serial.print(sum / g); Serial.print('/'); Serial.println(mx);
    } else {
      Serial.println(F("  (single edge, noise?)"));
    }
  } else if (!have && (uint32_t)(millis() - lastIdle) >= 1000) {
    lastIdle = millis();
    Serial.print(F("idle, level="));
    Serial.println(level() ? 1 : 0);
  }
}
