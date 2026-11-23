/*
  850nm IR Laser Detector: timestamped detections only
  Interrupt-based, prints time of each detection and delta since the last
*/

const int DETECTOR_PIN = 2;            // must be an interrupt pin (D2 or D3 on Uno/Nano)
const int STATUS_LED = LED_BUILTIN;

const unsigned long DEBOUNCE_US = 10000;   // ignore re-triggers within 10 ms (noise filter)

const int BUF_SIZE = 32;
volatile unsigned long stamps[BUF_SIZE];
volatile byte head = 0;
byte tail = 0;
volatile unsigned long lastAcceptedUs = 0;

unsigned long prevDetectUs = 0;
bool havePrev = false;

void onDetect() {
  unsigned long now = micros();
  if (now - lastAcceptedUs < DEBOUNCE_US) return;   // reject noise bursts
  lastAcceptedUs = now;

  byte next = (head + 1) % BUF_SIZE;
  if (next != tail) {                               // drop if buffer full
    stamps[head] = now;
    head = next;
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(DETECTOR_PIN, INPUT_PULLUP);
  pinMode(STATUS_LED, OUTPUT);

  // Detector pulls LOW when it sees the laser -> trigger on FALLING edge
  attachInterrupt(digitalPinToInterrupt(DETECTOR_PIN), onDetect, FALLING);

  Serial.println("Ready. Format: detect_time_ms, delta_ms");
}

void loop() {
  while (tail != head) {
    noInterrupts();
    unsigned long t = stamps[tail];
    tail = (tail + 1) % BUF_SIZE;
    interrupts();

    Serial.print(t / 1000.0, 3);               // absolute time since boot, ms
    Serial.print(", ");
    if (havePrev) {
      Serial.println((t - prevDetectUs) / 1000.0, 3);   // delta, ms
    } else {
      Serial.println("-");
    }
    prevDetectUs = t;
    havePrev = true;

    digitalWrite(STATUS_LED, !digitalRead(STATUS_LED));  // toggle LED per detection
  }
}