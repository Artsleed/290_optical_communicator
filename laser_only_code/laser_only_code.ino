/*
  850 nm IR laser switching test
  Serial commands (115200 baud, any line ending):
    a  arm (start toggling)     d  disarm (laser off)
    f  fast: 1 ms on / 1 ms off (500 Hz, same as the link's burst)
    s  slow: 100 ms on / 100 ms off (easy to see on an LED)
*/

const uint8_t LASER_PIN = 3;           // same as the link sketch
const uint32_t FAST_US = 1000;
const uint32_t SLOW_US = 100000;

uint32_t halfUs = SLOW_US;
bool armed = false;
bool level = false;
uint32_t nextT = 0;

void setOutputs(bool on) {
  level = on;
  digitalWrite(LASER_PIN, on ? HIGH : LOW);
  digitalWrite(LED_BUILTIN, on ? HIGH : LOW);
}

void setup() {
  pinMode(LASER_PIN, OUTPUT);
  pinMode(LED_BUILTIN, OUTPUT);
  setOutputs(false);                   // laser OFF at power-up
  Serial.begin(115200);
  Serial.println(F("a=arm d=disarm f=fast(1ms) s=slow(100ms). Laser is OFF."));
}

void loop() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == 'a') { armed = true; nextT = micros(); Serial.println(F("ARMED")); }
    else if (c == 'd') { armed = false; setOutputs(false); Serial.println(F("Disarmed")); }
    else if (c == 'f') { halfUs = FAST_US; nextT = micros(); Serial.println(F("Fast: 1 ms")); }
    else if (c == 's') { halfUs = SLOW_US; nextT = micros(); Serial.println(F("Slow: 100 ms")); }
  }

  if (!armed) return;

  if ((int32_t)(micros() - nextT) >= 0) {   // no prints in here, to keep timing clean
    setOutputs(!level);
    nextT += halfUs;
  }
}