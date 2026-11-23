/*
  850nm IR Laser Driver Test
  Toggles the laser on/off at a fixed interval
*/

const int LASER_PIN = 9;
const int STATUS_LED = LED_BUILTIN;

// Timing settings (milliseconds)
const unsigned long ON_MS = 100;
const unsigned long OFF_MS = 100;

void setup() {
  Serial.begin(115200);

  pinMode(LASER_PIN, OUTPUT);
  pinMode(STATUS_LED, OUTPUT);

  digitalWrite(LASER_PIN, LOW);
  digitalWrite(STATUS_LED, LOW);

  Serial.println("850nm IR Laser Driver");
}

void loop() {
  digitalWrite(LASER_PIN, HIGH);
  digitalWrite(STATUS_LED, HIGH);
  Serial.println("Laser ON");
  delay(ON_MS);

  digitalWrite(LASER_PIN, LOW);
  digitalWrite(STATUS_LED, LOW);
  Serial.println("Laser OFF");
  delay(OFF_MS);
}