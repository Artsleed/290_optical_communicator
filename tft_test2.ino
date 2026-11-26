/*
  TFT X + CHECKMARK - 2.0" SPI TFT LCD (ST7789, 240x320)
  Board: Arduino Uno WiFi Rev2 (same wiring as the test sketch)

  Shows a big red X, then a big green checkmark, alternating.
  Set SIDE_BY_SIDE to 1 to show both at once instead.
*/

#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ST7789.h>

#define TFT_CS   10
#define TFT_DC    9
#define TFT_RST   8
#define TFT_MOSI 11
#define TFT_SCLK 13

#define SIDE_BY_SIDE 0     // 0 = alternate full size, 1 = both on screen together
#define HOLD_MS   2000     // how long each symbol stays up when alternating

Adafruit_ST7789 tft = Adafruit_ST7789(TFT_CS, TFT_DC, TFT_MOSI, TFT_SCLK, TFT_RST);

// Draws a line 'w' pixels thick with rounded ends
void thickLine(int16_t x0, int16_t y0, int16_t x1, int16_t y1, int16_t w, uint16_t color) {
  float dx = x1 - x0, dy = y1 - y0;
  float len = sqrt(dx * dx + dy * dy);
  if (len == 0) return;
  float ox = -dy / len * w / 2.0;   // offset perpendicular to the line
  float oy =  dx / len * w / 2.0;

  int16_t ax = x0 + ox, ay = y0 + oy;
  int16_t bx = x0 - ox, by = y0 - oy;
  int16_t cx = x1 - ox, cy = y1 - oy;
  int16_t ex = x1 + ox, ey = y1 + oy;

  tft.fillTriangle(ax, ay, bx, by, cx, cy, color);
  tft.fillTriangle(ax, ay, cx, cy, ex, ey, color);
  tft.fillCircle(x0, y0, w / 2, color);   // round caps
  tft.fillCircle(x1, y1, w / 2, color);
}

// Red X centred on (cx, cy); 'size' is half the width of the X
void drawX(int16_t cx, int16_t cy, int16_t size, int16_t thick) {
  thickLine(cx - size, cy - size, cx + size, cy + size, thick, ST77XX_RED);
  thickLine(cx - size, cy + size, cx + size, cy - size, thick, ST77XX_RED);
}

// Green checkmark centred on (cx, cy); 'size' is half its width
void drawCheck(int16_t cx, int16_t cy, int16_t size, int16_t thick) {
  int16_t lx = cx - size,         ly = cy + size / 6;       // left tip
  int16_t bx = cx - size / 3,     by = cy + size * 3 / 4;   // bottom corner
  int16_t rx = cx + size,         ry = cy - size * 3 / 4;   // right tip
  thickLine(lx, ly, bx, by, thick, ST77XX_GREEN);
  thickLine(bx, by, rx, ry, thick, ST77XX_GREEN);
}

void setup() {
  // If your module has BLK instead of CS, use: tft.init(240, 320, SPI_MODE3);
  tft.init(240, 320);
  tft.setRotation(1);              // landscape, 320 x 240
  // tft.invertDisplay(false);     // uncomment if colours look inverted

  tft.fillScreen(ST77XX_BLACK);

#if SIDE_BY_SIDE
  drawX(80, 120, 55, 22);
  drawCheck(240, 120, 60, 22);
#endif
}

void loop() {
#if !SIDE_BY_SIDE
  tft.fillScreen(ST77XX_BLACK);
  drawX(160, 120, 85, 32);
  delay(HOLD_MS);

  tft.fillScreen(ST77XX_BLACK);
  drawCheck(160, 120, 95, 32);
  delay(HOLD_MS);
#endif
}