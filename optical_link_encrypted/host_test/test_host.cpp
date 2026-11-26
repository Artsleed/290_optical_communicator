// Host-side test for secure_payload (same source files as the sketch).
#include "secure_payload.cpp"      // include the .cpp so the static Heatshrink helpers are testable
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

static const uint8_t KEY[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static int fails = 0;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL line %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static std::string gen(int kind, int len) {
  std::string s;
  const char *words[] = {"the ", "laser ", "link ", "hello ", "ELEC290 ", "message ", "test ", "ok "};
  for (int i = 0; i < len; i++) {
    switch (kind) {
      case 0: s += (char)(32 + rand() % 95); break;                       // random printable
      case 1: s += (char)(rand() % 256); break;                           // random binary (includes 0x00)
      case 2: s += 'A'; break;                                            // all same
      case 3: s += "ab"[i & 1]; break;                                    // periodic
      case 4: { if (i == 0 || s.size() >= (size_t)len) break; }           // word salad (below)
      default: break;
    }
  }
  if (kind == 4) { s.clear(); while ((int)s.size() < len) s += words[rand() % 8]; s.resize(len); }
  return s;
}

static void hex(const uint8_t *p, int n) { for (int i = 0; i < n; i++) printf("%02x", p[i]); }

int main() {
  srand(12345);
  // ---- 1. round trips ----
  long cnt = 0, comp = 0, saved = 0, wasteIfAlways = 0;
  for (int iter = 0; iter < 20000; iter++) {
    int kind = iter % 5, len = 1 + rand() % TEXT_MAX;
    std::string t = gen(kind, len);
    uint8_t out[PAYLOAD_MAX]; bool c = false;
    uint32_t ctr = (uint32_t)rand() * 7919u; uint8_t sender = rand() & 1, sess = rand();
    uint8_t sl = sp_seal(KEY, sender, ctr, sess, (const uint8_t *)t.data(), (uint8_t)t.size(), out, &c);
    CHECK(sl > SP_OVERHEAD && sl <= PAYLOAD_MAX, "len %d", sl);
    CHECK(sl <= t.size() + SP_OVERHEAD, "payload bigger than raw+overhead: %d vs %zu", sl, t.size());
    uint8_t back[TEXT_MAX + 1]; uint8_t who = 99; uint32_t bc = 0;
    int16_t r = sp_open(KEY, sess, out, sl, back, &who, &bc);
    CHECK(r == (int)t.size() && memcmp(back, t.data(), t.size()) == 0, "roundtrip kind %d len %d r=%d", kind, len, r);
    CHECK(who == sender && bc == ctr, "header fields");
    cnt++; if (c) { comp++; saved += (long)t.size() - (sl - SP_OVERHEAD); }
  }
  printf("round trips: %ld, compressed in %ld (%.0f%%), avg bytes saved when compressed: %.1f\n", cnt, comp, 100.0*comp/cnt, comp ? (double)saved/comp : 0.0);

  // ---- 2. tamper: every single-bit flip in the payload must be rejected ----
  const char *samples[] = {"HELLO ELEC290 HELLO ELEC290", "hi", "The quick brown fox jumps over the lazy dog. The quick brown fox!"};
  for (const char *s : samples) {
    uint8_t out[PAYLOAD_MAX]; bool c; uint8_t n = strlen(s);
    uint8_t sl = sp_seal(KEY, 0, 1000, 7, (const uint8_t *)s, n, out, &c);
    int rejected = 0, total = 0;
    for (int bit = 0; bit < sl * 8; bit++) {
      uint8_t bad[PAYLOAD_MAX]; memcpy(bad, out, sl); bad[bit / 8] ^= 1 << (bit % 8);
      uint8_t back[TEXT_MAX + 1], who; uint32_t bc;
      int16_t r = sp_open(KEY, 7, bad, sl, back, &who, &bc);
      total++; if (r < 0) rejected++;
    }
    printf("tamper \"%.20s...\": %d/%d single-bit flips rejected (payload %d B, %s)\n", s, rejected, total, sl, c ? "compressed" : "raw");
    CHECK(rejected == total, "some bit flips accepted");
    // wrong session / wrong key / truncated
    uint8_t back[TEXT_MAX + 1], who; uint32_t bc;
    CHECK(sp_open(KEY, 8, out, sl, back, &who, &bc) < 0, "wrong session accepted");
    uint8_t k2[16]; memcpy(k2, KEY, 16); k2[3] ^= 1;
    CHECK(sp_open(k2, 7, out, sl, back, &who, &bc) < 0, "wrong key accepted");
    CHECK(sp_open(KEY, 7, out, sl - 1, back, &who, &bc) < 0, "truncated accepted");
    CHECK(sp_open(KEY, 7, out, SP_OVERHEAD, back, &who, &bc) < 0, "empty body accepted");
  }

  // ---- 3. decompress-bomb: authenticated but expands past 100 bytes must be rejected, not overflow ----
  {
    std::string big(300, 'A'); // compress 300 bytes directly with the same Heatshrink settings
    heatshrink_encoder_reset(&hse);
    size_t sunk = 0, o = 0, cn; uint8_t buf[256];
    size_t k=0;
    while (sunk < big.size()) { heatshrink_encoder_sink(&hse, (uint8_t*)big.data()+sunk, big.size()-sunk, &k); sunk += k;
      HSE_poll_res pr; do { pr = heatshrink_encoder_poll(&hse, buf+o, sizeof(buf)-o, &cn); o += cn; } while (pr == HSER_POLL_MORE); }
    while (heatshrink_encoder_finish(&hse) == HSER_FINISH_MORE) { HSE_poll_res pr; do { pr = heatshrink_encoder_poll(&hse, buf+o, sizeof(buf)-o, &cn); o += cn; } while (pr == HSER_POLL_MORE); }
    printf("bomb: 300 bytes of 'A' -> %zu compressed bytes\n", o);
    uint8_t out[TEXT_MAX + 1 + 64];
    memset(out + TEXT_MAX + 1, 0xEE, 64);
    int16_t r = hsDecompress(buf, (uint8_t)o, out);
    CHECK(r == -1, "bomb accepted r=%d", r);
    bool intact = true; for (int i = TEXT_MAX + 1; i < TEXT_MAX + 1 + 64; i++) if (out[i] != 0xEE) intact = false;
    CHECK(intact, "decompressor wrote past TEXT_MAX+1");
  }
  // random garbage into the decompressor must never crash or overflow (ASan/UBSan are on)
  for (int i = 0; i < 20000; i++) {
    uint8_t g[PAYLOAD_MAX], out[TEXT_MAX + 1]; int n = 1 + rand() % 100;
    for (int j = 0; j < n; j++) g[j] = rand();
    int16_t r = hsDecompress(g, n, out); CHECK(r == -1 || (r >= 1 && r <= TEXT_MAX), "garbage r=%d", r);
  }

  // ---- 4. input validation ----
  { uint8_t out[PAYLOAD_MAX]; bool c; const uint8_t t[1] = {'x'}; uint8_t big[TEXT_MAX + 1] = {0};
    CHECK(sp_seal(KEY, 0, 0, 0, t, 0, out, &c) == 0, "empty accepted");
    CHECK(sp_seal(KEY, 0, 0, 0, big, TEXT_MAX + 1, out, &c) == 0, "101 bytes accepted");
    CHECK(sp_seal(KEY, 2, 0, 0, t, 1, out, &c) != 0 ? false : true, "sender 2 should be rejected");
    uint8_t full[TEXT_MAX]; for (int i = 0; i < TEXT_MAX; i++) full[i] = rand();
    uint8_t sl = sp_seal(KEY, 1, 5, 9, full, TEXT_MAX, out, &c);
    CHECK(sl == TEXT_MAX + SP_OVERHEAD, "incompressible 100 B should be raw: %d", sl);
  }

  // ---- 5. known-answer vectors for cross-checking against the python 'ascon' package ----
  { const char *s = "HELLO ELEC290 HELLO ELEC290"; uint8_t out[PAYLOAD_MAX]; bool c;
    uint8_t sl = sp_seal(KEY, 1, 0x01020304, 0x55, (const uint8_t *)s, strlen(s), out, &c);
    printf("KAT1 compressed=%d payload=", c); hex(out, sl); printf("\n");
    const char *s2 = "hi there"; sl = sp_seal(KEY, 0, 7, 0x10, (const uint8_t *)s2, strlen(s2), out, &c);
    printf("KAT2 compressed=%d payload=", c); hex(out, sl); printf("\n"); }

  printf("%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
  return fails ? 1 : 0;
}
