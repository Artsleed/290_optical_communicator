#include "secure_payload.h"
#include <string.h>
#include <Ascon128.h>      // Library Manager: "Ascon128" by Hauke D (Ascon-128 v1.2 from Rhys Weatherley's CryptoLW)

extern "C" {               // Heatshrink is plain C
#include "heatshrink_encoder.h"
#include "heatshrink_decoder.h"
}

static const uint8_t META_COMPRESSED = 0x01;
static const uint8_t META_SENDER1    = 0x02;
static const uint8_t META_RESERVED   = 0xFC;
static const uint8_t COMP_BUF        = 128;   // worst case for 100 input bytes is 113

static heatshrink_encoder hse;
static heatshrink_decoder hsd;

// Compress in[0..n) into out[COMP_BUF]. Returns false on any library error.
static bool hsCompress(const uint8_t *in, uint8_t n, uint8_t *out, uint8_t *outLen) {
  heatshrink_encoder_reset(&hse);
  size_t sunk = 0, o = 0, cnt = 0;
  while (sunk < n) {
    if (heatshrink_encoder_sink(&hse, (uint8_t *)in + sunk, n - sunk, &cnt) < 0) return false;
    sunk += cnt;
    HSE_poll_res pr;
    do {
      pr = heatshrink_encoder_poll(&hse, out + o, COMP_BUF - o, &cnt);
      if (pr < 0) return false;
      o += cnt;
    } while (pr == HSER_POLL_MORE && o < COMP_BUF);
  }
  HSE_finish_res fr;
  uint8_t guard = 0;
  do {
    fr = heatshrink_encoder_finish(&hse);
    if (fr < 0) return false;
    if (fr == HSER_FINISH_MORE) {
      HSE_poll_res pr;
      do {
        pr = heatshrink_encoder_poll(&hse, out + o, COMP_BUF - o, &cnt);
        if (pr < 0) return false;
        o += cnt;
      } while (pr == HSER_POLL_MORE && o < COMP_BUF);
    }
  } while (fr == HSER_FINISH_MORE && ++guard < 8);
  if (fr != HSER_FINISH_DONE || o >= COMP_BUF) return false;
  *outLen = (uint8_t)o;
  return true;
}

// Decompress in[0..n) into out[TEXT_MAX + 1]. Returns the length, or -1 on error or if the result
// would be longer than TEXT_MAX (the spare byte is how overflow is detected).
static int16_t hsDecompress(const uint8_t *in, uint8_t n, uint8_t *out) {
  heatshrink_decoder_reset(&hsd);
  size_t sunk = 0, o = 0, cnt = 0;
  uint16_t guard = 0;
  while (sunk < n) {
    if (heatshrink_decoder_sink(&hsd, (uint8_t *)in + sunk, n - sunk, &cnt) < 0) return -1;
    sunk += cnt;
    HSD_poll_res pr;
    do {
      pr = heatshrink_decoder_poll(&hsd, out + o, (TEXT_MAX + 1) - o, &cnt);
      if (pr < 0) return -1;
      o += cnt;
      if (o > TEXT_MAX) return -1;
    } while (pr == HSDR_POLL_MORE);
    if (cnt == 0 && sunk < n && ++guard > 1000) return -1;   // no progress: bail out
  }
  HSD_finish_res fr;
  guard = 0;
  do {
    fr = heatshrink_decoder_finish(&hsd);
    if (fr < 0) return -1;
    if (fr == HSDR_FINISH_MORE) {
      HSD_poll_res pr;
      do {
        pr = heatshrink_decoder_poll(&hsd, out + o, (TEXT_MAX + 1) - o, &cnt);
        if (pr < 0) return -1;
        o += cnt;
        if (o > TEXT_MAX) return -1;
      } while (pr == HSDR_POLL_MORE);
    }
  } while (fr == HSDR_FINISH_MORE && ++guard < 64);
  if (fr != HSDR_FINISH_DONE || o == 0) return -1;
  return (int16_t)o;
}

static void makeIv(uint8_t iv[16], uint8_t sender, uint32_t ctr) {
  memset(iv, 0, 16);
  iv[0] = sender & 1;
  iv[1] = (uint8_t)(ctr >> 24); iv[2] = (uint8_t)(ctr >> 16);
  iv[3] = (uint8_t)(ctr >> 8);  iv[4] = (uint8_t)ctr;
}

uint8_t sp_seal(const uint8_t key[16], uint8_t sender, uint32_t ctr, uint8_t session,
                const uint8_t *text, uint8_t n, uint8_t *out, bool *wasCompressed) {
  if (n == 0 || n > TEXT_MAX || sender > 1) return 0;

  // 1. Compress first (ciphertext is incompressible). Keep the raw text if compression does not help:
  //    Heatshrink spends 9 bits per literal byte, so short or non-repetitive text gets longer.
  uint8_t comp[COMP_BUF];
  uint8_t cn = 0;
  bool useComp = hsCompress(text, n, comp, &cn) && cn < n;
  const uint8_t *body = useComp ? comp : text;
  uint8_t m = useComp ? cn : n;

  // 2. Header, then encrypt + tag.
  uint8_t meta = (useComp ? META_COMPRESSED : 0) | (sender ? META_SENDER1 : 0);
  out[0] = meta;
  out[1] = (uint8_t)(ctr >> 24); out[2] = (uint8_t)(ctr >> 16);
  out[3] = (uint8_t)(ctr >> 8);  out[4] = (uint8_t)ctr;

  uint8_t iv[16], ad[2] = { meta, session };
  makeIv(iv, sender, ctr);
  Ascon128 c;
  c.setKey(key, 16);
  c.setIV(iv, 16);
  c.addAuthData(ad, sizeof(ad));
  c.encrypt(out + SP_HDR, body, m);
  c.computeTag(out + SP_HDR + m, TAG_LEN);
  c.clear();

  memset(comp, 0, sizeof(comp));
  if (wasCompressed) *wasCompressed = useComp;
  return (uint8_t)(SP_HDR + m + TAG_LEN);
}

int16_t sp_open(const uint8_t key[16], uint8_t session, const uint8_t *p, uint8_t len,
                uint8_t *text, uint8_t *sender, uint32_t *counter) {
  if (len <= SP_OVERHEAD || len > PAYLOAD_MAX) return -1;
  uint8_t meta = p[0];
  if (meta & META_RESERVED) return -1;
  uint8_t who = (meta & META_SENDER1) ? 1 : 0;
  uint32_t ctr = ((uint32_t)p[1] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 8) | p[4];
  uint8_t m = len - SP_OVERHEAD;

  uint8_t iv[16], ad[2] = { meta, session };
  uint8_t pt[TEXT_MAX + 1];
  makeIv(iv, who, ctr);
  Ascon128 c;
  c.setKey(key, 16);
  c.setIV(iv, 16);
  c.addAuthData(ad, sizeof(ad));
  c.decrypt(pt, p + SP_HDR, m);
  bool ok = c.checkTag(p + SP_HDR + m, TAG_LEN);
  c.clear();
  if (!ok) { memset(pt, 0, sizeof(pt)); return -1; }       // plaintext is only released after the tag checks out

  int16_t r;
  if (meta & META_COMPRESSED) {
    r = hsDecompress(pt, m, text);
  } else {
    memcpy(text, pt, m);
    r = m;
  }
  memset(pt, 0, sizeof(pt));
  if (r < 0) { memset(text, 0, TEXT_MAX + 1); return -1; }
  *sender = who;
  *counter = ctr;
  return r;
}
