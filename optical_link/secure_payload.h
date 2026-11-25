// secure_payload: compress (Heatshrink) then encrypt + authenticate (Ascon-128) one message.
// No Arduino dependencies, so it can be unit-tested on a PC.
//
// DATA payload on the air:
//   [meta 1][counter 4, big-endian][ciphertext m][tag 16]
//   meta bit0 = body is Heatshrink-compressed, bit1 = sender ID (0 or 1), other bits must be 0
//   nonce (16 B) = [sender][counter x4][11 zero bytes], never sent, rebuilt from meta + counter
//   associated data (authenticated, not encrypted) = [meta][session]
#pragma once
#include <stdint.h>
#include <stddef.h>

constexpr uint8_t TEXT_MAX    = 100;                       // characters per message
constexpr uint8_t SP_HDR      = 5;                         // meta + counter
constexpr uint8_t TAG_LEN     = 16;                        // Ascon-128 tag
constexpr uint8_t SP_OVERHEAD = SP_HDR + TAG_LEN;          // 21 bytes added to every message
constexpr uint8_t PAYLOAD_MAX = TEXT_MAX + SP_OVERHEAD;    // 121

// Builds the DATA payload into out[PAYLOAD_MAX]. Returns its length, or 0 if the input is invalid.
// The caller must never reuse a (sender, counter) pair with the same key.
uint8_t sp_seal(const uint8_t key[16], uint8_t sender, uint32_t counter, uint8_t session,
                const uint8_t *text, uint8_t n, uint8_t *out, bool *wasCompressed);

// Verifies the tag, decrypts and decompresses. text must have room for TEXT_MAX + 1 bytes.
// Returns the plaintext length, or -1 if anything is wrong (bad tag, bad format, bad compressed data).
// On -1 nothing in text is valid.
int16_t sp_open(const uint8_t key[16], uint8_t session, const uint8_t *payload, uint8_t len,
                uint8_t *text, uint8_t *sender, uint32_t *counter);
