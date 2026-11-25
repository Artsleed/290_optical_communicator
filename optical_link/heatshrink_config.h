#ifndef HEATSHRINK_CONFIG_H
#define HEATSHRINK_CONFIG_H

/* Static allocation: no malloc on the ATmega4809. */
#ifndef HEATSHRINK_DYNAMIC_ALLOC
#define HEATSHRINK_DYNAMIC_ALLOC 0
#endif

#if HEATSHRINK_DYNAMIC_ALLOC
    #define HEATSHRINK_MALLOC(SZ) malloc(SZ)
    #define HEATSHRINK_FREE(P, SZ) free(P)
#else
    /* Messages are at most 100 bytes, so a 128-byte window (2^7) already covers a whole message.
       Encoder RAM ~ 2*2^W bytes, decoder RAM ~ 2^W + input buffer. Both ends MUST use the same W and L. */
    #ifndef HEATSHRINK_STATIC_INPUT_BUFFER_SIZE
    #define HEATSHRINK_STATIC_INPUT_BUFFER_SIZE 16
    #endif
    #ifndef HEATSHRINK_STATIC_WINDOW_BITS
    #define HEATSHRINK_STATIC_WINDOW_BITS 7
    #endif
    #ifndef HEATSHRINK_STATIC_LOOKAHEAD_BITS
    #define HEATSHRINK_STATIC_LOOKAHEAD_BITS 4
    #endif
#endif

#define HEATSHRINK_DEBUGGING_LOGS 0

/* The search index only speeds up compression and costs 2*2^(W+1) bytes of RAM. Not needed here. */
#ifndef HEATSHRINK_USE_INDEX
#define HEATSHRINK_USE_INDEX 0
#endif

#endif
