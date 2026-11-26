#!/bin/sh
# PC-side test of compress -> encrypt -> decrypt -> decompress (needs gcc/g++).
# Usage: ./run_tests.sh /path/to/Arduino/libraries/Ascon128/src
set -e
A="${1:?give the path to the Ascon128 library's src folder}"
S="$(dirname "$0")/../optical_link"
mkdir -p obj
for f in heatshrink_encoder heatshrink_decoder; do gcc -c -O1 -g -fsanitize=address,undefined -I"$S" "$S/$f.c" -o obj/$f.o; done
for f in Ascon128 AuthenticatedCipher Cipher Crypto; do g++ -c -O1 -g -fsanitize=address,undefined -I"$A" "$A/$f.cpp" -o obj/$f.o; done
g++ -std=c++11 -O1 -g -fsanitize=address,undefined -I"$S" -I"$A" test_host.cpp obj/*.o -o test_host
./test_host
