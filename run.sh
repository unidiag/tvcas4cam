#!/bin/sh

rm tvcas4cam

# apt install libssl-dev libdvbcsa-dev
gcc tvcas4cam.c -o tvcas4cam -static -lcrypto -ldvbcsa
./tvcas4cam
