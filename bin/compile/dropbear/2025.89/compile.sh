#!/usr/bin/env bash
set -e

### --- Install build dependencies (single line) ---
apt-get update && apt-get install -y --no-install-recommends build-essential zlib1g-dev libpam0g-dev ca-certificates wget

### --- Build Dropbear ---
wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2025.89.tar.bz2
tar xjf dropbear-2025.89.tar.bz2
cd dropbear-2025.89

sed -i 's/^#define DROPBEAR_DH_GROUP14_SHA1 0/#define DROPBEAR_DH_GROUP14_SHA1 1/' src/default_options.h

./configure
# For PAM:
# ./configure --enable-pam

make -j"$(nproc)"
make
for f in dropbear dropbearkey dropbearconvert dbclient; do cp "./$f" "/usr/sbin/$f" && chmod +x "/usr/sbin/$f"; done

#find /usr/local -type l ! -exec test -e {} \;
#hash -r

### --- Cleanup sources ---
cd ..
rm -rf dropbear-2025.89 dropbear-2025.89.tar.bz2

### --- Remove build dependencies (single line) ---
apt-get purge -y build-essential zlib1g-dev libpam0g-dev && apt-get autoremove -y && apt-get clean && rm -rf /var/lib/apt/lists/*
