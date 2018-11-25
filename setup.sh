#!/bin/bash
set -eu

# fetch googletest
GOOGLETEST_VERSION='1.8.0'
echo "======== Downloading googletest version ${GOOGLETEST_VERSION} ========"
mkdir 3rdparty
curl -L https://github.com/abseil/googletest/archive/release-${GOOGLETEST_VERSION}.tar.gz > ./3rdparty/googletest.tar.gz

# Unzip
echo "======== Unarchiving googletest ========"
cd 3rdparty
tar zxvf ./googletest.tar.gz

# Build
echo "======== Building googletest ========"
cd googletest-release-${GOOGLETEST_VERSION}
cd googletest
mkdir build
cd build
cmake ../
make

# After Building
cd ../../../
rm googletest.tar.gz
echo "======== Finished!! ========"