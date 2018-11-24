#!/bin/bash -eu

cd 3rdparty/googletest-release/googletest
mkdir build
cd build
cmake ../
make