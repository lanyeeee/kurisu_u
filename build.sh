#!/bin/bash
sudo apt install cmake make libboost-dev
unzip fmt.zip && cd fmt
mkdir _build && cd _build
cmake ..

make -j$(nproc)
sudo make install
cd ../.. && rm -rf fmt/

mkdir -p build/lib build/include
gcc -c ./kurisu/kurisu.cpp -pthread -lfmt -O2 -std=gnu++17 -Wall
ar -crv ./build/lib/libkurisu.a ./kurisu.o
rm kurisu.o
cp -p ./kurisu/kurisu.h ./build/include/

