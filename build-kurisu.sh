#!/bin/bash
mkdir -p build/lib build/include
gcc -c ./kurisu/kurisu.cpp -pthread -lfmt -O2 -std=gnu++17 -Wall
ar -crv ./build/lib/libkurisu.a ./kurisu.o
rm kurisu.o
cp -p ./kurisu/kurisu.h ./build/include/

