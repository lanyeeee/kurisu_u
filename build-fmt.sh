#!/bin/bash
sudo echo start
unzip fmt.zip && cd fmt
mkdir _build && cd _build
cmake ..

make -j$(nproc)
sudo make install
cd ../.. && rm -rf fmt/

