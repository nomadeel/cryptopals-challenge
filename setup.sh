#!/bin/bash

git clone https://github.com/weidai11/cryptopp.git
cd cryptopp
make -j8
cd ..
cmake .
