# kurisu
## Requires:  

  GCC >= 7.1(supports C++17 or above)  
  [fmt](https://github.com/fmtlib/fmt)(format the log)  
&nbsp;
## Before using it you should:  
### 1. Make sure the version of g++  and gcc >= 7.1
```
Check the g++/gcc version:
$ g++ --version
$ gcc --version
```
### 2. Install required packages
```
Ubuntu:  
$ sudo apt install cmake make
CentOS:  
$ sudo yum install cmake make
```    

&nbsp;
## Build
### build with `cmake`
make sure you are in root directory `kurisu_u`
```
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```