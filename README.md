# kurisu
## Requires:  

  GCC >= 7.1(supports C++17 or above)  
  Boost (boost/operators.hpp, boost/circular_buffer.hpp)  
  [fmt](https://github.com/fmtlib/fmt)(format the log)  
&nbsp;
## Before using it you should:  
### 1. Make sure the version of g++  and gcc >= 7.1
```
Check the version:
$ g++ --version
$ gcc --version
```
### 2. Install required packages
```
Ubuntu:  
$ sudo apt install cmake make libboost-dev  
CentOS:  
$ sudo yum install cmake make boost-devel  
```
### 3. Build fmt
```
$ sh build-fmt.sh
```
&nbsp;
## How to use in your project:
### The easiest way is:  
```
#include "kurisu.hpp"
```
Yes, it can be a header-only library
### Or you can build the `static lib`:
```
$ sh build-kurisu.sh 
```
This will create a folder named `build` in the `kurisu_u` directory  
Then you should move the `include` and `lib` in the `build` folder to where they should be  
Finally:  
`#include <kurisu.h>`