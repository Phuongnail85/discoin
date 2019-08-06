# How to compile the project
### RHEL
#### Install required software
```
$ sudo yum install gcc72.x86_64 gcc72-c++.x86_64 make glibc-static libxml2-devel
```
#### Install cmake 3
This step is needed only if the cmake version distributed through yum is less than 3.10.
Otherwise, simply use yum install cmake.
```
$ wget https://cmake.org/files/v3.15/cmake-3.15.1.tar.gz
$ tar jxf cmake-3.15.1.tar.gz
$ cd cmake-3.15.1/
$ ./bootstrap
$ make
$ sudo make install
```
#### Install boost
```
$ wget -c https://sourceforge.net/projects/boost/files/boost/1.70.0/boost_1_70_0.tar.gz/download
$ tar jxf boost_1_70_0.tar.bz2
$ cd boost_1_70_0
$ sudo ./bootstrap.sh --prefix=/usr/local/
$ ./b2
$ sudo ./b2 install 
```
#### Compile Discoin binaries
```
$ git clone https://github.com/discodery/discoin.git
$ cd discoin
$ cmake .
$ make
```
or with multi-threading:
```
$ make -j
```
### macOS
#### Install required software
```
$ brew install gcc cmake boost
```
#### Compile Discoin binaries
```
$ git clone https://github.com/discodery/discoin.git
$ cd discoin
$ mkdir build
$ cmake -S . -B build
$ cd build
$ make -j
```
Tested on macOS Mojave. After compile, the binaries can be found in discoin/build/src/.
