# How to compile the project
### RHEL
#### Install required software
```
$ sudo yum install gcc72.x86_64 gcc72-c++.x86_64 make cmake glibc-static libxml2-devel 
```
#### Install boost
```
$ wget -c http://sourceforge.net/projects/boost/files/boost/1.66.0/boost_1_66_0.tar.bz2
$ tar jxf boost_1_66_0.tar.bz2
$ cd boost_1_66_0
$ sudo ./bootstrap.sh --prefix=/usr/local/
$ ./b2
$ sudo ./b2 install 
```
#### Compile Discoin binaries
```
$ git clone https://github.com/discodery/discoin.git
$ cd discoin
$ cmake .
$ make -j
```
### macOS
#### Install required software
```
$ brew install gcc cmake boost
```
#### Compile Discoin binaries
```
$ git clone https://github.com/flodaq/discoin.git
$ cd discoin
$ mkdir build
$ cmake -S . -B build
$ cd build
$ make -j
```
Tested on macOS Mojave. After compile, the binaries can be found in discoin/build/src/.
