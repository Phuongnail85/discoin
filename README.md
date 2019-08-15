# How to run the release binaries
To run the pre-compiled binaries, some prerequisites can be necessary to install.
### Ubuntu 16.04
```
sudo add-apt-repository ppa:mhier/libboost-latest
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt update
sudo apt install libboost1.70 g++-7 -y
```
# How to compile the project
###  Ubuntu
#### 1. Install required software
```
sudo apt-get install build-essential libpthread-stubs0-dev
```
#### 2. Install gcc7 and cmake
Ubuntu 18.04
```
sudo apt-get install g++ cmake
```
Ubuntu 16.04
```
sudo apt-get install -y software-properties-common
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt update
sudo apt install g++-7 -y
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 60 --slave /usr/bin/g++ g++ /usr/bin/g++-7 
sudo update-alternatives --config gcc

sudo apt purge --auto-remove cmake
wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | sudo apt-key add -
sudo apt-add-repository 'deb https://apt.kitware.com/ubuntu/ xenial main'
sudo apt update
sudo apt install cmake
```
#### 3. Install libboost
```
sudo add-apt-repository ppa:mhier/libboost-latest
sudo apt update
sudo apt install libboost1.70-dev
```
#### 4. Download and install the Discoin binaries
```
git clone https://github.com/discodery/discoin.git
cd discoin
cmake .
```
Compile in a single thread:
```
make
```
Or compile with multi-threading:
```
make -j
```
### RHEL
### 1. Install the required software
```
sudo yum install gcc72.x86_64 gcc72-c++.x86_64 make glibc-static libxml2-devel
```
### 2. Install cmake 3
If the cmake version distributed through yum is equal or above than 3.10:
```
sudo yum install cmake
```
Otherwise, download and compile cmake:
```
wget https://cmake.org/files/v3.15/cmake-3.15.1.tar.gz
tar xzf cmake-3.15.1.tar.gz
cd cmake-3.15.1/
./bootstrap
make
sudo make install
```
#### 3. Compile and install libboost manually
```
wget -c https://dl.bintray.com/boostorg/release/1.70.0/source/boost_1_70_0.tar.bz2
tar jxf boost_1_70_0.tar.bz2
cd boost_1_70_0
sudo ./bootstrap.sh --prefix=/usr/local/
./b2
sudo ./b2 install
```
#### 4. Download and install the Discoin binaries
Same as for Ubuntu (see above).
### macOS
#### 1. Install the required software
```
brew install gcc cmake boost
```
#### 2. Download and compile the Discoin binaries
```
git clone https://github.com/discodery/discoin.git
cd discoin
mkdir build
cmake -S . -B build
cd build
make -j
```
Tested on macOS Mojave. After compile, the binaries can be found in discoin/build/src/.
### Windows 10
#### Prerequisites
Install Visual Studio Community 2019.
#### 1. Download the Discoin sources
```
git clone https://github.com/discodery/discoin
cd discoin
```
#### 2. Setup vcpkg
```
git clone https://github.com/Microsoft/vcpkg
cd vcpkg 
bootstrap-vcpkg.bat
vcpkg integrate install
vcpkg install boost:x64-windows
```
#### 3. Setup Visual Studio CMake
In Visual Studio, click go to "Project > CryptoNote CMake parameters".
Create a new build configuration of type x64-Release.
Copy/paste the following line in "CMake command arguments".
```
-DCMAKE_TOOLCHAIN_FILE=./vcpkg/scripts/buildsystems/vcpkg.cmake
```
Now go to "Generate > Generate all".