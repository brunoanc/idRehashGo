# idRehashLinux
![Build Status](https://github.com/PowerBall253/idRehashLinux/actions/workflows/cmake.yml/badge.svg)

DOOM Eternal .resources rehasher, rewritten in C for Linux.

## Usage
First, idRehash needs to generate an idRehash.map file to get the resource hash offsets. You can generate one by running:
```
./idRehash --getoffsets
```

After that, you can rehash the resource offsets on meta.resources by running:
```
./idRehash
```

## Compiling
The project uses Cmake to compile.

First clone the repo by running:

```
git clone https://github.com/PowerBall253/idRehashLinux.git
```

Then, generate the makefile by running:
```
cd idRehashLinux
mkdir build
cd build
cmake ..
```

Finally, build with:
```
make
```

The idRehash executable will be in the "build" folder.

## Credits
* proteh and emoose: For creating the original idRehash.
