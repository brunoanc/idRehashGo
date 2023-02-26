# idRehashGo
![Build Status](https://github.com/PowerBall253/idRehashGo/actions/workflows/test.yml/badge.svg)

DOOM Eternal .resources rehasher, rewritten in Go.

## Usage
First, idRehashGo needs to generate an idRehash.map file to get the resource hash offsets. You can generate one by running:
```
./idRehash --getoffsets
```

After that, you can rehash the resource offsets on meta.resources by running:
```
./idRehash
```

## Compiling
The project requires the [go toolchain](https://go.dev/dl/) to be compiled. Additionally, a GCC toolchain such as MinGW is required on Windows.

To compile, run:

```
go build -o idRehash -ldflags="-s -w" .
```

To set a version number, build with:

```
go build -o idRehash -ldflags="-s -w -X 'main.Version=vX.Y.Z'" .
```

(replace vX.Y.Z with the version number you prefer).

Additionally, you may use [UPX](https://upx.github.io/) to compress the binary:

```
upx --best idRehash
```

## Credits
* proteh and emoose: For creating the original idRehash.
