/*
* This file is part of idRehashGo (https://github.com/PowerBall253/idRehashGo).
* Copyright (C) 2023 PowerBall253
*
* idRehashGo is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* idRehashGo is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with idRehashGo. If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"github.com/dgryski/go-farm"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// #cgo linux LDFLAGS: -L./ooz -looz_linux -lstdc++ -static
// #cgo windows LDFLAGS: -L./ooz -looz_windows -lstdc++ -static
// #include "ooz/ooz.h"
import "C"

// Hash resource headers using Farmhash
func hashResourceHeaders(path string) uint64 {
	// Open file
	file, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to open %s for reading: %s\n", path, err.Error())
		return 0
	}
	defer file.Close()

	// Get start and end addresses
	startAddr := uint64(0x7C)
	var endAddr uint64

	file.Seek(0x74, io.SeekStart)
	if err = binary.Read(file, binary.LittleEndian, &endAddr); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to read from %s: %s\n", path, err.Error())
		return 0
	}
	endAddr += 4

	// Read header data to be hashed
	headersSize := endAddr - startAddr
	hashedData := make([]byte, headersSize)

	file.Seek(int64(startAddr), io.SeekStart)
	count, err := file.Read(hashedData)
	if uint64(count) != headersSize || err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to read from %s: %s\n", path, err.Error())
		return 0
	}

	// Hash header data
	hash := farm.Fingerprint64(hashedData)
	fmt.Printf("%s: %x\n", path, hash)
	return hash
}

// Get all resource files in a directory and its subdirectories
func getResourcePaths(path string) []string {
	// Create slice to store resources with capacity 100
	resourcePaths := make([]string, 0, 100)

	// Walk through directory recursively
	err := filepath.WalkDir(path, func(path string, dirEntry fs.DirEntry, err error) error {
		// Ignore errors
		if err != nil {
			return nil
		}

		// Ignore directories
		if !dirEntry.Type().IsRegular() {
			return nil
		}

		// Find resource files (except meta.resources)
		if dirEntry.Name() != "meta.resources" && strings.HasSuffix(path, ".resources") {
			resourcePaths = append(resourcePaths, path)
		}

		return nil
	})

	// Check errors
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to get resource file paths: %s\n", err.Error())
		return nil
	}

	return resourcePaths
}

// Get the offset for the given hash in meta.resources
func getResourceHashOffset(path string, decContainerMaskData []byte) uint64 {
	// Get resource header hash
	hash := hashResourceHeaders(path)
	if hash == 0 {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to get hash for %s.\n", path)
		return 0
	}

	// Convert hash to bytes (little endian)
	hashBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(hashBytes, hash)

	// Find hash offset in container mask data
	hashOffset := uint64(0)
	currentHashByte := 0

	// Traverse mask data in reverse until we find the hash bytes
	for i := len(decContainerMaskData) - 1; i >= 0; i-- {
		if decContainerMaskData[i] != hashBytes[7 - currentHashByte] {
			currentHashByte = 0
			continue
		}

		currentHashByte++
		if currentHashByte == 8 {
			hashOffset = uint64(i)
			break
		}
	}

	if hashOffset == 0 {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to get hash offset for %s.\n", path)
		return 0
	}

	return hashOffset
}

// Generate map with the resource filenames and their hash offset
func generateMap(decData []byte) int {
	// Open file
	file, err := os.Create("idRehash.map")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to open idRehash.map for writing: %s\n", err.Error())
		return 1
	}
	defer file.Close()

	// Get hash offset of each file and write it to map
	for _, path := range getResourcePaths(".") {
		hashOffset := getResourceHashOffset(path, decData)
		if hashOffset == 0 {
			fmt.Fprintf(os.Stderr, "ERROR: Faled to get hash for %s.\n", path)
			return 1
		}
		fmt.Fprintf(file, "%s;%d\n", path, hashOffset)
	}

	fmt.Println("\nidRehash.map has been successfully generated.")
	return 0
}

// Rehash offsets in meta.resources
func rehashOffsets(metaPath string, decData []byte, infoOffset int64, fileOffset int64) int {
	// Open hash offset map
	file, err := os.Open("idRehash.map")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to open idRehash.map for reading: %s\n", err.Error())
		fmt.Fprintln(os.Stderr, "Make sure to generate the hash offset map file first using the --getoffsets option.")
		return 1
	}
	defer file.Close()

	// Read offsets, one line at a time
	resourceOffsets := make(map[string]uint64, 100)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Split line with ;
		pair := strings.Split(scanner.Text(), ";")
		if len(pair) != 2 {
			continue
		}

		// Replace backslashes with slashes on path (Windows version compatibility)
		path := strings.ReplaceAll(pair[0], "\\", "/")

		// Attempt to convert second part to uint64
		offset, err := strconv.ParseUint(pair[1], 10, 64)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR: Failed to read hash from idRehash.map.")
			fmt.Fprintln(os.Stderr, "Regenerate the hash offset map file by using the --getoffsets option.")
			return 1
		}

		// Add pair to map
		resourceOffsets[path] = offset
	}

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to read from idRehash.map: %s\n", err.Error())
		fmt.Fprintln(os.Stderr, "Regenerate the hash offset map file by using the --getoffsets option.")
	}

	// Hash resource headers and update the hash value in the map
	fixedHashes := 0

	for path, offset := range resourceOffsets {
		// Get resource header hash
		if hash := hashResourceHeaders(path); hash != 0 {
			// Get old hash
			oldHash := uint64(0)

			for i := 7; i >= 0; i-- {
				oldHash <<= 8
				oldHash |= uint64(decData[offset + uint64(i)])
			}

			// Update hash
			if oldHash != hash {
				// Convert hash to bytes (little endian)
				hashBytes := make([]byte, 8)
				binary.LittleEndian.PutUint64(hashBytes, hash)

				// Set new values in data
				for i := 7; i >= 0; i-- {
					decData[offset + uint64(i)] = hashBytes[i]
				}
				fixedHashes++
				fmt.Printf("  ^ Updated from %x\n\n", oldHash)
			}
		}
	}

	// Check fixed hashes
	if fixedHashes == 0 {
		fmt.Println("\nDone, 0 hashes changed.")
		return 0
	}

	// Write the new decompressed data to meta.resources
	if writeDecompressedData(metaPath, decData, infoOffset, fileOffset) != 0 {
		return 1
	}
	fmt.Printf("\nDone, %d hashes changed.\n", fixedHashes)
	return 0
}

// Get decompressed data from meta.resources
func getDecompressedData(metaPath string) ([]byte, int64, int64) {
	// Read and decompress data from meta.resources
	meta, err := os.Open(metaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to open meta.resources for writing: %s\n", err.Error())
		return nil, 0, 0
	}
	defer meta.Close()

	// Get info offset
	var infoOffset int64
	meta.Seek(0x50, io.SeekStart)
	if err = binary.Read(meta, binary.LittleEndian, &infoOffset); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: Failed to read from meta.resources")
		return nil, 0, 0
	}

	// Get file offset
	var fileOffset int64
	meta.Seek(0x38 + infoOffset, io.SeekStart)
	if err = binary.Read(meta, binary.LittleEndian, &fileOffset); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: Failed to read from meta.resources")
		return nil, 0, 0
	}

	// Get compressed size
	var sizeZ uint64
	if err = binary.Read(meta, binary.LittleEndian, &sizeZ); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: Failed to read from meta.resources")
		return nil, 0, 0
	}

	// Get decompressed size
	var size uint64
	if err = binary.Read(meta, binary.LittleEndian, &size); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: Failed to read from meta.resources")
		return nil, 0, 0
	}

	// Get data from meta
	data := make([]byte, sizeZ)
	meta.Seek(fileOffset, io.SeekStart)
	count, err := meta.Read(data)
	if uint64(count) != sizeZ || err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: Failed to read from meta.resources")
		return nil, 0, 0
	}

	// Check if file is compressed
	if size != sizeZ {
		// Create slice for decompression
		decData := make([]byte, size + 64)

		// Decompress using Kraken
		result := (uint64)(C.Kraken_Decompress((*C.uchar)(&data[0]), (C.size_t)(sizeZ), (*C.uchar)(&decData[0]), (C.size_t)(size)))
		if result != size {
			fmt.Fprintln(os.Stderr, "ERROR: Failed to decompress meta.resources - bad file?")
			return nil, 0, 0
		}

		decData = decData[:result]
		return decData, infoOffset, fileOffset
	} else {
		return data, infoOffset, fileOffset
	}
}

// Write decompressed data to meta.resources
func writeDecompressedData(metaPath string, decData []byte, infoOffset int64, fileOffset int64) int {
	// Open meta.resources
	meta, err := os.OpenFile(metaPath, os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to open meta.resources for writing: %s\n", err.Error())
		return 1
	}
	defer meta.Close()

	// Update compressed size
	size := uint64(len(decData))
	meta.Seek(0x38 + infoOffset + 0x8, io.SeekStart)
	if err = binary.Write(meta, binary.LittleEndian, &size); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to write to meta.resources: %s\n", err.Error())
		return 1
	}

	// Clear compression flag
	zero := byte(0)
	meta.Seek(0x38 + infoOffset + 0x38, io.SeekStart)
	if err = binary.Write(meta, binary.LittleEndian, &zero); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to write to meta.resources: %s\n", err.Error())
		return 1
	}

	// Write decompressed data
	meta.Seek(fileOffset, io.SeekStart)
	count, err := meta.Write(decData)
	if uint64(count) != size || err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to write to meta.resources: %s\n", err.Error())
		return 1
	}

	return 0
}

// Program version: to be set with -ldflags="-x 'main.Version=vX.X.X'"
var Version = "dev"

// Main function
func main() {
	fmt.Printf("idRehashGo %s by PowerBall253 :)\n\n", Version)

	// Get decompressed data
	decData, infoOffset, fileOffset := getDecompressedData("meta.resources")

	if decData == nil {
		os.Exit(1)
	}

	if len(os.Args) > 1 {
		// Generate map
		if os.Args[1] == "--getoffsets" {
			os.Exit(generateMap(decData))
		}

		// Print help
		fmt.Println("Usage:")
		fmt.Printf("%s [--getoffsets]\n", os.Args[0])
		fmt.Println("\n--getoffsets\tGenerates the hash offset map file required to use this tool.")
		os.Exit(1)
	}

	// Rehash offsets in meta.resources
	os.Exit(rehashOffsets("meta.resources", decData, infoOffset, fileOffset))
}
