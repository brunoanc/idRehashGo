/*
* idRehashLinux
* Copyright (C) 2021 PowerBall253
*
* idRehashLinux is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* idRehashLinux is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with idRehashLinux. If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include "cvector/cvector.h"
#include "cvector/cvector_utils.h"
#include "farmhash-c/farmhash.h"
#include "fts/fts.h"
#include "ooz/ooz.h"

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

struct resource_map_entry {
    char *resource_path;
    size_t offset;
};

// Hashes the resource headers with farmhash64
bool hash_resource_headers(const char *path, uint64_t *hash)
{
    FILE *f = fopen(path, "rb");

    if (!f) {
        eprintf("ERROR: Failed to open %s for reading: %s\n", path, strerror(errno));
        return false;
    }

    fseek(f, 0x74, SEEK_SET);

    uint64_t start_addr = 0x7C;
    uint64_t end_addr = 0;

    if (fread(&end_addr, 8, 1, f) != 1) {
        eprintf("ERROR: Failed to read from %s: %s\n", path, strerror(errno));
        fclose(f);
        return false;
    }

    end_addr += 4;

    size_t headers_size = end_addr - start_addr;

    char *hashed_data = malloc(headers_size);
    fseek(f, (long)start_addr, SEEK_SET);

    if (fread(hashed_data, 1, headers_size, f) != headers_size) {
        eprintf("ERROR: Failed to read from %s: %s\n", path, strerror(errno));
        fclose(f);
        return false;
    }

    fclose(f);

    *hash = farmhash_fingerprint64(hashed_data, headers_size);
    printf("%s: %lx\n", path, *hash);

    free(hashed_data);
    return true;
}

// Gets all the resource file paths
cvector_vector_type(char*) get_resource_paths(char *filepath)
{
    char *filepath_array[2] = { filepath, NULL };
    cvector_vector_type(char*) resource_files = NULL;
    FTS *ftsp;
    FTSENT *p, *chp;

    cvector_reserve(resource_files, 100);
    ftsp = fts_open(filepath_array, FTS_COMFOLLOW | FTS_LOGICAL | FTS_NOCHDIR, NULL);

    if (!ftsp) {
        perror("ERROR: Failed to open base directory");
        return NULL;
    }

    chp = fts_children(ftsp, 0);

    if (!chp) {
        eprintf("ERROR: Failed to open %s directory: %s\n", filepath, strerror(errno));
        return NULL;
    }

    while ((p = fts_read(ftsp)) != NULL) {
        if (p->fts_info != FTS_F)
            continue;

        char *filename = strrchr(p->fts_path, '/') + 1;

        if (!filename)
            filename = p->fts_path;
        
        char *extension = strrchr(p->fts_path, '.');

        if (!extension)
            extension = filename;

        if (strcmp(extension, ".resources") == 0 && strcmp(filename, "meta.resources") != 0) {
            char *resource_path = strdup(p->fts_path);
            cvector_push_back(resource_files, resource_path);
        }
    }

    fts_close(ftsp);
    return resource_files;
}

// Gets the offset for the hashes in the given resource
size_t get_resource_hash_offset(const char *path, const unsigned char *dec_container_mask_data, const size_t dec_size)
{
    uint64_t hash = 0;

    if (!hash_resource_headers(path, &hash)) {
        eprintf("ERROR: Failed to get hash for %s.\n", path);
        return 0;
    }

    unsigned char hash_bytes[sizeof(hash)];
    memcpy(hash_bytes, &hash, sizeof(hash));

    size_t hash_offset = 0;
    int current_hash_byte = 0;

    for (ssize_t i = dec_size - 1; i >= 0; i--) {
        if (dec_container_mask_data[i] != hash_bytes[7 - current_hash_byte]) {
            current_hash_byte = 0;
            continue;
        }

        current_hash_byte++;

        if (current_hash_byte == 8) {
            hash_offset = i;
            break;
        }
    }

    if (hash_offset == 0) {
        eprintf("ERROR: Failed to get offset for %s.\n", path);
        return 0;
    }

    return hash_offset;
}

// Generates the map with the resource filenames and their hash offset
bool generate_map(unsigned char *dec_data, const size_t size)
{
    FILE *hash_offset_map = fopen("idRehash.map", "w");

    if (!hash_offset_map) {
        perror("ERROR: Failed to open idRehash.map for writing");
        return false;
    }

    cvector_vector_type(char*) resources_path_array = get_resource_paths(".");
    char **resource_path;

    cvector_for_each_in(resource_path, resources_path_array) {
        size_t hash_offset = get_resource_hash_offset(*resource_path, dec_data, size);

        if (hash_offset == 0) {
            eprintf("ERROR: Failed to get hash for %s.\n", *resource_path);
            fclose(hash_offset_map);
            return false;
        }

        fprintf(hash_offset_map, "%s;%lu\n", *resource_path, hash_offset);
        free(*resource_path);
    }

    cvector_free(resources_path_array);
    fclose(hash_offset_map);

    printf("\nidRehash.map has been successfully generated.\n");
    return true;
}

int main(int argc, char **argv)
{   
    printf("idRehashLinux v1.4.2 by PowerBall253 :)\n\n");

    // Read and decompress data from meta.resources
    FILE *meta = fopen("meta.resources", "rb");

    if (!meta) {
        perror("ERROR: Failed to open meta.resources for reading");
        return 1;
    }

    fseek(meta, 0x50, SEEK_SET);
    uint64_t info_offset;

    if (fread(&info_offset, 8, 1, meta) != 1) {
        perror("ERROR: Failed to read from meta.resources");
        fclose(meta);
        return 1;
    }

    fseek(meta, 0x38 + (long)info_offset, SEEK_SET);
    uint64_t file_offset;

    if (fread(&file_offset, 8, 1, meta) != 1) {
        perror("ERROR: Failed to read from meta.resources");
        fclose(meta);
        return 1;
    }

    uint64_t size_z;

    if (fread(&size_z, 8, 1, meta) != 1) {
        perror("ERROR: Failed to read from meta.resources");
        fclose(meta);
        return 1;
    }

    uint64_t size;

    if (fread(&size, 8, 1, meta) != 1) {
        perror("ERROR: Failed to read from meta.resources");
        fclose(meta);
        return 1;
    }
    
    unsigned char *dec_data = malloc(size + SAFE_SPACE);

    if (!dec_data) {
        perror("ERROR: Failed to allocate memory");
        fclose(meta);
        return 1;
    }

    if (size == size_z) {
        fseek(meta, (long)file_offset, SEEK_SET);

        if (fread(dec_data, 1, size, meta) != size) {
            perror("ERROR: Failed to read from meta.resources");
            free(dec_data);
            fclose(meta);
            return 1;
        }
    }
    else {
        unsigned char *comp_data = malloc(size_z);

        if (!comp_data) {
            perror("ERROR: Failed to allocate memory");
            free(dec_data);
            fclose(meta);
            return 1;
        }

        fseek(meta, (long)file_offset, SEEK_SET);

        if (fread(comp_data, 1, size_z, meta) != size_z) {
            perror("ERROR: Failed to read from meta.resources");
            free(dec_data);
            free(comp_data);
            fclose(meta);
            return 1;
        }

        if (Kraken_Decompress(comp_data, size_z, dec_data, size) != size) {
            eprintf("ERROR: Failed to decompress meta.resources - bad file?\n");
            free(dec_data);
            free(comp_data);
            fclose(meta);
            return 1;
        }

        free(comp_data);
    }

    fclose(meta);

    // Check program arguments & generate map if needed
    if (argc > 1) {
        if (strcmp(argv[1], "--getoffsets") == 0)
            return generate_map(dec_data, size) ? 0 : 1;

        printf("Usage:\n");
        printf("%s [--getoffsets]\n", argv[0]);
        printf("\n--getoffsets\tGenerates the hash offset map file required to use this tool.\n");
        return 1;
    }

    // Read from previously generated hash map
    FILE *hash_offset_map = fopen("idRehash.map", "rb");

    if (!hash_offset_map) {
        perror("ERROR: Failed to open idRehash.map for reading");
        eprintf("Make sure to generate the hash offset map file first using the --getoffsets option.\n");
        free(dec_data);
        return 1;
    }

    cvector_vector_type(struct resource_map_entry) resource_offsets;
    cvector_reserve(resource_offsets, 100);

    char buffer[1024];

    while(fgets(buffer, sizeof(buffer), hash_offset_map) != NULL) {
        char *delim_pos = strchr(buffer, ';');

        if (!delim_pos)
            continue;

        *delim_pos = '\0';
        char *path = buffer;
        char *x = path;

        while (*x != '\0') {
            if (*x == '\\')
                *x = '/';

            x++;
        }

        char *hash_str = buffer + strlen(path) + 1;
        char *end;

        if (*hash_str == '\n' || *hash_str == '\0')
            continue;

        size_t offset = strtoul(hash_str, &end, 10);

        if (end == hash_str || errno == ERANGE) {
            eprintf("ERROR: Failed to read hash from idRehash.map.\n");
            eprintf("Regenerate the hash offset map file by using the --getoffsets option.\n");
            cvector_free(resource_offsets);
            free(dec_data);
            return 1;
        }

        struct resource_map_entry entry = { strdup(path), offset };
        cvector_push_back(resource_offsets, entry);
    }

    fclose(hash_offset_map);

    // Hash resource headers and change the hash in the decompressed meta.resources data
    struct resource_map_entry *resource;
    int fixed_hashes = 0;

    cvector_for_each_in(resource, resource_offsets) {
        size_t offset = resource->offset;
        uint64_t hash = 0;

        if (hash_resource_headers(resource->resource_path, &hash)) {
            if (offset > 0) {
                uint64_t old_hash = 0;

                for (int j = 7; j >= 0; j--) {
                    old_hash <<= 8;
                    old_hash |= (uint64_t)dec_data[offset + j];
                }

                if (old_hash != hash) {
                    unsigned char* phash = (unsigned char*)&hash;

                    for (int j = 7; j >= 0; j--)
                        dec_data[offset + j] = phash[j];

                    fixed_hashes++;
                    printf("  ^ Updated from %lx\n\n", old_hash);
                }
            }
        }

        free(resource->resource_path);
    }

    cvector_free(resource_offsets);

    if (fixed_hashes == 0) {
        printf("\nDone, 0 hashes changed.\n");
        free(dec_data);
        return 0;
    }

    // Write the new decompressed data to meta.resources
    meta = fopen("meta.resources", "rb+");

    if (!meta) {
        perror("ERROR: Failed to open meta.resources for writing");
        free(dec_data);
        return 1;
    }

    fseek(meta, 0x38 + (long)info_offset + 0x8, SEEK_SET);

    if (fwrite(&size, 1, 4, meta) != 4) {
        perror("ERROR: Failed to write to meta.resources");
        fclose(meta);
        free(dec_data);
        return 1;
    }

    unsigned char *zero = 0;
    fseek(meta, 0x2C, SEEK_CUR);

    if (fwrite(&zero, 1, 1, meta) != 1) {
        perror("ERROR: Failed to write to meta.resources");
        fclose(meta);
        free(dec_data);
        return 1;
    }

    fseek(meta, (long)file_offset, SEEK_SET);

    if (fwrite(dec_data, 1, size, meta) != size) {
        perror("ERROR: Failed to write to meta.resources");
        fclose(meta);
        free(dec_data);
        return 1;
    }

    fclose(meta);
    free(dec_data);

    printf("\nDone, %d hashes changed.\n", fixed_hashes);
    return 0;
}
