#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <fts.h>
#include <dlfcn.h>
#include <glib.h>

#include "farmhash-c/farmhash.h"

typedef int OodLZ_DecompressFunc(uint8_t *src_buf, int src_len, uint8_t *dst, size_t dst_size,
    int fuzz, int crc, int verbose,
    uint8_t *dst_base, size_t e, void *cb, void *cb_ctx, void *scratch, size_t scratch_size, int threadPhase);

struct resource_map_entry {
    char *resource_path;
    long offset;
};

bool hash_resource_headers(char *path, uint64_t *hash)
{
    FILE *f = fopen(path, "rb");

    if (!f) {
        fprintf(stderr, "ERROR: Failed to open %s for reading!\n", path);
        return false;
    }

    fseek(f, 0x74, SEEK_SET);

    uint64_t start_addr = 0x7C;
    uint64_t end_addr = 0;

    if (fread(&end_addr, 8, 1, f) != 1) {
        fprintf(stderr, "ERROR: Failed to read from %s!\n", path);
        return false;
    }

    end_addr += 4;

    uint64_t headers_size = end_addr - start_addr;

    char *hashed_data = malloc(headers_size);
    fseek(f, start_addr, SEEK_SET);

    if (fread(hashed_data, 1, headers_size, f) != headers_size) {
        fprintf(stderr, "ERROR: Failed to read from %s!\n", path);
        return false;
    }

    fclose(f);

    *hash = farmhash64(hashed_data, headers_size);
    printf("%s: %lx\n", path, *hash);

    free(hashed_data);

    return true;
}

GArray *get_resource_paths(char *filepath)
{
    char **filepath_array;
    GArray *resource_files;
    FTS *ftsp;
    FTSENT *p, *chp;

    filepath_array = malloc(sizeof(char**));
    filepath_array[0] = filepath;
    ftsp = fts_open(filepath_array, FTS_COMFOLLOW | FTS_LOGICAL | FTS_NOCHDIR, NULL);
    free(filepath_array);

    resource_files = g_array_sized_new(false, false, sizeof(char*), 80);

    if (!ftsp) {
        fprintf(stderr, "ERROR: Failed to open %s directory!\n", filepath);
        return NULL;
    }

    chp = fts_children(ftsp, 0);

    if (!chp) {
        fprintf(stderr, "ERROR: Failed to open %s directory!\n", filepath);
        return NULL;
    }

    while ((p = fts_read(ftsp)) != NULL) {
        if (p->fts_info != FTS_F)
            continue;

        char *filename = strrchr(p->fts_path, '/') + 1;

        if (!filename) {
            filename = p->fts_path;
        }
        
        char *extension = strrchr(p->fts_path, '.');

        if (!extension) {
            extension = filename;
        }

        if (!strcmp(extension, ".resources") && strcmp(filename, "meta.resources") && strcmp(filename, "tutorial_demons.resources")) {
            char *resource_path = strdup(p->fts_path);
            g_array_append_val(resource_files, resource_path);
        }
    }

    fts_close(ftsp);

    return resource_files;
}

int get_resource_hash_offset(char *path, unsigned char *dec_container_mask_data, int dec_size)
{
    uint64_t hash = 0;

    if (!hash_resource_headers(path, &hash)) {
        fprintf(stderr, "ERROR: Failed to get hash for %s!\n", path);
        return -1;
    }

    unsigned char hash_bytes[sizeof(hash)];
    memcpy(hash_bytes, &hash, sizeof(hash));

    int hash_offset = 0;
    int current_hash_byte = 0;

    for (int i = dec_size - 1; i >= 0; i--) {
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
        fprintf(stderr, "ERROR: Failed to get offset for %s!\n", path);
        return -1;
    }

    return hash_offset;
}

bool generate_map(unsigned char *dec_data, uint64_t size)
{
    FILE *hash_offset_map = fopen("idRehash.map", "w");

    if (!hash_offset_map) {
        fprintf(stderr, "ERROR: Failed to open idRehash.map for writing!\n");
        return false;
    }

    GArray *resources_path_array = get_resource_paths(".");

    for (int i = 0; i < resources_path_array->len; i++) {
        char *resource_path = g_array_index(resources_path_array, char*, i);

        int hash_offset = get_resource_hash_offset(resource_path, dec_data, size);

        if (hash_offset == 0)
            return false;
        
        fprintf(hash_offset_map, "%s;%d\n", resource_path, hash_offset);
    }

    g_array_free(resources_path_array, true);

    fclose(hash_offset_map);

    printf("\nidRehash.map has been successfully generated!\n");
    return true;
}

int main(int argc, char **argv)
{   
    printf("idRehashLinux v1.0 by PowerBall253 :)\n\n");

    FILE *meta = fopen("meta.resources", "rb");

    if (!meta) {
        fprintf(stderr, "ERROR: Failed to open meta.resources for reading!\n");
        return 1;
    }

    fseek(meta, 0x50, SEEK_SET);
    uint64_t info_offset;

    if (fread(&info_offset, 8, 1, meta) != 1) {
        fprintf(stderr, "ERROR: Failed to read from meta.resources!\n");
        return 1;
    }

    fseek(meta, 0x38 + info_offset, SEEK_SET);
    uint64_t file_offset;

    if (fread(&file_offset, 8, 1, meta) != 1) {
        fprintf(stderr, "ERROR: Failed to read from meta.resources!\n");
        return 1;
    }

    uint64_t size_z;

    if (fread(&size_z, 8, 1, meta) != 1) {
        fprintf(stderr, "ERROR: Failed to read from meta.resources!\n");
        return 1;
    }

    uint64_t size;

    if (fread(&size, 8, 1, meta) != 1) {
        fprintf(stderr, "ERROR: Failed to read from meta.resources!\n");
        return 1;
    }
    
    unsigned char *dec_data = malloc(size);

    if (size == size_z) {
        fseek(meta, file_offset, SEEK_SET);

        if (fread(dec_data, 1, size, meta) != size) {
            fprintf(stderr, "ERROR: Failed to read from meta.resources - bad file?\n");
            return 1;
        }
    }
    else {
        unsigned char *comp_data = malloc(size_z);

        fseek(meta, file_offset, SEEK_SET);

        if (fread(comp_data, 1, size_z, meta) != size_z) {
            fprintf(stderr, "ERROR: Failed to read from meta.resources - bad file?\n");
            return 1;
        }

        void *oodle = dlopen("./liblinoodle.so", RTLD_LAZY);
        OodLZ_DecompressFunc *OodLZ_Decompress = (OodLZ_DecompressFunc*)dlsym(oodle, "OodleLZ_Decompress");

        if (OodLZ_Decompress(comp_data, size_z, dec_data, size, 0, 0, 0, NULL, 0, NULL, NULL, NULL, 0, 0) != size) {
            fprintf(stderr, "ERROR: Failed to decompress meta.resources - bad file?\n");
            return 1;
        }

        free(comp_data);
    }

    fclose(meta);

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--getoffsets"))
            return generate_map(dec_data, size) ? 0 : 1;

        printf("Usage:\n");
        printf("%s [--getoffsets]\n", argv[0]);
        printf("\n--getoffsets\tGenerates the hash offset map file required to use this tool.\n");
        return 1;
    }

    FILE *hash_offset_map = fopen("idRehash.map", "rb");

    if (!hash_offset_map) {
        fprintf(stderr, "ERROR: Failed to open idRehash.map for reading!\n");
        fprintf(stderr, "Make sure to generate the hash offset map file first using the --getoffsets option.\n");
        return 1;
    }

    GArray *resource_offsets = g_array_sized_new(false, false, sizeof(struct resource_map_entry), 80);
    char buffer[1024];

    while(fgets(buffer, sizeof(buffer), hash_offset_map) != NULL) {
        char *delim_pos = strchr(buffer, ';');

        if (!delim_pos)
            continue;

        *delim_pos = '\0';

        char *path = buffer;
        char *hash_str = buffer + strlen(path) + 1;
        char *end;

        if (*hash_str == '\n' || *hash_str == '\0')
            continue;

        long offset = strtol(hash_str, &end, 10);

        if (end == hash_str || errno == ERANGE) {
            fprintf(stderr, "ERROR: Failed to read hash from idRehash.map!\n");
            fprintf(stderr, "Regenerate the hash offset map file by using the --getoffsets option.\n");
            return 1;
        }

        struct resource_map_entry entry = { strdup(path), offset };

        g_array_append_val(resource_offsets, entry);
    }

    fclose(hash_offset_map);

    int fixed_hashes = 0;

    for (int i = 0; i < resource_offsets->len; i++) {
        struct resource_map_entry resource = g_array_index(resource_offsets, struct resource_map_entry, i);

        long offset = resource.offset;
        uint64_t hash = 0;

        if (hash_resource_headers(resource.resource_path, &hash)) {
            if (offset > 0) {
                uint64_t old_hash = 0;

                for (int i = 7; i >= 0; i--) {
                    old_hash <<= 8;
                    old_hash |= (uint64_t)dec_data[offset + i];
                }

                if (old_hash != hash) {
                    unsigned char* phash = (unsigned char*)&hash;

                    for (int i = 7; i >= 0; i--)
                        dec_data[offset + i] = phash[i];

                    fixed_hashes++;
                    printf("  ^ Updated from %lx\n\n", old_hash);
                }
            }
        }
    }

    g_array_free(resource_offsets, true);

    if (fixed_hashes == 0) {
        printf("\nDone, 0 hashes changed.\n");
        return 0;
    }

    meta = fopen("meta.resources", "rb+");

    if (!meta) {
        fprintf(stderr, "ERROR: Failed to open meta.resources for writing!\n");
        return 1;
    }

    fseek(meta, 0x38 + info_offset + 0x8, SEEK_SET);

    if (fwrite(&size, 1, 4, meta) != 4) {
        fprintf(stderr, "ERROR: Failed to write to meta.resources!\n");
        return 1;
    }

    unsigned char *zero = 0;
    fseek(meta, 0x2C, SEEK_CUR);

    if (fwrite(&zero, 1, 1, meta) != 1) {
        fprintf(stderr, "ERROR: Failed to write to meta.resources!\n");
        return 1;
    }

    fseek(meta, file_offset, SEEK_SET);

    if (fwrite(dec_data, 1, size, meta) != size) {
        fprintf(stderr, "ERROR: Failed to write to meta.resources!\n");
        return 1;
    }

    fclose(meta);

    free(dec_data);

    printf("\nDone, %d hashes changed.\n", fixed_hashes);
    return 0;
}