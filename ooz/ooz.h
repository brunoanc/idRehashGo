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

#ifndef OOZ_H
#define OOZ_H

#include <stdint.h>
#include <stddef.h>

#define SAFE_SPACE 64

int Kraken_Compress(uint8_t* src, size_t src_len, uint8_t* dst, int level);
int Kraken_Decompress(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_len);

#endif
