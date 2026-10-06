/*
 * Copyright (C) 2025 David Guillen Fandos <david@davidgf.net>
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>
#include <stddef.h>

// Maximum number of addr+value pairs in a single cheat line.  t_cheathdr
// stores the payload length in 8 bits, and it accounts for 8 bytes per pair
// plus a zero filled terminator entry, which caps the count here.
#define MAX_CHEAT_CODES  30

typedef struct {
  uint8_t slen;        // String length (bytes)
  uint8_t codelen;     // Data payload length (bytes)
  uint8_t enabled;
  uint8_t _pad;        // Helps with 16 bit writes when updating enabled.
  uint8_t data[];
} t_cheathdr;

// Same four header bytes as t_cheathdr, spelled out again: a struct with a
// flexible array member must not be embedded into another struct (constraint
// violation in standard C, hard error C2229 on MSVC).  t_cheathdr_ext is only
// ever used as a stack scratch buffer that gets copied out in one block, so
// the header has to stay a byte for byte prefix of t_cheathdr_ext.
typedef struct {
  uint8_t slen;
  uint8_t codelen;
  uint8_t enabled;
  uint8_t _pad;
} t_cheathdr_head;

typedef struct {
  t_cheathdr_head h;
  char title[256];
} t_cheathdr_ext;

_Static_assert(sizeof(t_cheathdr) == sizeof(t_cheathdr_head),
               "t_cheathdr_head must mirror t_cheathdr");
_Static_assert(offsetof(t_cheathdr_ext, title) == sizeof(t_cheathdr_head),
               "the title must immediately follow the header bytes");

typedef struct {
  uint8_t opcode;            // The codebreaker opcode (0 to 15)
  uint8_t blen;              // Number of bytes used by this cheat (usually 8, this struct)
  uint16_t value;            // Cheat value
  uint32_t address;          // Cheat address
} t_cheat_predec;

int open_read_cheats(uint8_t *buffer, unsigned buffersize, const char *fn);
