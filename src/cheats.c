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
#include <stdbool.h>
#include <string.h>

#include "cheats.h"
#include "util.h"
#include "fatfs/ff.h"

// Preprocessing cheats, includes a proper header and pre-formats some payloads.
bool predecode_cheats(uint32_t *codes, unsigned cnt) {
  for (unsigned i = 0; i < cnt; i++) {
    t_cheat_predec h = {
      .opcode = ((codes[2*i] >> 28) & 0xF) * 2,    // Opcode scaled by 2
      .value = codes[2*i+1],
      .address = codes[2*i] & 0xFFFFFFF,
    };
    h.blen = (h.opcode == 4 * 2) ? 16 :
             (h.opcode == 5 * 2) ? (h.value + 1) * 8 :
             8;

    // Overwrite buffer with the new format
    memcpy(&codes[2*i], &h, sizeof(h));

    if (h.opcode == 4 * 2)
      i++;                    // Extra addr + value for opc4
    else if (h.opcode == 5 * 2) {
      // Extra buffer. We perform some endianess conversion here.
      for (unsigned j = 0; j < h.value; j++) {
        i++;
        uint32_t addr = codes[2*i];
        uint16_t valu = codes[2*i+1];
        codes[2*i] = __builtin_bswap32(addr);
        codes[2*i+1] = __builtin_bswap16(valu);
      }
    }
  }
  return true;
}

bool parse_hex(const char *s, uint32_t *val, unsigned nibcnt) {
  unsigned r = 0;
  for (unsigned i = 0; i < nibcnt; i++) {
    if (!s[i])
      return false;    // String ended prematurely

    if (s[i] >= '0' && s[i] <= '9')
      r = (r << 4) | (s[i] - '0');
    else if (s[i] >= 'a' && s[i] <= 'f')
      r = (r << 4) | (s[i] - 'a' + 10);
    else if (s[i] >= 'A' && s[i] <= 'F')
      r = (r << 4) | (s[i] - 'A' + 10);
    else
      return false;
  }
  *val = r;
  return true;
}

// Parses RAW codes into a uint32 buffer
int parse_cheat_codes(const char *s, uint32_t *codes, unsigned capacity) {
  // Codes are in the format:
  // 0123ABCD+67EF 125634AB+78CD ....
  // We parse them assuming that the separators are space or plus. We admit multiple separators.
  unsigned cnt = 0;

  while (*s == ' ' || *s == '+' || *s == '\r' || *s == '\t') s++;

  while (*s) {
    if (cnt >= capacity)
      return -1;

    uint32_t addr, val;
    if (!parse_hex(s, &addr, 8))
      return -1;

    s += 8;
    while (*s == ' ' || *s == '+' || *s == '\r' || *s == '\t') s++;
    if (!*s)
      return -1;   // The cheat is truncated, abort.

    if (!parse_hex(s, &val, 4))
      return -1;
    s += 4;

    *codes++ = addr;
    *codes++ = val;
    cnt++;

    while (*s == ' ' || *s == '+' || *s == '\r' || *s == '\t') s++;
  }
  return cnt;
}


// Reads a cheat file into a temp buffer (usually in SDRAM) and returns the size in bytes
// Returns -1 if the file is not found or the cheats cannot be loaded.
int open_read_cheats(uint8_t *buffer, unsigned buffsize, const char *fn) {
  FIL fd;
  FRESULT res = f_open(&fd, fn, FA_READ);
  if (res != FR_OK)
    return -1;

  bool parse_name = true;
  unsigned bcount = 0;
  char tmp[1024 + 4];

  t_cheathdr_ext chdr;
  uint32_t *bufhd = (uint32_t*)buffer;
  *bufhd = 0;
  unsigned bufsz = 4;

  // Parse the file line by line, using a temp buffer.
  do {
    if (bcount <= 512) {
      UINT rdbytes;
      if (FR_OK != f_read(&fd, &tmp[bcount], 512, &rdbytes)) {
        f_close(&fd);
        return -1;
      }
      bcount += rdbytes;
      tmp[bcount] = 0;
    }

    // Attempt to parse the next line.
    char *p = strchr(tmp, '\n');
    if (!p)
      p = strchr(tmp, '\0');
    if (!p)
      break;

    // Strip trailing \r for CRLF compatibility
    while (p > tmp && (p[-1] == '\r' || p[-1] == ' ' || p[-1] == '\t'))
      p[-1] = 0;
    *p = 0;

    // Skip leading whitespace
    char *s = tmp;
    while (*s == ' ' || *s == '\t')
      s++;

    // Skip empty lines!
    if (*s != 0) {
      if (bufsz + 1024 > buffsize) {
        f_close(&fd);
        return -1;
      }

      if (parse_name) {
        // Fill title with bounded copy to prevent overflow
        size_t len = strlen(s);
        if (len > 251)
          len = 251;
        memcpy(&chdr.title[0], s, len);
        chdr.title[len] = 0;
        chdr.h.slen = (strlen(chdr.title) + 1 + 3) & ~3U;
        chdr.h.enabled = 0;
        chdr.h.codelen = 0;
      } else {
        uint32_t codes[74];
        memset(codes, 0, sizeof(codes));
        int numcodes = parse_cheat_codes(tmp, codes, 37);
        if (numcodes < 0) {
          f_close(&fd);
          return -1;
        }
        if (!predecode_cheats(codes, numcodes)) {
          f_close(&fd);
          return -1;
        }

        chdr.h.codelen = 8 * (numcodes + 1);

        {
          unsigned pheadl = sizeof(t_cheathdr) + chdr.h.slen;
          memcpy32(&buffer[bufsz], &chdr, pheadl);
          memcpy32(&buffer[bufsz + pheadl], codes, chdr.h.codelen);

          bufsz += pheadl + chdr.h.codelen;
          (*bufhd)++;
        }
      }

      parse_name = !parse_name;
    }

    // Consume bytes
    unsigned linecnt = strlen(tmp) + 1;
    memmove(&tmp[0], &tmp[linecnt], bcount - linecnt);
    bcount -= linecnt;
  } while (bcount);

  f_close(&fd);
  return bufsz;
}


