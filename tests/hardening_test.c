/*
 * Copyright (C) 2026 Kurisu Chan <miemiekurisu@aol.com>
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

/*
 * Host-side regression tests for this fork's hardening of the ROM patch
 * pipeline and the cheat loader.  They cover behaviour that is otherwise only
 * reachable on real hardware or through malformed database/cheat files:
 *
 *   - copy_func16(): interval intersection between a source payload and a
 *     partial ROM chunk (underflows / wrong source skip / chunk overrun).
 *   - apply_patch_ops(): full-width bounds for every opcode, plus operand
 *     stream consumption for the multi-word opcodes.
 *   - payload_apply_rom(): overlap tests at both chunk edges.
 *   - patchmem_lookup(): validation of untrusted patch databases (op counts,
 *     save types, hole words).
 *   - patch_apply_rom(): segment walk, save routine table selection and the
 *     in-game menu entry point detour.
 *   - predecode_cheats()/parse_cheat_codes(): truncated or hostile cheat
 *     files, including the opcode 5 payload count coming from the file.
 *
 * src/patcher.c is #included so its file-static helpers and tables can be
 * exercised directly.  The patch payloads it references (src/patches.S in the
 * firmware) are replaced by the plain arrays defined below, with the same
 * "_size holds a byte count" convention.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cheats.h"

//-----------------------------------------------------------------------------
// Dummy replacements for the assembly patch payloads (src/patches.S).
//-----------------------------------------------------------------------------
#define FNSZ            8            // Bytes per dummy patch routine
#define FN_HALFWORDS    (FNSZ / 2)

#define DEFINE_DUMMY_FN(name) \
  uint16_t name[FN_HALFWORDS];       \
  const uint32_t name##_size = FNSZ;

DEFINE_DUMMY_FN(patch_rtc_probe)
DEFINE_DUMMY_FN(patch_rtc_getstatus)
DEFINE_DUMMY_FN(patch_rtc_gettimedate)
DEFINE_DUMMY_FN(patch_rtc_reset)

DEFINE_DUMMY_FN(patch_eeprom_read_sram64k)
DEFINE_DUMMY_FN(patch_eeprom_write_sram64k)
DEFINE_DUMMY_FN(patch_eeprom_read_directsave)
DEFINE_DUMMY_FN(patch_eeprom_write_directsave)

DEFINE_DUMMY_FN(patch_flash_read_sram64k)
DEFINE_DUMMY_FN(patch_flash_erase_device_sram64k)
DEFINE_DUMMY_FN(patch_flash_erase_sector_sram64k)
DEFINE_DUMMY_FN(patch_flash_write_sector_sram64k)
DEFINE_DUMMY_FN(patch_flash_write_byte_sram64k)

DEFINE_DUMMY_FN(patch_flash_read_sram128k)
DEFINE_DUMMY_FN(patch_flash_erase_device_sram128k)
DEFINE_DUMMY_FN(patch_flash_erase_sector_sram128k)
DEFINE_DUMMY_FN(patch_flash_write_sector_sram128k)
DEFINE_DUMMY_FN(patch_flash_write_byte_sram128k)

DEFINE_DUMMY_FN(patch_flash_read_directsave)
DEFINE_DUMMY_FN(patch_flash_erase_device_directsave)
DEFINE_DUMMY_FN(patch_flash_erase_sector_directsave)
DEFINE_DUMMY_FN(patch_flash_write_sector_directsave)
DEFINE_DUMMY_FN(patch_flash_write_byte_directsave)

#include "../src/patcher.c"

// Minimal FatFS stand-ins: only the cheat file loader uses them, and the tests
// below call its parsing helpers directly.
FRESULT f_open(FIL *fp, const TCHAR *path, BYTE mode) {
  FILE *fd = fopen(path, "rb");
  if (!fd)
    return FR_NO_FILE;
  *(FILE**)fp = fd;
  return FR_OK;
}

// Set by a test to make the underlying file read fail (dying card, etc).
static int stub_read_fail;

FRESULT f_read(FIL *fp, void *buff, UINT btr, UINT *br) {
  if (stub_read_fail)
    return FR_DISK_ERR;
  size_t ret = fread(buff, 1, btr, *(FILE**)fp);
  *br = ret;
  return FR_OK;
}

FRESULT f_close(FIL *fp) {
  fclose(*(FILE**)fp);
  return FR_OK;
}

//-----------------------------------------------------------------------------
// Test scaffolding
//-----------------------------------------------------------------------------
static int checks;
static int failures;

#define CHECK(cond)                                 \
  do {                                              \
    checks++;                                       \
    if (!(cond)) {                                  \
      printf("FAIL %s:%d: %s\n", __FILE__,          \
             __LINE__, #cond);                      \
      failures++;                                   \
    }                                               \
  } while (0)

// Patch opcodes are matched against ROM-relative addresses (the loader hands
// over the offset of the loaded chunk, not a mapped 0x08000000 pointer), and
// op words only carry 25 address bits.
#define BASE       0x00100000u
#define BUFSIZE    32
#define PAD        0xAA

static uint8_t guarded[BUFSIZE + 64];
static uint8_t *buf = &guarded[16];

static uint16_t src16[64];
static uint8_t payload[128];

static t_patch_prog test_prgs[MAX_PATCH_PRG];
static uint16_t fn_eep_read[FN_HALFWORDS], fn_eep_write[FN_HALFWORDS];
static uint16_t fn_fl_read[FN_HALFWORDS], fn_fl_edev[FN_HALFWORDS];
static uint16_t fn_fl_esec[FN_HALFWORDS], fn_fl_wsec[FN_HALFWORDS];
static uint16_t fn_fl_wbyte[FN_HALFWORDS];
static const uint32_t fnsize = FNSZ;

static t_psave_funcs test_psf;
static t_psave_info test_psi;

static void init_dummies(void) {
  unsigned base = 0x1000;
#define FILL(a)                                    \
  do {                                             \
    for (unsigned k = 0; k < FN_HALFWORDS; k++)     \
      a[k] = base + k;                              \
    base += 0x100;                                  \
  } while (0)

  FILL(patch_rtc_probe);
  FILL(patch_rtc_getstatus);
  FILL(patch_rtc_gettimedate);
  FILL(patch_rtc_reset);
  FILL(patch_eeprom_read_sram64k);
  FILL(patch_eeprom_write_sram64k);
  FILL(patch_eeprom_read_directsave);
  FILL(patch_eeprom_write_directsave);
  FILL(patch_flash_read_sram64k);
  FILL(patch_flash_erase_device_sram64k);
  FILL(patch_flash_erase_sector_sram64k);
  FILL(patch_flash_write_sector_sram64k);
  FILL(patch_flash_write_byte_sram64k);
  FILL(patch_flash_read_sram128k);
  FILL(patch_flash_erase_device_sram128k);
  FILL(patch_flash_erase_sector_sram128k);
  FILL(patch_flash_write_sector_sram128k);
  FILL(patch_flash_write_byte_sram128k);
  FILL(patch_flash_read_directsave);
  FILL(patch_flash_erase_device_directsave);
  FILL(patch_flash_erase_sector_directsave);
  FILL(patch_flash_write_sector_directsave);
  FILL(patch_flash_write_byte_directsave);

  FILL(fn_eep_read);
  FILL(fn_eep_write);
  FILL(fn_fl_read);
  FILL(fn_fl_edev);
  FILL(fn_fl_esec);
  FILL(fn_fl_wsec);
  FILL(fn_fl_wbyte);
#undef FILL

  for (unsigned i = 0; i < 64; i++)
    src16[i] = 0x2000 + i;
  for (unsigned i = 0; i < sizeof(payload); i++)
    payload[i] = 0x40 + i;

  memset(test_prgs, 0, sizeof(test_prgs));
  test_prgs[0].length = 8;
  for (unsigned i = 0; i < test_prgs[0].length; i++)
    test_prgs[0].data[i] = 0x70 + i;

  test_psf.eeprom_fncs[0].ptr = fn_eep_read;
  test_psf.eeprom_fncs[0].size = &fnsize;
  test_psf.eeprom_fncs[1].ptr = fn_eep_write;
  test_psf.eeprom_fncs[1].size = &fnsize;
  for (unsigned i = 0; i < 5; i++)
    test_psf.flash_fncs[i].size = &fnsize;
  test_psf.flash_fncs[0].ptr = fn_fl_read;
  test_psf.flash_fncs[1].ptr = fn_fl_edev;
  test_psf.flash_fncs[2].ptr = fn_fl_esec;
  test_psf.flash_fncs[3].ptr = fn_fl_wsec;
  test_psf.flash_fncs[4].ptr = fn_fl_wbyte;

  test_psi.dspayload_addr = 0x09ABC000u;
  test_psi.sfns = &test_psf;
}

static void reset_buf(void) {
  memset(guarded, PAD, sizeof(guarded));
}

// Nothing may be written outside of [buf, buf + BUFSIZE).
static int guard_intact(void) {
  for (unsigned i = 0; i < 16; i++)
    if (guarded[i] != PAD)
      return 0;
  for (unsigned i = BUFSIZE + 16; i < (unsigned)sizeof(guarded); i++)
    if (guarded[i] != PAD)
      return 0;
  return 1;
}

static int untouched(unsigned from, unsigned to) {
  for (unsigned i = from; i < to; i++)
    if (buf[i] != PAD)
      return 0;
  return 1;
}

static void expect_hw(unsigned off, uint16_t v) {
  uint16_t got = (uint16_t)(buf[off] | ((uint16_t)buf[off + 1] << 8));
  CHECK(got == v);
  if (got != v)
    printf("       buf[%u]: want %04X got %04X\n", off, v, got);
}

static void expect_be(unsigned off, const uint8_t *data, unsigned n) {
  for (unsigned i = 0; i < n; i++)
    CHECK(buf[off + i] == data[i]);
}

static uint32_t rd32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static uint32_t mkop(unsigned opc, unsigned arg, uint32_t moff) {
  return ((uint32_t)opc << 28) | ((uint32_t)arg << 25) | moff;
}
//-----------------------------------------------------------------------------
// copy_func16(): source/chunk interval intersection
//-----------------------------------------------------------------------------
static void test_copy_func16(void) {
  // Fully inside the chunk, at an offset.
  reset_buf();
  copy_func16(buf, BASE, BUFSIZE, src16, BASE + 4, 8);
  CHECK(untouched(0, 4));
  expect_hw(4, src16[0]);
  expect_hw(6, src16[1]);
  expect_hw(8, src16[2]);
  expect_hw(10, src16[3]);
  CHECK(untouched(12, BUFSIZE));
  CHECK(guard_intact());

  // Source starts inside the chunk and runs past its end: the tail is clipped.
  reset_buf();
  copy_func16(buf, BASE, BUFSIZE, src16, BASE + BUFSIZE - 8, 32);
  CHECK(untouched(0, 24));
  for (unsigned i = 0; i < 8; i += 2)
    expect_hw(24 + i, src16[i / 2]);
  CHECK(guard_intact());

  // Source starts before the chunk and ends inside it: the first bytes of the
  // source must be skipped, not written at a negative buffer offset.
  reset_buf();
  copy_func16(buf, BASE, BUFSIZE, src16, BASE - 4, 16);
  expect_hw(0, src16[2]);
  expect_hw(10, src16[7]);
  CHECK(untouched(12, BUFSIZE));
  CHECK(guard_intact());

  // Source starts before the chunk and ends inside it, with a longer backoff.
  reset_buf();
  copy_func16(buf, BASE, BUFSIZE, src16, BASE - 16, 20);
  expect_hw(0, src16[8]);
  expect_hw(2, src16[9]);
  CHECK(untouched(4, BUFSIZE));
  CHECK(guard_intact());

  // Source covers the whole chunk.
  reset_buf();
  copy_func16(buf, BASE, BUFSIZE, src16, BASE - 8, sizeof(src16));
  for (unsigned i = 0; i < BUFSIZE; i += 2)
    expect_hw(i, src16[4 + i / 2]);
  CHECK(guard_intact());

  // Source ends exactly at the chunk start: no overlap, no writes.
  reset_buf();
  copy_func16(buf, BASE, BUFSIZE, src16, BASE - 32, 32);
  CHECK(untouched(0, BUFSIZE));
  CHECK(guard_intact());

  // Source starts exactly at the chunk end: no overlap, no writes.
  reset_buf();
  copy_func16(buf, BASE, BUFSIZE, src16, BASE + BUFSIZE, 32);
  CHECK(untouched(0, BUFSIZE));
  CHECK(guard_intact());

  // Only the first halfword of the source fits at the very end of the chunk:
  // the rest must not be written past the buffer.
  reset_buf();
  copy_func16(buf, BASE, BUFSIZE, src16, BASE + BUFSIZE - 2, 8);
  expect_hw(BUFSIZE - 2, src16[0]);
  CHECK(untouched(0, BUFSIZE - 2));
  CHECK(guard_intact());

  // Zero size and empty chunk are no-ops.
  reset_buf();
  copy_func16(buf, BASE, 0, src16, BASE, 8);
  copy_func16(buf, BASE, BUFSIZE, src16, BASE, 0);
  CHECK(untouched(0, BUFSIZE));
  CHECK(guard_intact());
}

//-----------------------------------------------------------------------------
// payload_apply_rom(): DirectSave / IGM trampoline partial application
//-----------------------------------------------------------------------------
static void test_payload_apply(void) {
  reset_buf();
  payload_apply_rom(buf, BUFSIZE, BASE, payload, 32, BASE + 16);
  CHECK(untouched(0, 16));
  expect_be(16, &payload[0], 16);
  CHECK(guard_intact());

  reset_buf();
  payload_apply_rom(buf, BUFSIZE, BASE, payload, 8, BASE - 4);
  expect_be(0, &payload[4], 4);
  CHECK(untouched(4, BUFSIZE));
  CHECK(guard_intact());

  reset_buf();
  payload_apply_rom(buf, BUFSIZE, BASE, payload, 8, BASE + BUFSIZE - 2);
  expect_be(BUFSIZE - 2, &payload[0], 2);
  CHECK(untouched(0, BUFSIZE - 2));
  CHECK(guard_intact());

  reset_buf();
  payload_apply_rom(buf, BUFSIZE, BASE, payload, sizeof(payload), BASE - 8);
  expect_be(0, &payload[8], BUFSIZE);
  CHECK(guard_intact());

  // No overlap on either side.
  reset_buf();
  payload_apply_rom(buf, BUFSIZE, BASE, payload, 32, BASE - 32);
  payload_apply_rom(buf, BUFSIZE, BASE, payload, 32, BASE + BUFSIZE);
  CHECK(untouched(0, BUFSIZE));
  CHECK(guard_intact());
}

//-----------------------------------------------------------------------------
// apply_patch_ops(): bounds and operand stream consumption
//-----------------------------------------------------------------------------
static void test_apply_ops(void) {
  uint32_t ops[16];

  // Opcode 1 (Thumb nop) is a 2 byte write.
  reset_buf();
  memset(ops, 0, sizeof(ops));
  ops[0] = mkop(0x1, 0, BASE + BUFSIZE - 2);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 1, test_prgs, &test_psi);
  expect_hw(BUFSIZE - 2, 0x46C0);
  CHECK(guard_intact());

  // A write that would only partially fit must be dropped entirely.
  reset_buf();
  ops[0] = mkop(0x1, 0, BASE + BUFSIZE - 1);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 1, test_prgs, &test_psi);
  CHECK(untouched(0, BUFSIZE));
  CHECK(guard_intact());

  reset_buf();
  ops[0] = mkop(0x2, 0, BASE + BUFSIZE - 2);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 1, test_prgs, &test_psi);
  CHECK(untouched(0, BUFSIZE));
  CHECK(guard_intact());

  // Below the chunk is out of range as well.
  reset_buf();
  ops[0] = mkop(0x2, 0, BASE - 4);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 1, test_prgs, &test_psi);
  CHECK(untouched(0, BUFSIZE));
  CHECK(guard_intact());

  // Opcode 0 writes a program, clipped to the chunk end.
  reset_buf();
  memset(ops, 0, sizeof(ops));
  ops[0] = mkop(0x0, 0, BASE + BUFSIZE - 6);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 1, test_prgs, &test_psi);
  for (unsigned i = 0; i < 6; i++)
    CHECK(buf[BUFSIZE - 6 + i] == 0x70 + i);
  CHECK(guard_intact());

  // Opcode 3 writes arg+1 bytes taken from the following words, and consumes
  // them.  The data words must be read relative to the op, not from the start
  // of the stream, and never shifted by 32 or more bits.
  reset_buf();
  memset(ops, 0, sizeof(ops));
  ops[0] = mkop(0x1, 0, BASE + 4);          // Follows the byte writer
  ops[1] = mkop(0x3, 3, BASE + 16);         // 4 bytes, not at index 0
  ops[2] = 0xAABBCCDD;
  ops[3] = mkop(0x1, 0, BASE + 6);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 4, test_prgs, &test_psi);
  expect_be(16, (const uint8_t*)"\xDD\xCC\xBB\xAA", 4);
  expect_hw(4, 0x46C0);
  expect_hw(6, 0x46C0);
  CHECK(guard_intact());

  reset_buf();
  memset(ops, 0, sizeof(ops));
  ops[0] = mkop(0x3, 7, BASE + 16);         // 8 bytes: two operand words
  ops[1] = 0x44332211;
  ops[2] = 0x88776655;
  ops[3] = mkop(0x1, 0, BASE + 8);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 4, test_prgs, &test_psi);
  expect_be(16, (const uint8_t*)"\x11\x22\x33\x44\x55\x66\x77\x88", 8);
  expect_hw(8, 0x46C0);                     // Both operand words consumed
  CHECK(guard_intact());

  // Byte writer clipped by the chunk end.
  reset_buf();
  memset(ops, 0, sizeof(ops));
  ops[0] = mkop(0x3, 3, BASE + BUFSIZE - 2);
  ops[1] = 0x88776655;
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 2, test_prgs, &test_psi);
  CHECK(buf[BUFSIZE - 2] == 0x55);
  CHECK(buf[BUFSIZE - 1] == 0x66);
  CHECK(untouched(0, BUFSIZE - 2));
  CHECK(guard_intact());

  // Opcode 4 writes arg+1 words, dropping the ones that do not fit.
  reset_buf();
  memset(ops, 0, sizeof(ops));
  ops[0] = mkop(0x4, 1, BASE + BUFSIZE - 4);
  ops[1] = 0x11111111;
  ops[2] = 0x22222222;
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 3, test_prgs, &test_psi);
  CHECK(buf[BUFSIZE - 4] == 0x11 && buf[BUFSIZE - 1] == 0x11);
  CHECK(guard_intact());

  reset_buf();
  memset(ops, 0, sizeof(ops));
  ops[0] = mkop(0x4, 1, BASE + 16);
  ops[1] = 0x11111111;
  ops[2] = 0x22222222;
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 3, test_prgs, &test_psi);
  CHECK(buf[16] == 0x11 && buf[19] == 0x11);
  CHECK(buf[20] == 0x22 && buf[23] == 0x22);
  CHECK(guard_intact());

  // Opcode 5 with arg 4/5 writes a pair of ARM words.
  reset_buf();
  memset(ops, 0, sizeof(ops));
  ops[0] = mkop(0x5, 4, BASE + 24);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 1, test_prgs, &test_psi);
  CHECK(buf[24] == 0x00 && buf[27] == 0xe3);
  CHECK(buf[28] == 0x1e && buf[31] == 0xe1);
  CHECK(guard_intact());

  reset_buf();
  ops[0] = mkop(0x5, 5, BASE + BUFSIZE - 4);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 1, test_prgs, &test_psi);
  CHECK(buf[BUFSIZE - 4] == 0x01 && buf[BUFSIZE - 1] == 0xe3);
  CHECK(guard_intact());

  // Opcode 7 (RTC handlers) must reject an out of range function index.
  reset_buf();
  memset(ops, 0, sizeof(ops));
  ops[0] = mkop(0x7, 4, BASE);
  ops[1] = mkop(0x7, 7, BASE);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 2, test_prgs, &test_psi);
  CHECK(untouched(0, BUFSIZE));
  CHECK(guard_intact());

  reset_buf();
  ops[0] = mkop(0x7, 0, BASE);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 1, test_prgs, &test_psi);
  for (unsigned i = 0; i < FNSZ; i += 2)
    expect_hw(i, patch_rtc_probe[i / 2]);
  CHECK(untouched(FNSZ, BUFSIZE));
  CHECK(guard_intact());

  // Opcodes 8/9 (EEPROM/FLASH handlers) copy the handler and follow it with
  // the DirectSave payload address.
  for (unsigned arg = 0; arg < 2; arg++) {
    reset_buf();
    memset(ops, 0, sizeof(ops));
    ops[0] = mkop(0x8, arg, BASE);
    apply_patch_ops(buf, BUFSIZE, BASE, ops, 1, test_prgs, &test_psi);
    uint16_t *fn = arg ? fn_eep_write : fn_eep_read;
    for (unsigned i = 0; i < FNSZ; i += 2)
      expect_hw(i, fn[i / 2]);
    CHECK(buf[8] == 0x00 && buf[11] == 0x09);
    CHECK(guard_intact());
  }

  reset_buf();
  memset(ops, 0, sizeof(ops));
  ops[0] = mkop(0x8, 2, BASE);
  ops[1] = mkop(0x9, 5, BASE);
  ops[2] = mkop(0x9, 7, BASE);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 3, test_prgs, &test_psi);
  CHECK(untouched(0, BUFSIZE));
  CHECK(guard_intact());

  reset_buf();
  memset(ops, 0, sizeof(ops));
  ops[0] = mkop(0x9, 0, BASE + BUFSIZE - 4);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 1, test_prgs, &test_psi);
  CHECK(!untouched(0, BUFSIZE));
  CHECK(untouched(0, BUFSIZE - FNSZ));
  CHECK(guard_intact());

  // An unknown opcode must be ignored without consuming operands.
  reset_buf();
  memset(ops, 0, sizeof(ops));
  ops[0] = mkop(0x6, 0, BASE);
  ops[1] = mkop(0x6, 0, 0xFFFFFFFF);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 2, test_prgs, &test_psi);
  CHECK(untouched(0, BUFSIZE));
  CHECK(guard_intact());

  // Opcode 2 (ARM nop) is a 4 byte write that must fit entirely in the chunk.
  reset_buf();
  memset(ops, 0, sizeof(ops));
  ops[0] = mkop(0x2, 0, BASE + BUFSIZE - 4);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 1, test_prgs, &test_psi);
  CHECK(rd32(&buf[BUFSIZE - 4]) == 0xE1A00000u);
  CHECK(untouched(0, BUFSIZE - 4));
  CHECK(guard_intact());

  // Opcode 5 with arg 0/1 writes a Thumb function returning 0 or 1.
  reset_buf();
  ops[0] = mkop(0x5, 0, BASE + 8);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 1, test_prgs, &test_psi);
  CHECK(rd32(&buf[8]) == 0x47702000u);
  CHECK(untouched(12, BUFSIZE));
  CHECK(guard_intact());

  reset_buf();
  ops[0] = mkop(0x5, 1, BASE + BUFSIZE - 4);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 1, test_prgs, &test_psi);
  CHECK(rd32(&buf[BUFSIZE - 4]) == 0x47702001u);
  CHECK(guard_intact());

  // A stub that would only partially fit is dropped entirely.
  reset_buf();
  ops[0] = mkop(0x5, 0, BASE + BUFSIZE - 2);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 1, test_prgs, &test_psi);
  CHECK(untouched(0, BUFSIZE));
  CHECK(guard_intact());

  // The unimplemented arg values must be no-ops.
  reset_buf();
  ops[0] = mkop(0x5, 2, BASE);
  ops[1] = mkop(0x5, 3, BASE);
  ops[2] = mkop(0x5, 6, BASE);
  ops[3] = mkop(0x5, 7, BASE);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 4, test_prgs, &test_psi);
  CHECK(untouched(0, BUFSIZE));
  CHECK(guard_intact());

  // Opcode 9 appends the DirectSave payload address after the handler, and
  // drops that word when it would not fit (covered above).
  reset_buf();
  memset(ops, 0, sizeof(ops));
  ops[0] = mkop(0x9, 1, BASE + 8);
  apply_patch_ops(buf, BUFSIZE, BASE, ops, 1, test_prgs, &test_psi);
  for (unsigned i = 0; i < FNSZ; i += 2)
    expect_hw(8 + i, fn_fl_edev[i / 2]);
  CHECK(rd32(&buf[16]) == test_psi.dspayload_addr);
  CHECK(untouched(20, BUFSIZE));
  CHECK(guard_intact());
}
//-----------------------------------------------------------------------------
// patchmem_lookup(): untrusted patch database validation
//-----------------------------------------------------------------------------
#define DB_SIZE   (1024 + 512 + 2048)

static uint8_t *db;

bool predecode_cheats(uint32_t *codes, unsigned cnt);
int parse_cheat_codes(const char *s, uint32_t *codes, unsigned capacity);

static uint32_t mkphdr(unsigned wcnt, unsigned save, unsigned smode,
                       unsigned irqh, unsigned rtc, int hole) {
  return (wcnt & 0xFF) | ((save & 0x1F) << 8) | ((smode & 7) << 13) |
         ((irqh & 0xFF) << 16) | ((rtc & 0xF) << 24) | (hole ? (1u << 28) : 0);
}

static void db_build(uint32_t pheader, const uint32_t *ops, unsigned nops,
                     int hole) {
  memset(db, 0, DB_SIZE);

  t_db_header *h = (t_db_header*)&db[0];
  h->signature = 0x31424450;    // "PTDB"
  h->dbversion = 0x00010000;
  h->patchcnt = 1;
  h->idxcnt = 1;
  memcpy(h->date, "20261006", 8);
  memcpy(h->version, "testdb!!", 8);
  memcpy(h->creator, "hardening_test", 14);

  // A single program record at the start of the program page.
  db[512] = 6;
  for (unsigned i = 0; i < 6; i++)
    db[513 + i] = 0x10 + i;

  t_db_idx *di = (t_db_idx*)&db[1024];
  memcpy(di->gcode, "ABCD", 4);
  di->offset = 0x01;        // Entry word index 0, game version 1

  uint32_t *entries = (uint32_t*)&db[1024 + 512 * h->idxcnt];
  entries[0] = pheader;
  memcpy(&entries[1], ops, nops * sizeof(uint32_t));
  if (hole)
    entries[1 + nops] = (0x100u << 16) | 0x40;
}

static void test_patchmem_lookup(void) {
  static const uint8_t gc[5] = { 'A', 'B', 'C', 'D', 1 };
  static const uint8_t gc_ver[5] = { 'A', 'B', 'C', 'D', 2 };
  t_patch p;
  uint32_t ops[136];

  // A well formed entry, including the trailing hole word.
  memset(ops, 0, sizeof(ops));
  for (unsigned i = 0; i < 3; i++)
    ops[i] = 0x11111111u * (i + 1);
  db_build(mkphdr(2, 1, SaveTypeFlash512K, 0, 0, 1), ops, 3, 1);
  memset(&p, 0xEE, sizeof(p));
  CHECK(patchmem_lookup(gc, db, &p));
  CHECK(p.wcnt_ops == 2 && p.save_ops == 1);
  CHECK(p.save_mode == SaveTypeFlash512K);
  CHECK(p.op[0] == 0x11111111u && p.op[2] == 0x33333333u);
  CHECK(p.hole_addr == (0x100u << 10) && p.hole_size == (0x40u << 10));
  CHECK(p.prgs[0].length == 6 && p.prgs[0].data[0] == 0x10);
  CHECK(p.prgs[0].data[5] == 0x15);
  CHECK(p.prgs[1].length == 0 && p.prgs[3].length == 0);

  // The game version byte is part of the lookup key.
  memset(&p, 0xEE, sizeof(p));
  CHECK(!patchmem_lookup(gc_ver, db, &p));

  // More ops than the fixed size array can hold must be rejected before they
  // are copied into it.
  db_build(mkphdr(0xFF, 0x1F, SaveTypeSRAM, 0xFF, 0xF, 0), ops, 0, 0);
  memset(&p, 0xEE, sizeof(p));
  CHECK(!patchmem_lookup(gc, db, &p));

  // Exactly MAX_PATCH_OPS is the accepted boundary.
  for (unsigned i = 0; i < MAX_PATCH_OPS; i++)
    ops[i] = 0x00BAD000u + i;
  db_build(mkphdr(MAX_PATCH_OPS, 0, SaveTypeSRAM, 0, 0, 0), ops,
           MAX_PATCH_OPS, 0);
  memset(&p, 0xEE, sizeof(p));
  CHECK(patchmem_lookup(gc, db, &p));
  CHECK(p.op[0] == 0x00BAD000u);
  CHECK(p.op[MAX_PATCH_OPS - 1] == 0x00BAD000u + MAX_PATCH_OPS - 1);

  // One op too many.
  db_build(mkphdr(MAX_PATCH_OPS + 1, 0, SaveTypeSRAM, 0, 0, 0), ops,
           MAX_PATCH_OPS, 0);
  CHECK(!patchmem_lookup(gc, db, &p));

  // Save types that cannot be emulated.
  db_build(mkphdr(1, 0, 7, 0, 0, 0), ops, 1, 0);
  CHECK(!patchmem_lookup(gc, db, &p));

  // A program record bigger than a program slot.
  db_build(mkphdr(1, 0, SaveTypeSRAM, 0, 0, 0), ops, 1, 0);
  db[512] = 0xFE;
  CHECK(!patchmem_lookup(gc, db, &p));

  // Corrupt headers.
  db_build(mkphdr(1, 0, SaveTypeSRAM, 0, 0, 0), ops, 1, 0);
  ((t_db_header*)&db[0])->signature ^= 0xFF;
  CHECK(!patchmem_lookup(gc, db, &p));

  db_build(mkphdr(1, 0, SaveTypeSRAM, 0, 0, 0), ops, 1, 0);
  ((t_db_header*)&db[0])->dbversion ^= 0xFF;
  CHECK(!patchmem_lookup(gc, db, &p));
}

//-----------------------------------------------------------------------------
// patchmem_dbinfo(): database header metadata
//-----------------------------------------------------------------------------
static void test_patchmem_dbinfo(void) {
  uint32_t noop = 0;
  uint32_t pcnt = 0;
  char version[8], date[8], creator[32];

  db_build(mkphdr(0, 0, SaveTypeSRAM, 0, 0, 0), &noop, 0, 0);
  memset(version, 0, sizeof(version));
  memset(date, 0, sizeof(date));
  memset(creator, 0, sizeof(creator));
  patchmem_dbinfo(db, &pcnt, version, date, creator);
  CHECK(pcnt == 1);
  CHECK(memcmp(version, "testdb!!", 8) == 0);
  CHECK(memcmp(date, "20261006", 8) == 0);
  CHECK(strcmp(creator, "hardening_test") == 0);
}

//-----------------------------------------------------------------------------
// patch_apply_rom(): segment walk, save routine tables, IGM header detour
//-----------------------------------------------------------------------------
static void test_patch_apply_rom(void) {
  // Deliberately 4 byte aligned: patch ops write 16/32 bit words.
  static uint32_t romw[128];      // 512 byte "full ROM"
  static uint32_t partw[64];      // 256 byte partial chunk
  uint8_t *rom = (uint8_t*)romw;
  uint8_t *part = (uint8_t*)partw;
  t_patch p, q;

  memset(&p, 0, sizeof(p));
  p.wcnt_ops = 2;
  p.save_ops = 1;
  p.irqh_ops = 1;
  p.rtc_ops = 1;
  p.save_mode = SaveTypeSRAM;
  p.op[0] = mkop(0x1, 0, 0x100);       // WAITCNT: Thumb nop
  p.op[1] = mkop(0x2, 0, 0x104);       // WAITCNT: ARM nop
  p.op[2] = mkop(0x9, 0, 0x110);       // save: FLASH read handler
  p.op[3] = mkop(0x1, 0, 0x120);       // IGM: IRQ handler nop
  p.op[4] = mkop(0x7, 2, 0x130);       // RTC: gettimedate handler

  // Whole ROM mapped at 0: every segment applies, and the entry point is
  // redirected to the in-game menu with the original address saved at 0xB8.
  memset(rom, 0, sizeof(romw));
  *(uint32_t*)&rom[0] = 0xEA000010;      // b +0x40, i.e. entry at 0x08000048
  CHECK(patch_apply_rom(rom, sizeof(romw), 0x0, true, &p, true, 0x080F0000u, 0));
  CHECK(rd32(&rom[0]) == 0xEA03BFFEu);
  CHECK(rd32(&rom[0xB8]) == 0x08000048u);
  CHECK((rd32(&rom[0x100]) & 0xFFFFu) == 0x46C0u);
  CHECK(rd32(&rom[0x104]) == 0xE1A00000u);
  CHECK(rom[0x111] == 0x18);             // psram_conversion_64k table
  CHECK(rd32(&rom[0x118]) == 0);         // no DirectSave payload address
  CHECK((rd32(&rom[0x120]) & 0xFFFFu) == 0x46C0u);
  CHECK(rom[0x131] == 0x11);             // rtc_fncs[2] is getstatus

  // WAITCNT/RTC segments disabled and no IGM: only the save handler applies,
  // and with a DirectSave address it comes from the DirectSave table.
  memset(rom, 0, sizeof(romw));
  CHECK(patch_apply_rom(rom, sizeof(romw), 0x0, false, &p, false, 0,
                        0x08800000u));
  CHECK(rd32(&rom[0]) == 0);             // header left alone
  CHECK(rd32(&rom[0x100]) == 0);         // WAITCNT ops skipped
  CHECK(rd32(&rom[0x104]) == 0);
  CHECK(rom[0x111] == 0x22);             // pdirectsave table
  CHECK(rd32(&rom[0x118]) == 0x08800000u);
  CHECK(rd32(&rom[0x120]) == 0);         // IGM segment skipped
  CHECK(rd32(&rom[0x130]) == 0);         // RTC segment skipped

  // A partial ROM chunk never gets the header detour, and 1024K FLASH saves
  // use the 128K SRAM conversion routines (which share the 64K EEPROM ones).
  memset(&q, 0, sizeof(q));
  q.save_ops = 1;
  q.irqh_ops = 1;
  q.save_mode = SaveTypeFlash1024K;
  q.op[0] = mkop(0x9, 0, BASE + 0x20);
  q.op[1] = mkop(0x8, 1, BASE + 0x40);
  memset(part, 0, sizeof(partw));
  CHECK(patch_apply_rom(part, sizeof(partw), BASE, true, &q, true,
                        0x080F0000u, 0));
  CHECK(rd32(&part[0]) == 0);
  CHECK(part[0x21] == 0x1d);             // psram_conversion_128k table
  CHECK(part[0x41] == 0x15);             // eeprom write comes from the 64K set
  CHECK(rd32(&part[0x48]) == 0);
}

//-----------------------------------------------------------------------------
// Cheat decoding: truncated or hostile .cht content
//-----------------------------------------------------------------------------
static void test_predecode_cheats(void) {
  uint32_t codes[80];

  // Plain code pairs.
  memset(codes, 0, sizeof(codes));
  codes[0] = 0x02000130;
  codes[1] = 0x0009;
  codes[2] = 0x02000132;
  codes[3] = 0x0001;
  CHECK(predecode_cheats(codes, 2));
  t_cheat_predec *e = (t_cheat_predec*)&codes[0];
  CHECK(e->opcode == 0 && e->blen == 8);
  CHECK(e->address == 0x02000130 && e->value == 0x0009);
  CHECK(e[1].opcode == 0 && e[1].blen == 8);
  CHECK(e[1].address == 0x02000132 && e[1].value == 0x0001);

  // Opcode 4 consumes one extra pair that has to be there.
  memset(codes, 0, sizeof(codes));
  codes[0] = 0x42000130;
  codes[1] = 0x0008;
  codes[2] = 0x03002000;
  codes[3] = 0x0004;
  CHECK(predecode_cheats(codes, 2));
  e = (t_cheat_predec*)&codes[0];
  CHECK(e->opcode == 8 && e->blen == 16);

  memset(codes, 0, sizeof(codes));
  codes[0] = 0x42000130;
  codes[1] = 0x0008;
  CHECK(!predecode_cheats(codes, 1));

  // Opcode 5 takes its payload length from the file and byteswaps it.
  memset(codes, 0, sizeof(codes));
  codes[0] = 0x52000130;
  codes[1] = 2;
  codes[2] = 0x03002000;
  codes[3] = 0x1122;
  codes[4] = 0x03002004;
  codes[5] = 0x3344;
  CHECK(predecode_cheats(codes, 3));
  e = (t_cheat_predec*)&codes[0];
  CHECK(e->opcode == 10 && e->blen == 24);
  CHECK(codes[2] == __builtin_bswap32(0x03002000u));
  CHECK(codes[3] == __builtin_bswap16(0x1122));
  CHECK(codes[4] == __builtin_bswap32(0x03002004u));
  CHECK(codes[5] == __builtin_bswap16(0x3344));

  // Claiming more payload pairs than the buffer holds.
  memset(codes, 0, sizeof(codes));
  codes[0] = 0x52000130;
  codes[1] = 5;
  codes[2] = 0x03002000;
  codes[3] = 0x1122;
  CHECK(!predecode_cheats(codes, 2));

  // The payload length is not bounded by t_cheat_predec.blen.
  memset(codes, 0, sizeof(codes));
  codes[0] = 0x52000130;
  codes[1] = 31;
  CHECK(!predecode_cheats(codes, 32));

  // Largest accepted payload.
  memset(codes, 0, sizeof(codes));
  codes[0] = 0x52000130;
  codes[1] = 30;
  CHECK(predecode_cheats(codes, 31));
  e = (t_cheat_predec*)&codes[0];
  CHECK(e->blen == 248);

  // The classic hostile case: a huge payload count with nothing behind it.
  // Nothing may be read or written beyond the buffer.
  uint32_t hostile[9];
  for (unsigned i = 0; i < 8; i++)
    hostile[i] = 0x03000000u + i;
  hostile[0] = 0x53000000u;
  hostile[1] = 0xFFFF;
  hostile[8] = 0xDEADBEEF;
  CHECK(!predecode_cheats(hostile, 4));
  CHECK(hostile[8] == 0xDEADBEEF);

  // An empty list is fine.
  CHECK(predecode_cheats(codes, 0));
}

static int make_line(char *out, int pairs) {
  int pos = 0;
  for (int i = 0; i < pairs; i++)
    pos += sprintf(&out[pos], "%s02000130+0009", i ? " " : "");
  out[pos] = 0;
  return pos;
}

static void test_parse_cheat_codes(void) {
  uint32_t codes[80];
  char line[1024];

  memset(codes, 0xAA, sizeof(codes));
  CHECK(parse_cheat_codes("02000130+0009 02000132+0001", codes, 16) == 2);
  CHECK(codes[0] == 0x02000130 && codes[1] == 0x0009);
  CHECK(codes[2] == 0x02000132 && codes[3] == 0x0001);

  // Separators, including the ones produced by CRLF files.
  CHECK(parse_cheat_codes("\t 02000130 0009\r", codes, 16) == 1);
  CHECK(parse_cheat_codes("++02000130++0009", codes, 16) == 1);

  CHECK(parse_cheat_codes("02000130", codes, 16) == -1);
  CHECK(parse_cheat_codes("02000130+", codes, 16) == -1);
  CHECK(parse_cheat_codes("0200ZZZZ+0009", codes, 16) == -1);
  CHECK(parse_cheat_codes("02000130+00", codes, 16) == -1);
  CHECK(parse_cheat_codes("", codes, 16) == 0);

  // Capacity is honoured instead of writing past the caller buffer.
  memset(codes, 0xAA, sizeof(codes));
  CHECK(parse_cheat_codes("02000130+0009 02000132+0001", codes, 1) == -1);
  CHECK(codes[2] == 0xAAAAAAAA);

  // t_cheathdr.codelen is 8 bits and covers every pair plus a terminator:
  // MAX_CHEAT_CODES has to keep that sum representable.
  CHECK(8 * (MAX_CHEAT_CODES + 1) <= 0xFF);

  make_line(line, MAX_CHEAT_CODES);
  CHECK(parse_cheat_codes(line, codes, MAX_CHEAT_CODES) == MAX_CHEAT_CODES);

  make_line(line, MAX_CHEAT_CODES + 1);
  CHECK(parse_cheat_codes(line, codes, MAX_CHEAT_CODES) == -1);
}

//-----------------------------------------------------------------------------
// open_read_cheats(): whole .cht file decoding into the IGM buffer
//-----------------------------------------------------------------------------
#define CHT_NAME     "hardening_test.cht"
#define CHT_BUFSIZE  8192

static uint32_t cbuf_aligned[CHT_BUFSIZE / 4];

static int write_cht(const char *data) {
  FILE *f = fopen(CHT_NAME, "wb");
  if (!f)
    return -1;
  size_t len = strlen(data), w = fwrite(data, 1, len, f);
  fclose(f);
  return w == len ? 0 : -1;
}

// The in-game menu walks the entries using only slen and codelen, so this
// mirrors that walk and validates the framing instead of the raw bytes.
static int cht_walk(uint8_t *buf, int bufsz, int *entries, char *title,
                    int titlemax, int *codelen, int *zero_tail) {
  uint32_t count = *(uint32_t*)buf;
  unsigned pos = 4;
  int n = 0;
  while (pos + sizeof(t_cheathdr) <= (unsigned)bufsz && (uint32_t)n < count) {
    t_cheathdr *e = (t_cheathdr*)&buf[pos];
    unsigned phead = sizeof(t_cheathdr) + e->slen;
    if (pos + phead + e->codelen > (unsigned)bufsz)
      return -1;
    if (e->slen == 0 || (e->slen & 3) || e->codelen == 0 || (e->codelen & 7))
      return -1;
    if (n == 0) {
      snprintf(title, titlemax, "%s", (char*)&buf[pos + sizeof(t_cheathdr)]);
      *codelen = e->codelen;
      // The last payload entry is the end-of-payload marker and must be zero.
      uint32_t *codes = (uint32_t*)&buf[pos + phead];
      *zero_tail = codes[e->codelen / 4 - 2] == 0 &&
                   codes[e->codelen / 4 - 1] == 0;
    }
    pos += phead + e->codelen;
    n++;
  }
  *entries = n;
  return (uint32_t)n == count ? (int)pos : -1;
}

static void test_open_read_cheats(void) {
  uint8_t *cbuf = (uint8_t*)cbuf_aligned;
  char title[512];
  int entries, codelen, zero_tail, ret;

  // A normal two pair line: header, title, payload and zero terminator.
  memset(cbuf_aligned, 0xAA, sizeof(cbuf_aligned));
  if (write_cht("Infinite Life\r\n02000130+0009 02000132+0001\r\n")) return;
  ret = open_read_cheats(cbuf, CHT_BUFSIZE, CHT_NAME);
  CHECK(ret > 0);
  CHECK(*(uint32_t*)cbuf == 1);
  CHECK(cht_walk(cbuf, ret, &entries, title, sizeof(title), &codelen,
                 &zero_tail) == ret);
  CHECK(entries == 1);
  CHECK(strcmp(title, "Infinite Life") == 0);
  CHECK(codelen == 8 * 3);
  CHECK(zero_tail);
  remove(CHT_NAME);

  // A missing file is reported, not partially decoded.
  memset(cbuf_aligned, 0xAA, sizeof(cbuf_aligned));
  CHECK(open_read_cheats(cbuf, CHT_BUFSIZE, "no_such_file_here.cht") == -1);

  // Titles longer than the header field are truncated, not copied verbatim.
  {
    char longline[600];
    for (int i = 0; i < 400; i++) longline[i] = 'A';
    longline[400] = 0;
    strcat(longline, "\n02000130+0009\n");
    memset(cbuf_aligned, 0xAA, sizeof(cbuf_aligned));
    CHECK(write_cht(longline) == 0);
    ret = open_read_cheats(cbuf, CHT_BUFSIZE, CHT_NAME);
    CHECK(ret > 0);
    t_cheathdr *e = (t_cheathdr*)&cbuf[4];
    CHECK(e->slen == 252);
    CHECK(((char*)&cbuf[4 + sizeof(t_cheathdr)])[251] == 0);
    CHECK(((char*)&cbuf[4 + sizeof(t_cheathdr)])[250] == 'A');
    CHECK(cht_walk(cbuf, ret, &entries, title, sizeof(title), &codelen,
                   &zero_tail) == ret);
    CHECK(strlen(title) == 251);
    remove(CHT_NAME);
  }

  // The largest accepted line: its 8 bit payload length still covers the
  // pairs plus the terminator entry.
  {
    char full[1200];
    strcpy(full, "Big line\n");
    make_line(full + strlen(full), MAX_CHEAT_CODES);
    strcat(full, "\n");
    memset(cbuf_aligned, 0xAA, sizeof(cbuf_aligned));
    CHECK(write_cht(full) == 0);
    ret = open_read_cheats(cbuf, CHT_BUFSIZE, CHT_NAME);
    CHECK(ret > 0);
    CHECK(((t_cheathdr*)&cbuf[4])->codelen == 8 * (MAX_CHEAT_CODES + 1));
    CHECK(cht_walk(cbuf, ret, &entries, title, sizeof(title), &codelen,
                   &zero_tail) == ret);
    CHECK(zero_tail);
    remove(CHT_NAME);
  }

  // One pair more than the loader accepts must abort the whole file instead
  // of writing a wrapped (and desynchronizing) payload length.
  {
    char full[1200];
    strcpy(full, "Too big\n");
    make_line(full + strlen(full), MAX_CHEAT_CODES + 1);
    strcat(full, "\n");
    memset(cbuf_aligned, 0xAA, sizeof(cbuf_aligned));
    CHECK(write_cht(full) == 0);
    CHECK(open_read_cheats(cbuf, CHT_BUFSIZE, CHT_NAME) == -1);
    remove(CHT_NAME);
  }

  // Leading whitespace on a title line is skipped, and lower case hex digits
  // parse exactly like upper case ones.
  memset(cbuf_aligned, 0xAA, sizeof(cbuf_aligned));
  CHECK(write_cht("\tIndented title\n0a00abc5+12ab 02000132+0001\n") == 0);
  ret = open_read_cheats(cbuf, CHT_BUFSIZE, CHT_NAME);
  CHECK(ret > 0);
  CHECK(cht_walk(cbuf, ret, &entries, title, sizeof(title), &codelen,
                 &zero_tail) == ret);
  CHECK(strcmp(title, "Indented title") == 0);
  CHECK(codelen == 8 * 3);
  {
    t_cheathdr *e = (t_cheathdr*)&cbuf[4];
    t_cheat_predec *cp = (t_cheat_predec*)&cbuf[4 + sizeof(t_cheathdr) + e->slen];
    CHECK(cp[0].opcode == 0 && cp[0].blen == 8);
    CHECK(cp[0].address == 0x0a00abc5u && cp[0].value == 0x12ab);
    CHECK(cp[1].address == 0x02000132u && cp[1].value == 0x0001);
    CHECK(cp[2].address == 0 && cp[2].value == 0);   // end of payload marker
  }
  remove(CHT_NAME);

  // A failing read is reported instead of returning a half parsed buffer.
  memset(cbuf_aligned, 0xAA, sizeof(cbuf_aligned));
  CHECK(write_cht("Dying card\n02000130+0009\n") == 0);
  stub_read_fail = 1;
  CHECK(open_read_cheats(cbuf, CHT_BUFSIZE, CHT_NAME) == -1);
  stub_read_fail = 0;
  CHECK(open_read_cheats(cbuf, CHT_BUFSIZE, CHT_NAME) > 0);
  remove(CHT_NAME);

  // Malformed code lines abort the file.
  memset(cbuf_aligned, 0xAA, sizeof(cbuf_aligned));
  CHECK(write_cht("Bad\n0200ZZZZ+0009\n") == 0);
  CHECK(open_read_cheats(cbuf, CHT_BUFSIZE, CHT_NAME) == -1);
  remove(CHT_NAME);

  memset(cbuf_aligned, 0xAA, sizeof(cbuf_aligned));
  CHECK(write_cht("Truncated\n02000130+\n") == 0);
  CHECK(open_read_cheats(cbuf, CHT_BUFSIZE, CHT_NAME) == -1);
  remove(CHT_NAME);

  // A hostile opcode 5 line claiming a huge payload must not run off the end
  // of the parse buffer.
  memset(cbuf_aligned, 0xAA, sizeof(cbuf_aligned));
  CHECK(write_cht("Hostile\n52000130+FFFF 03000000+1122\n") == 0);
  CHECK(open_read_cheats(cbuf, CHT_BUFSIZE, CHT_NAME) == -1);
  remove(CHT_NAME);

  // The destination buffer size is honoured.
  memset(cbuf_aligned, 0xAA, sizeof(cbuf_aligned));
  CHECK(write_cht("Some Title\n02000130+0009\n") == 0);
  CHECK(open_read_cheats(cbuf, 1000, CHT_NAME) == -1);
  memset(cbuf_aligned, 0xAA, sizeof(cbuf_aligned));
  CHECK(open_read_cheats(cbuf, CHT_BUFSIZE, CHT_NAME) > 0);
  remove(CHT_NAME);

  // Files bigger than the internal 512 byte refill window still decode, and
  // blank lines do not desynchronize the walk.
  {
    char big[2048];
    int pos = 0;
    for (int i = 0; i < 12; i++) {
      pos += sprintf(&big[pos], "Entry number %d\n", i);
      pos += sprintf(&big[pos], "0200013%X+000%X 02000200+1234\n\n", i, i);
    }
    memset(cbuf_aligned, 0xAA, sizeof(cbuf_aligned));
    CHECK(write_cht(big) == 0);
    ret = open_read_cheats(cbuf, CHT_BUFSIZE, CHT_NAME);
    CHECK(ret > 0);
    CHECK(*(uint32_t*)cbuf == 12);
    CHECK(cht_walk(cbuf, ret, &entries, title, sizeof(title), &codelen,
                   &zero_tail) == ret);
    CHECK(entries == 12);
    remove(CHT_NAME);
  }
}

//-----------------------------------------------------------------------------
//
// Note: src/directsave_emu.c is not exercised here.  Its entry points read and
// write the emulated save memory through the fixed GBA mirrors (0x08000000 and
// 0x0E000000); tests/directsave_test.c maps those addresses inside the host
// process and covers that file instead.
//
//-----------------------------------------------------------------------------
int main(void) {
  db = (uint8_t*)malloc(DB_SIZE);
  if (!db) {
    printf("hardening_test: out of memory\n");
    return 1;
  }
  init_dummies();

  test_copy_func16();
  test_payload_apply();
  test_apply_ops();
  test_patchmem_lookup();
  test_patchmem_dbinfo();
  test_patch_apply_rom();
  test_predecode_cheats();
  test_parse_cheat_codes();
  test_open_read_cheats();

  free(db);
  printf("hardening_test: %d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
