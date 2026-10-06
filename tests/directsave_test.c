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
 * Host-side regression tests for the DirectSave emulation entry points
 * (src/directsave_emu.c).
 *
 * The code under test reaches the emulated save memory through the fixed GBA
 * SRAM mirror at 0x0E000000, so this test maps that exact address into the
 * host process and fakes the SD card below it.  Everything else (the config
 * predicates and the geometry helpers) is stubbed, which makes the bounds
 * checks reachable and directly assertable:
 *
 *   - ds_read_eeprom()/ds_write_eeprom() must reject block numbers that would
 *     overflow "block_num * 8", otherwise a wrapped product passes an
 *     "offset >= size" style check and the flush targets an arbitrary SD
 *     sector, writing outside the save file.
 *   - ds_read_flash() must not let "offset + bytecount" wrap around.
 *   - ds_write_sector_flash()/ds_erase_sector_flash() must bounds check the
 *     sector number before multiplying it by 4096.
 *   - All of them must propagate SD errors instead of reporting success.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#define FAKE_SRAM_BASE   0x0E000000u
#define FAKE_SRAM_SIZE   (256u * 1024u)

// Fake SD card geometry: the save file starts at BASE_SEC and the (small)
// image is big enough for every sector the tests can address.
#define SD_SECTOR_SIZE   512u
#define SD_BASE_SEC      2048u
#define SD_TOTAL_SEC     4096u

static uint8_t *sram;
static uint8_t *sdimg;
static uint8_t *sdbase;    // Pristine copy, restored by begin().

static uint32_t g_memsize;
static int g_config_ok;
static int g_sd_fail;

// Recorded SD traffic, so the tests can prove that rejected requests never
// touch the card at all.
#define MAX_OPS     64
static struct {
  uint32_t block;
  unsigned count;
  int write;
  uint8_t digest;
} ops[MAX_OPS];
static int nop_count;

static int map_fake_sram(void) {
#ifdef _WIN32
  return VirtualAlloc((void*)(uintptr_t)FAKE_SRAM_BASE, FAKE_SRAM_SIZE,
                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) != NULL;
#else
  return mmap((void*)(uintptr_t)FAKE_SRAM_BASE, FAKE_SRAM_SIZE,
              PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
              -1, 0) != MAP_FAILED;
#endif
}

//-----------------------------------------------------------------------------
// Stubs for the firmware/hardware layer.
//-----------------------------------------------------------------------------
bool validate_config(void) {
  return g_config_ok;
}

uint32_t base_sector(void) {
  return SD_BASE_SEC;
}

uint32_t get_memory_size(void) {
  return g_memsize;
}

static int record(const uint8_t *buf, uint32_t block, unsigned cnt, int write) {
  if (nop_count >= MAX_OPS)
    return -1;
  ops[nop_count].block = block;
  ops[nop_count].count = cnt;
  ops[nop_count].write = write;
  ops[nop_count].digest = 0;
  for (unsigned i = 0; i < cnt * SD_SECTOR_SIZE; i += 61)
    ops[nop_count].digest = (uint8_t)(ops[nop_count].digest * 31 + buf[i]);
  nop_count++;
  return 0;
}

unsigned sdcard_read_blocks(uint8_t *buffer, uint32_t blocknum,
                            unsigned blkcnt) {
  if (g_sd_fail)
    return 1;
  // Record before refusing: asking for a sector outside the save file is
  // exactly what the bounds checks must prevent, so it has to stay visible
  // even though this fake card refuses the transfer.
  if (record(buffer, blocknum, blkcnt, 0))
    return 1;
  if (blocknum + blkcnt > SD_TOTAL_SEC)
    return 1;
  memcpy(buffer, &sdimg[blocknum * SD_SECTOR_SIZE], blkcnt * SD_SECTOR_SIZE);
  return 0;
}

unsigned sdcard_write_blocks(const uint8_t *buffer, uint32_t blocknum,
                             unsigned blkcnt) {
  if (g_sd_fail)
    return 1;
  if (record(buffer, blocknum, blkcnt, 1))
    return 1;
  if (blocknum + blkcnt > SD_TOTAL_SEC)
    return 1;
  memcpy(&sdimg[blocknum * SD_SECTOR_SIZE], buffer, blkcnt * SD_SECTOR_SIZE);
  return 0;
}

// src/directsave_emu.c gives min32() C99 "inline" linkage without an extern
// declaration, which only emits a callable definition in gnu89 mode.  Ask for
// the external definition here so the host build can link against it.
extern uint32_t min32(uint32_t a, uint32_t b);

#include "../src/directsave_emu.c"

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

static void begin(void) {
  nop_count = 0;
  g_sd_fail = 0;
  g_config_ok = 1;
  memset(sram, 0, FAKE_SRAM_SIZE);
  memcpy(sdimg, sdbase, SD_TOTAL_SEC * SD_SECTOR_SIZE);
}

// Number of recorded SD operations of the given direction.
static int writes(void) {
  int n = 0;
  for (int i = 0; i < nop_count; i++)
    if (ops[i].write)
      n++;
  return n;
}

static int reads(void) {
  int n = 0;
  for (int i = 0; i < nop_count; i++)
    if (!ops[i].write)
      n++;
  return n;
}

// Nothing may have been cached in the emulated save memory.
static int sram_untouched(void) {
  for (unsigned i = 0; i < FAKE_SRAM_SIZE; i++)
    if (sram[i] != 0)
      return 0;
  return 1;
}

static void fill_sd(void) {
  for (uint32_t i = 0; i < SD_TOTAL_SEC * SD_SECTOR_SIZE; i++)
    sdbase[i] = (uint8_t)(i * 131 + (i >> 9) * 7);
  memcpy(sdimg, sdbase, SD_TOTAL_SEC * SD_SECTOR_SIZE);
}

// Checks that a byte range of the fake SD sector stream was not modified by
// the call under test.
static int sd_untouched(uint32_t first, uint32_t count) {
  for (uint32_t i = first; i < first + count; i++)
    for (unsigned b = 0; b < SD_SECTOR_SIZE; b++) {
      uint32_t o = i * SD_SECTOR_SIZE + b;
      if (sdimg[o] != (uint8_t)(o * 131 + (o >> 9) * 7))
        return 0;
    }
  return 1;
}

//-----------------------------------------------------------------------------
// EEPROM (8 byte blocks, cached in SRAM, flushed one 512 byte sector)
//-----------------------------------------------------------------------------
static void test_eeprom(void) {
  uint8_t b[8];
  g_memsize = 8192;     // 512 blocks.

  // Refuse to run without a valid save configuration, and touch nothing.
  begin();
  g_config_ok = 0;
  memset(b, 0x5A, sizeof(b));
  CHECK(ds_read_eeprom(0, b) == -1);
  CHECK(ds_write_eeprom(0, b) == -1);
  CHECK(nop_count == 0);

  // In range block numbers work, and the block is stored byte reversed.
  begin();
  for (unsigned i = 0; i < 8; i++) b[i] = 0x10 + i;
  CHECK(ds_write_eeprom(3, b) == 0);
  for (unsigned i = 0; i < 8; i++)
    CHECK(sram[3 * 8 + 7 - i] == 0x10 + i);
  CHECK(writes() == 1);
  CHECK(ops[0].block == SD_BASE_SEC && ops[0].count == 1);
  memset(b, 0, sizeof(b));
  CHECK(ds_read_eeprom(3, b) == 0);
  for (unsigned i = 0; i < 8; i++)
    CHECK(b[i] == 0x10 + i);

  // Blocks in the second sector flush to the second sector.
  begin();
  CHECK(ds_write_eeprom(64 + 5, b) == 0);
  CHECK(writes() == 1 && ops[0].block == SD_BASE_SEC + 1);

  // The last valid block, and the first invalid one.
  begin();
  CHECK(ds_read_eeprom(1023, b) == 0);
  CHECK(ds_read_eeprom(1024, b) == -1);
  CHECK(ds_write_eeprom(1024, b) == -1);
  CHECK(ds_read_eeprom(0xFFFFFFFFu, b) == -1);

  // This is the interesting one: block_num * 8 overflows to 8, which used to
  // look in range.  The block must be rejected and must not reach the card.
  begin();
  CHECK(ds_write_eeprom(0x20000001u, b) == -1);
  CHECK(writes() == 0);
  CHECK(sram_untouched());
  begin();
  CHECK(ds_read_eeprom(0x20000001u, b) == -1);
  CHECK(reads() == 0);
  CHECK(sd_untouched(SD_BASE_SEC, 64));

  // Every block number above the size must be rejected, not just the ones
  // whose product wraps: sweep the boundary.
  for (uint32_t n = 1024; n < 1100; n++) {
    begin();
    CHECK(ds_write_eeprom(n, b) == -1);
    CHECK(writes() == 0);
    CHECK(sram_untouched());
  }

  // 512 byte sector flush happens for a high block inside a 128KiB save.
  g_memsize = 131072;   // 16384 blocks, 32 sectors.
  begin();
  CHECK(ds_write_eeprom(16383, b) == 0);
  CHECK(writes() == 1 && ops[0].block == SD_BASE_SEC + 255);
  begin();
  CHECK(ds_write_eeprom(16384, b) == -1);
  CHECK(writes() == 0);
  CHECK(sram_untouched());

  // SD errors are reported to the caller.
  begin();
  g_sd_fail = 1;
  CHECK(ds_write_eeprom(0, b) == -1);
  // Reads come from the SRAM cache so they cannot fail, and must not reach
  // the card either.
  CHECK(ds_read_eeprom(0, b) == 0);
  CHECK(reads() == 0);
}

//-----------------------------------------------------------------------------
// Flash reads: offset/length must not wrap around
//-----------------------------------------------------------------------------
static void test_read_flash(void) {
  uint8_t out[2048];
  g_memsize = 131072;   // 256 SD sectors.

  begin();
  g_config_ok = 0;
  CHECK(ds_read_flash(out, 0, 16) == -1);
  CHECK(nop_count == 0);

  // A plain aligned read of exactly one sector.
  begin();
  CHECK(ds_read_flash(out, 0, 512) == 0);
  CHECK(reads() == 1);
  CHECK(ops[0].block == SD_BASE_SEC && ops[0].count == 1);
  CHECK(memcmp(out, &sdimg[SD_BASE_SEC * SD_SECTOR_SIZE], 512) == 0);

  // An unaligned range spanning several sectors.
  begin();
  CHECK(ds_read_flash(out, 600, 1500) == 0);
  CHECK(ops[0].block == SD_BASE_SEC + 1 && ops[0].count == 4);
  CHECK(memcmp(out, &sdimg[(SD_BASE_SEC + 1) * SD_SECTOR_SIZE + 88], 1500) == 0);

  // The tail of the save, ending exactly at the size.
  begin();
  CHECK(ds_read_flash(out, 131072 - 1024, 1024) == 0);
  CHECK(ops[0].block == SD_BASE_SEC + 254 && ops[0].count == 2);

  // A range wider than the per-transfer limit is clamped to 64 blocks and
  // split over several reads, without losing or duplicating data.
  {
    static uint8_t bigout[131072];
    begin();
    CHECK(ds_read_flash(bigout, 0, sizeof(bigout)) == 0);
    CHECK(reads() == 4);
    CHECK(ops[0].count == 64 && ops[1].count == 64 &&
          ops[2].count == 64 && ops[3].count == 64);
    CHECK(ops[0].block == SD_BASE_SEC &&
          ops[3].block == SD_BASE_SEC + 192);
    CHECK(memcmp(bigout, &sdimg[SD_BASE_SEC * SD_SECTOR_SIZE],
                 sizeof(bigout)) == 0);
  }

  // One byte past the end.
  begin();
  CHECK(ds_read_flash(out, 131072, 1) == -1);
  CHECK(ds_read_flash(out, 131072 - 4, 5) == -1);
  CHECK(nop_count == 0);

  // The wraparound cases: "offset + bytecount" used to be computed first, so
  // these looked like short reads at the start of the save.
  begin();
  CHECK(ds_read_flash(out, 0xFFFFFFF0u, 32) == -1);
  CHECK(ds_read_flash(out, 0xFFFFFF00u, 0x400) == -1);
  CHECK(ds_read_flash(out, 0x80000000u, 0x80000000u) == -1);
  CHECK(ds_read_flash(out, 0xFFFFFFFFu, 16) == -1);
  CHECK(nop_count == 0);
  CHECK(sd_untouched(SD_BASE_SEC, 256));

  // A zero length read at a valid offset is a no-op.
  begin();
  CHECK(ds_read_flash(out, 1024, 0) == 0);
  CHECK(nop_count == 0);

  // A big read is chopped into 64 block bursts.
  begin();
  CHECK(ds_read_flash(out, 0, 2048) == 0);
  for (unsigned i = 0; i < 2048; i++)
    CHECK(out[i] == sdimg[SD_BASE_SEC * SD_SECTOR_SIZE + i]);

  // SD errors are reported to the caller.
  begin();
  g_sd_fail = 1;
  CHECK(ds_read_flash(out, 0, 512) == -1);
}

//-----------------------------------------------------------------------------
// Flash sector writes and erases
//-----------------------------------------------------------------------------
static void test_flash_sectors(void) {
  uint8_t buf[4096];
  g_memsize = 131072;   // 32 flash sectors of 4KiB.
  memset(buf, 0x5C, sizeof(buf));

  begin();
  g_config_ok = 0;
  CHECK(ds_write_sector_flash(buf, 0) == -1);
  CHECK(ds_erase_sector_flash(0) == -1);
  CHECK(ds_erase_chip_flash() == -1);
  CHECK(nop_count == 0);

  // The last valid sector, then the first invalid one.
  begin();
  CHECK(ds_write_sector_flash(buf, 31) == 0);
  CHECK(writes() == 1);
  CHECK(ops[0].block == SD_BASE_SEC + 31 * 8 && ops[0].count == 8);
  CHECK(memcmp(&sdimg[(SD_BASE_SEC + 31 * 8) * SD_SECTOR_SIZE], buf, 4096) == 0);
  begin();
  CHECK(ds_write_sector_flash(buf, 32) == -1);
  CHECK(writes() == 0);

  // A sector number whose product with 4096 wraps around.
  begin();
  CHECK(ds_write_sector_flash(buf, 0xFFFFF000u) == -1);
  CHECK(ds_write_sector_flash(buf, 0xFFFFFFFFu) == -1);
  CHECK(ds_write_sector_flash(buf, 0x80000000u) == -1);
  CHECK(writes() == 0);
  CHECK(sd_untouched(SD_BASE_SEC, 256));

  // Sector erase writes 4KiB of erased flash and stays inside the save.
  begin();
  CHECK(ds_erase_sector_flash(3) == 0);
  CHECK(writes() == 1 && ops[0].block == SD_BASE_SEC + 24 && ops[0].count == 8);
  for (unsigned i = 0; i < 4096; i++)
    CHECK(sdimg[(SD_BASE_SEC + 24) * SD_SECTOR_SIZE + i] == 0xFF);
  begin();
  CHECK(ds_erase_sector_flash(32) == -1);
  CHECK(ds_erase_sector_flash(0xFFFFF000u) == -1);
  CHECK(writes() == 0);

  // Chip erase covers the whole save in 16KiB chunks.
  begin();
  CHECK(ds_erase_chip_flash() == 0);
  CHECK(writes() == 8);
  CHECK(ops[0].block == SD_BASE_SEC && ops[0].count == 32);
  CHECK(ops[7].block == SD_BASE_SEC + 224 && ops[7].count == 32);
  CHECK(sd_untouched(SD_BASE_SEC + 256, 8));

  g_memsize = 128 * 1024 + 512;   // Not a multiple of a 16KiB chunk.
  begin();
  CHECK(ds_erase_chip_flash() == 0);
  CHECK(writes() == 9);
  CHECK(ops[8].count == 1);

  // SD errors are reported to the caller.
  begin();
  g_sd_fail = 1;
  CHECK(ds_erase_chip_flash() == -1);
  CHECK(ds_erase_sector_flash(1) == -1);
  CHECK(ds_write_sector_flash(buf, 1) == -1);
}

int main(void) {
  if (!map_fake_sram()) {
    printf("directsave_test: cannot map 0x%08X for the fake SRAM mirror\n",
           FAKE_SRAM_BASE);
    return 1;
  }
  sram = (uint8_t*)(uintptr_t)FAKE_SRAM_BASE;
  sdbase = (uint8_t*)malloc(SD_TOTAL_SEC * SD_SECTOR_SIZE);
  sdimg = (uint8_t*)malloc(SD_TOTAL_SEC * SD_SECTOR_SIZE);
  if (!sdimg || !sdbase) {
    printf("directsave_test: out of memory\n");
    return 1;
  }
  fill_sd();

  test_eeprom();
  test_read_flash();
  test_flash_sectors();

  printf("directsave_test: %d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
