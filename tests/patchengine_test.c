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
 * Host-side regression tests for the ROM patch *generator* (src/patchengine.c).
 *
 * These focus on the bounds/capacity hardening this fork added on top of
 * upstream, because those paths are otherwise only reachable with a hostile or
 * truncated ROM image:
 *
 *   - match_sig_prefix() refuses to look at more halfwords than the ROM chunk
 *     actually has left, so a signature at the very end of a ROM cannot read
 *     past the buffer.
 *   - every save/RTC/WAITCNT/IRQ handler push goes through patch_can_push(),
 *     which stops the scanner (returning false) instead of overflowing the
 *     fixed t_patch.op[] array.
 *   - the save-type strings and both flash "setup info" structure layouts are
 *     size-checked before the second word / the structure is inspected.
 *   - unserialize_patch() validates the op counts and save type coming from a
 *     cached .patch file.
 *
 * The last one is a real behavioural difference with upstream: in the v1
 * flash-setup branch the handler pointers must come from info1.  Upstream
 * still reads info2 there, which yields wrong patch addresses.  See
 * test_flash_info_v1().
 *
 * src/patchengine.c is #included so its file-static helpers can be called
 * directly, and the FatFS file calls are replaced by an in-memory fake so the
 * on-disk patch cache helpers can be driven through every error path.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/patchengine.c"

//-----------------------------------------------------------------------------
// In-memory FatFS fake.  Only the last opened file is tracked, which is all
// the patch cache helpers need.
//-----------------------------------------------------------------------------
static int fs_open_ok = 1;
static int fs_read_ok = 1;
static int fs_write_ok = 1;
static int fs_mkdir_calls;
static int fs_unlink_calls;
static int fs_close_calls;
static BYTE fs_open_mode;
static char fs_path[512];
static uint8_t fs_read_data[2048];
static unsigned fs_read_len;
static unsigned fs_read_got;
static uint8_t fs_write_data[2048];
static unsigned fs_write_len;
static unsigned fs_write_shortby;   // report fewer bytes written than asked

static void fs_reset(void) {
  fs_open_ok = 1;
  fs_read_ok = 1;
  fs_write_ok = 1;
  fs_mkdir_calls = 0;
  fs_unlink_calls = 0;
  fs_close_calls = 0;
  fs_open_mode = 0;
  fs_path[0] = 0;
  fs_read_len = 0;
  fs_read_got = 0;
  fs_write_len = 0;
  fs_write_shortby = 0;
}

FRESULT f_open(FIL *fp, const TCHAR *path, BYTE mode) {
  (void)fp;
  strcpy(fs_path, path);
  fs_open_mode = mode;
  fs_read_got = 0;
  return fs_open_ok ? FR_OK : FR_NO_FILE;
}

FRESULT f_read(FIL *fp, void *buff, UINT btr, UINT *br) {
  (void)fp;
  if (!fs_read_ok)
    return FR_DISK_ERR;
  unsigned n = btr < fs_read_len - fs_read_got ? btr : fs_read_len - fs_read_got;
  memcpy(buff, &fs_read_data[fs_read_got], n);
  fs_read_got += n;
  *br = n;
  return FR_OK;
}

FRESULT f_write(FIL *fp, const void *buff, UINT btw, UINT *bw) {
  (void)fp;
  if (!fs_write_ok)
    return FR_DISK_ERR;
  memcpy(fs_write_data, buff, btw);
  fs_write_len = btw;
  *bw = btw - fs_write_shortby;
  return FR_OK;
}

FRESULT f_close(FIL *fp) {
  (void)fp;
  fs_close_calls++;
  return FR_OK;
}

FRESULT f_mkdir(const TCHAR *path) {
  (void)path;
  fs_mkdir_calls++;
  return FR_OK;
}

FRESULT f_unlink(const TCHAR *path) {
  (void)path;
  fs_unlink_calls++;
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

#define CHECK_EQ(a, b)                              \
  do {                                              \
    checks++;                                       \
    unsigned va_ = (unsigned)(a), vb_ = (unsigned)(b);  \
    if (va_ != vb_) {                               \
      printf("FAIL %s:%d: %s == %s (0x%x != 0x%x)\n", __FILE__, __LINE__, \
             #a, #b, va_, vb_);                     \
      failures++;                                   \
    }                                               \
  } while (0)

// A synthetic ROM image with a guard region right after it: the fork's whole
// point is not reading past the end of the buffer, so every scan below asserts
// the guard is untouched afterwards.
#define ROM_WORDS       512
#define GUARD_WORDS     8
#define GUARD_VALUE     0xA5A5A5A5u

static struct {
  uint32_t rom[ROM_WORDS];
  uint32_t guard[GUARD_WORDS];
} romimg;

// Some tests deliberately put ROM data in the first guard word to prove the
// scanner does not peek at rom[i + 1] past the end; those skip that word.
static unsigned guard_skip;

// MSVC wants a name for the parameter of a function definition.
static void progress_nop(unsigned width) {
  (void)width;
}

static unsigned progress_calls;

static void progress_count(unsigned width) {
  (void)width;
  progress_calls++;
}

static void rom_reset(void) {
  memset(&romimg, 0, sizeof(romimg));
  for (unsigned i = 0; i < GUARD_WORDS; i++)
    romimg.guard[i] = GUARD_VALUE;
  progress_calls = 0;
  guard_skip = 0;
}

static int guard_intact(void) {
  for (unsigned i = guard_skip; i < GUARD_WORDS; i++)
    if (romimg.guard[i] != GUARD_VALUE)
      return 0;
  return 1;
}

// Checks the guard plus the scanner return value in one go.
static bool run_rom(t_patch_builder *pb, unsigned words) {
  bool ret = patchengine_process_rom(romimg.rom, words * sizeof(uint32_t), pb, progress_nop);
  CHECK(guard_intact());
  return ret;
}

static void plant_sig(unsigned word, const uint16_t *sig, unsigned sigsize) {
  memcpy(&romimg.rom[word], sig, sigsize);
}

// Same, but corrupts the last non-wildcard halfword (never word 0, which the
// dispatcher matches on) so match_sig_prefix() must reject the candidate.
static void plant_sig_nearmiss(unsigned word, const uint16_t *sig, unsigned sigsize) {
  unsigned k = sigsize / 2;
  plant_sig(word, sig, sigsize);
  while (k > 2 && sig[k - 1] == 0)
    k--;
  CHECK(k > 2);
  uint16_t *p16 = (uint16_t*)&romimg.rom[word];
  uint16_t v = (uint16_t)(sig[k - 1] + 1);
  CHECK(v != 0);
  p16[k - 1] = v;
}

static uint32_t mk_op(uint32_t addr, unsigned opcode, unsigned sub) {
  return addr | (opcode << 28) | (sub << 25);
}

// Pre-fills a builder so that patch_can_push() has exactly "free" slots left.
static void set_op_counts(t_patch_builder *pb, unsigned wcnt, unsigned save,
                          unsigned irqh, unsigned rtc) {
  pb->p.wcnt_ops = wcnt;
  pb->p.save_ops = save;
  pb->p.irqh_ops = irqh;
  pb->p.rtc_ops = rtc;
}

//-----------------------------------------------------------------------------
// match_sig_prefix(): the "available" bound added by this fork.
//-----------------------------------------------------------------------------
static void test_match_sig_prefix(void) {
  rom_reset();
  plant_sig(0, flash_v1_read_sig, sizeof(flash_v1_read_sig));

  // Exact fit is fine, one halfword short is not.
  CHECK(match_sig_prefix(&romimg.rom[0], sizeof(flash_v1_read_sig),
                         flash_v1_read_sig, sizeof(flash_v1_read_sig)));
  CHECK(!match_sig_prefix(&romimg.rom[0], sizeof(flash_v1_read_sig) - 2,
                          flash_v1_read_sig, sizeof(flash_v1_read_sig)));
  CHECK(!match_sig_prefix(&romimg.rom[0], 0, flash_v1_read_sig,
                          sizeof(flash_v1_read_sig)));
  // More available than needed still matches.
  CHECK(match_sig_prefix(&romimg.rom[0], 4096, flash_v1_read_sig,
                         sizeof(flash_v1_read_sig)));
  // Halfwords equal to zero in a signature are wildcards.
  static const uint16_t wild[] = { 0x1234, 0x0000, 0x5678, 0x0000 };
  uint16_t *w16 = (uint16_t*)&romimg.rom[0];
  w16[0] = 0x1234;
  w16[2] = 0x5678;
  CHECK(match_sig_prefix(&romimg.rom[0], sizeof(wild), wild, sizeof(wild)));
  // Break a non-wildcard halfword: it must stop matching.
  w16[2] = 0x5679;
  CHECK(!match_sig_prefix(&romimg.rom[0], sizeof(wild), wild, sizeof(wild)));
  // A real signature matched against itself of course matches.
  rom_reset();
  plant_sig(0, siirtc_probe_sig, sizeof(siirtc_probe_sig));
  CHECK(match_sig_prefix(&romimg.rom[0], 4096, siirtc_probe_sig,
                         sizeof(siirtc_probe_sig)));
  plant_sig(0, flash_v1_read_sig, sizeof(flash_v1_read_sig));
  plant_sig_nearmiss(0, flash_v1_read_sig, sizeof(flash_v1_read_sig));
  CHECK(!match_sig_prefix(&romimg.rom[0], 4096, flash_v1_read_sig,
                          sizeof(flash_v1_read_sig)));
  // An empty signature always matches, even with nothing available.
  const uint16_t empty[] = { 0 };
  CHECK(match_sig_prefix(&romimg.rom[0], 0, empty, 0));
}

//-----------------------------------------------------------------------------
// LDR rX, [PC, #off] back-scans used to validate WAITCNT/IRQ constants.
//-----------------------------------------------------------------------------
static void test_find_ldrpc(void) {
  rom_reset();

  // Nothing in the window: no candidate constant is "referenced".
  CHECK(!find_thumb_ldrpc((uint16_t*)romimg.rom, 0, 64));
  CHECK(!find_arm_ldrpc(romimg.rom, 0, 16));

  // Thumb: an "ldr rX, [pc, #4]" four halfwords before the target.
  const unsigned tw = 20;
  romimg.rom[tw - 2] = 0x4801;         // ldr r0, [pc, #4]
  CHECK(find_thumb_ldrpc((uint16_t*)romimg.rom, 0, tw * 2));
  CHECK(!find_thumb_ldrpc((uint16_t*)romimg.rom, tw * 2, tw * 2));   // empty window
  CHECK(!find_thumb_ldrpc((uint16_t*)romimg.rom, 0, (tw - 2) * 2));  // before the load
  // Right opcode, wrong pool offset.
  rom_reset();
  romimg.rom[tw - 2] = 0x4809;         // ldr r0, [pc, #0x24]
  CHECK(!find_thumb_ldrpc((uint16_t*)romimg.rom, 0, tw * 2));
  // Right offset but not an LDR-pool opcode.
  rom_reset();
  romimg.rom[tw - 2] = 0x6801;
  CHECK(!find_thumb_ldrpc((uint16_t*)romimg.rom, 0, tw * 2));

  // ARM: "ldr rX, [pc, #4]" three words before the target.
  const unsigned aw = 30;
  romimg.rom[aw - 3] = 0xE59F0004;
  CHECK(find_arm_ldrpc(romimg.rom, 0, aw));
  CHECK(!find_arm_ldrpc(romimg.rom, aw, aw));
  // Unaligned pool load is ignored.
  rom_reset();
  romimg.rom[aw - 3] = 0xE59F0005;
  CHECK(!find_arm_ldrpc(romimg.rom, 0, aw));
  // Wrong base register (not PC).
  rom_reset();
  romimg.rom[aw - 3] = 0xE59E0004;
  CHECK(!find_arm_ldrpc(romimg.rom, 0, aw));
  // Wrong opcode class.
  rom_reset();
  romimg.rom[aw - 3] = 0xE58F0004;
  CHECK(!find_arm_ldrpc(romimg.rom, 0, aw));
  // Aligned PC-relative load pointing elsewhere.
  rom_reset();
  romimg.rom[aw - 3] = 0x59F00044;
  CHECK(!find_arm_ldrpc(romimg.rom, 0, aw));
}

//-----------------------------------------------------------------------------
// The MAX_PATCH_OPS guard and the two push helpers it protects.
//-----------------------------------------------------------------------------
static void test_op_capacity(void) {
  t_patch_builder pb;
  patchengine_init(&pb, 0x10000);

  CHECK_EQ(patch_total_ops(&pb.p), 0);
  CHECK(patch_can_push(&pb.p, MAX_PATCH_OPS));
  CHECK(!patch_can_push(&pb.p, MAX_PATCH_OPS + 1));

  set_op_counts(&pb, 32, 32, 32, 31);
  CHECK_EQ(patch_total_ops(&pb.p), 127);
  CHECK(patch_can_push(&pb.p, 1));
  CHECK(!patch_can_push(&pb.p, 2));

  set_op_counts(&pb, 32, 32, 32, 32);
  CHECK_EQ(patch_total_ops(&pb.p), MAX_PATCH_OPS);
  CHECK(!patch_can_push(&pb.p, 1));
}

static void test_push_helpers(void) {
  t_patch_builder pb;
  patchengine_init(&pb, 0x10000);

  // A save op is inserted after the WAITCNT ops and shifts the IRQ/RTC ops.
  set_op_counts(&pb, 2, 1, 1, 1);
  pb.p.op[0] = 0x11111111;
  pb.p.op[1] = 0x22222222;
  pb.p.op[2] = 0x33333333;
  pb.p.op[3] = 0x44444444;   // irqh
  pb.p.op[4] = 0x55555555;   // rtc
  CHECK(push_save_handler(&pb.p, OPC_FLASH_HD, FLASH_CLRC_HNDLR, 0x00030000));
  CHECK_EQ(pb.p.save_ops, 2);
  CHECK_EQ(pb.p.op[0], 0x11111111);
  CHECK_EQ(pb.p.op[1], 0x22222222);
  CHECK_EQ(pb.p.op[2], 0x33333333);
  CHECK_EQ(pb.p.op[3], mk_op(0x00030000, OPC_FLASH_HD, FLASH_CLRC_HNDLR));
  CHECK_EQ(pb.p.op[4], 0x44444444);
  CHECK_EQ(pb.p.op[5], 0x55555555);

  // RTC ops go at the very end.
  CHECK(push_rtc_handler(&pb.p, RTC_GETTD_HNDLR, 0x00002000));
  CHECK_EQ(pb.p.rtc_ops, 2);
  CHECK_EQ(pb.p.op[6], mk_op(0x00002000, OPC_RTC_HD, RTC_GETTD_HNDLR));

  // Full arrays: both pushes must refuse and leave everything alone.
  set_op_counts(&pb, 40, 48, 20, 20);
  CHECK_EQ(patch_total_ops(&pb.p), MAX_PATCH_OPS);
  for (unsigned i = 0; i < MAX_PATCH_OPS; i++)
    pb.p.op[i] = 0x77770000 | i;
  CHECK(!push_save_handler(&pb.p, OPC_EEPROM_HD, EEPROM_RD_HNDLR, 0x00001000));
  CHECK(!push_rtc_handler(&pb.p, RTC_PROBE_HNDLR, 0x00001000));
  CHECK_EQ(pb.p.save_ops, 48);
  CHECK_EQ(pb.p.rtc_ops, 20);
  CHECK_EQ(pb.p.op[127], 0x7777007F);
}

//-----------------------------------------------------------------------------
// Address/classification helpers.
//-----------------------------------------------------------------------------
static void test_flash_helpers(void) {
  CHECK(isromaddr(0x08000000));
  CHECK(isromaddr(0x09FFFFFF));
  CHECK(!isromaddr(0x02000000));
  CHECK(!isromaddr(0x03000000));
  CHECK(!isromaddr(0x0E000000));

  CHECK(isromramaddr(0x08000000));
  CHECK(isromramaddr(0x09000000));
  CHECK(isromramaddr(0x02000000));
  CHECK(isromramaddr(0x03000000));
  CHECK(!isromramaddr(0x04000000));

  const uint16_t good[] = { 0x0000, 0x3D1F, 0xD4BF, 0x1B32, 0x1CC2, 0x09C2, 0x1362 };
  for (unsigned i = 0; i < sizeof(good) / sizeof(good[0]); i++)
    CHECK(valid_flashid(good[i]));
  const uint16_t bad[] = { 0x0001, 0x3D1E, 0xFFFF, 0x1363 };
  for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    CHECK(!valid_flashid(bad[i]));

  CHECK(isflash128k(0x09C2));
  CHECK(isflash128k(0x1362));
  CHECK(!isflash128k(0x3D1F));
  CHECK(!isflash128k(0x0000));
}

//-----------------------------------------------------------------------------
// filter_save_ops(): dropping ops must keep the survivors in order.
//-----------------------------------------------------------------------------
static void test_filter_save_ops(void) {
  t_patch p;
  memset(&p, 0, sizeof(p));
  p.wcnt_ops = 1;
  p.save_ops = 3;
  p.op[0] = mk_op(0x00000100, OPC_WR_BUF, 0);
  p.op[1] = mk_op(0x00001000, OPC_EEPROM_HD, EEPROM_RD_HNDLR);
  p.op[2] = mk_op(0x00002000, OPC_FLASH_HD, FLASH_CLRC_HNDLR);
  p.op[3] = mk_op(0x00003000, OPC_EEPROM_HD, EEPROM_WR_HNDLR);

  filter_save_ops(&p, OPC_FLASH_HD);
  CHECK_EQ(p.save_ops, 1);
  CHECK_EQ(p.op[0], mk_op(0x00000100, OPC_WR_BUF, 0));
  CHECK_EQ(p.op[1], mk_op(0x00002000, OPC_FLASH_HD, FLASH_CLRC_HNDLR));

  // 0xF filters everything, and an empty op list is a no-op.
  memset(&p, 0, sizeof(p));
  p.wcnt_ops = 2;
  p.save_ops = 2;
  p.op[2] = mk_op(0x00001000, OPC_EEPROM_HD, EEPROM_RD_HNDLR);
  p.op[3] = mk_op(0x00002000, OPC_FLASH_HD, FLASH_CLRC_HNDLR);
  filter_save_ops(&p, 0xF);
  CHECK_EQ(p.save_ops, 0);
  CHECK_EQ(p.wcnt_ops, 2);

  memset(&p, 0, sizeof(p));
  filter_save_ops(&p, OPC_FLASH_HD);
  CHECK_EQ(p.save_ops, 0);
}

//-----------------------------------------------------------------------------
// patchengine_init(): fixed program payloads.
//-----------------------------------------------------------------------------
static void test_init(void) {
  t_patch_builder pb;
  patchengine_init(&pb, 0x1234);

  CHECK_EQ(pb.filesize, 0x1234);
  CHECK_EQ(pb.save_type_guess, 0);
  CHECK_EQ(pb.ldatacnt, 0);
  CHECK_EQ(pb.p.wcnt_ops, 0);
  CHECK_EQ(pb.p.hole_size, 0);

  // prg 0 is the "store 32-bit zero" stub, prg 1 the redirected IRQ handler
  // address, prgs 2/3 the 64 KiB / 128 KiB flash ident replacements.
  CHECK_EQ(pb.p.prgs[0].length, 4);
  CHECK_EQ(pb.p.prgs[1].length, 4);
  uint32_t handler;
  memcpy(&handler, pb.p.prgs[1].data, 4);
  CHECK_EQ(handler, 0x03007FF4);
  CHECK_EQ(pb.p.prgs[2].length, 8);
  CHECK_EQ(pb.p.prgs[3].length, 8);
  const uint16_t f64[] = { 0x201c, 0x0200, 0x30c2, 0x4770 };
  const uint16_t f128[] = { 0x2009, 0x0200, 0x30c2, 0x4770 };
  CHECK(memcmp(pb.p.prgs[2].data, f64, sizeof(f64)) == 0);
  CHECK(memcmp(pb.p.prgs[3].data, f128, sizeof(f128)) == 0);
}

//-----------------------------------------------------------------------------
// patchengine_finalize(): every save-type resolution branch, the flash ident /
// verify rewriting, the op tail clearing and the trailing-hole annotation.
//-----------------------------------------------------------------------------
static void test_finalize(void) {
  t_patch_builder pb;

  // No strings, no signatures -> no saving at all.
  patchengine_init(&pb, 0x10000);
  patchengine_finalize(&pb);
  CHECK_EQ(pb.p.save_mode, SaveTypeNone);

  // Unambiguous SRAM: every save opcode gets dropped.
  patchengine_init(&pb, 0x10000);
  set_op_counts(&pb, 1, 2, 0, 0);
  pb.p.op[1] = mk_op(0x00001000, OPC_EEPROM_HD, EEPROM_RD_HNDLR);
  pb.p.op[2] = mk_op(0x00002000, OPC_FLASH_HD, FLASH_CLRC_HNDLR);
  pb.save_type_guess = GUESS_SRAM;
  patchengine_finalize(&pb);
  CHECK_EQ(pb.p.save_mode, SaveTypeSRAM);
  CHECK_EQ(pb.p.save_ops, 0);
  CHECK_EQ(pb.p.wcnt_ops, 1);

  // Unambiguous EEPROM: only the EEPROM handlers survive.
  patchengine_init(&pb, 0x10000);
  set_op_counts(&pb, 0, 2, 0, 0);
  pb.p.op[0] = mk_op(0x00001000, OPC_EEPROM_HD, EEPROM_RD_HNDLR);
  pb.p.op[1] = mk_op(0x00002000, OPC_FLASH_HD, FLASH_CLRC_HNDLR);
  pb.save_type_guess = GUESS_EEPROM;
  patchengine_finalize(&pb);
  CHECK_EQ(pb.p.save_mode, SaveTypeEEPROM64K);
  CHECK_EQ(pb.p.save_ops, 1);
  CHECK_EQ(pb.p.op[0], mk_op(0x00001000, OPC_EEPROM_HD, EEPROM_RD_HNDLR));

  // FLASH / FLASH64 -> 512 KiB, FLASH128 -> 1024 KiB, and the ident stub index
  // has to follow the guessed device.
  patchengine_init(&pb, 0x10000);
  set_op_counts(&pb, 0, 2, 0, 0);
  pb.p.op[0] = mk_op(0x00003000, OPC_FLASH_HD, FLASH_IDEN_HNDLR);
  pb.p.op[1] = mk_op(0x00002000, OPC_EEPROM_HD, EEPROM_RD_HNDLR);
  pb.save_type_guess = GUESS_FLASH;
  patchengine_finalize(&pb);
  CHECK_EQ(pb.p.save_mode, SaveTypeFlash512K);
  CHECK_EQ(pb.p.save_ops, 1);
  CHECK_EQ(pb.p.op[0], mk_op(0x00003000, OPC_WR_BUF, 2));

  patchengine_init(&pb, 0x10000);
  set_op_counts(&pb, 0, 1, 0, 0);
  pb.p.op[0] = mk_op(0x00003000, OPC_FLASH_HD, FLASH_IDEN_HNDLR);
  pb.save_type_guess = GUESS_FLASH64;
  patchengine_finalize(&pb);
  CHECK_EQ(pb.p.save_mode, SaveTypeFlash512K);
  CHECK_EQ(pb.p.op[0], mk_op(0x00003000, OPC_WR_BUF, 2));

  patchengine_init(&pb, 0x10000);
  set_op_counts(&pb, 0, 1, 0, 0);
  pb.p.op[0] = mk_op(0x00005000, OPC_FLASH_HD, FLASH_IDEN_HNDLR);
  pb.save_type_guess = GUESS_FLASH128;
  patchengine_finalize(&pb);
  CHECK_EQ(pb.p.save_mode, SaveTypeFlash1024K);
  CHECK_EQ(pb.p.op[0], mk_op(0x00005000, OPC_WR_BUF, 3));

  // The verify handler becomes a "return 0" (thumb) function patch.
  patchengine_init(&pb, 0x10000);
  set_op_counts(&pb, 0, 2, 0, 0);
  pb.p.op[0] = mk_op(0x00007000, OPC_FLASH_HD, FLASH_VERF_HNDLR);
  pb.p.op[1] = mk_op(0x00008000, OPC_FLASH_HD, FLASH_CLRS_HNDLR);
  pb.save_type_guess = GUESS_FLASH128;
  patchengine_finalize(&pb);
  CHECK_EQ(pb.p.save_ops, 2);
  CHECK_EQ(pb.p.op[0], mk_op(0x00007000, OPC_PATCH_FN, FUNC_RET0_THUMB));
  CHECK_EQ(pb.p.op[1], mk_op(0x00008000, OPC_FLASH_HD, FLASH_CLRS_HNDLR));

  // A save guess but no signatures: SRAM wins without filtering anything.
  patchengine_init(&pb, 0x10000);
  set_op_counts(&pb, 0, 0, 1, 1);
  pb.save_type_guess = GUESS_SRAM | GUESS_EEPROM;
  patchengine_finalize(&pb);
  CHECK_EQ(pb.p.save_mode, SaveTypeSRAM);

  // Ambiguous guess with signatures: fall back to SRAM and drop the handlers.
  patchengine_init(&pb, 0x10000);
  set_op_counts(&pb, 0, 1, 0, 0);
  pb.p.op[0] = mk_op(0x00001000, OPC_EEPROM_HD, EEPROM_RD_HNDLR);
  pb.save_type_guess = GUESS_SRAM | GUESS_FLASH;
  patchengine_finalize(&pb);
  CHECK_EQ(pb.p.save_mode, SaveTypeSRAM);
  CHECK_EQ(pb.p.save_ops, 0);

  // Unused op slots are zeroed so a cached patch is deterministic.
  patchengine_init(&pb, 0x10000);
  set_op_counts(&pb, 1, 0, 0, 0);
  pb.p.op[0] = mk_op(0x00000100, OPC_WR_BUF, 0);
  for (unsigned i = 1; i < MAX_PATCH_OPS; i++)
    pb.p.op[i] = 0xDEADBEEF;
  patchengine_finalize(&pb);
  CHECK_EQ(pb.p.op[0], mk_op(0x00000100, OPC_WR_BUF, 0));
  CHECK_EQ(pb.p.op[1], 0);
  CHECK_EQ(pb.p.op[MAX_PATCH_OPS - 1], 0);

  // Small ROMs never get a trailing hole, even with lots of repeated data.
  patchengine_init(&pb, 0x100000);
  pb.ldatacnt = 8192;
  patchengine_finalize(&pb);
  CHECK_EQ(pb.p.hole_size, 0);
  CHECK_EQ(pb.p.hole_addr, 0);

  // Big ROM with a >= 4 KiB repeated tail: hole is rounded to 1 KiB.
  patchengine_init(&pb, 33000000u);
  pb.ldatacnt = 5000;
  patchengine_finalize(&pb);
  CHECK_EQ(pb.p.hole_addr, 32995328u);
  CHECK_EQ(pb.p.hole_size, 4096u);

  // Big ROM but a tail that is too small to reuse.
  patchengine_init(&pb, 33000000u);
  pb.ldatacnt = 4095;
  patchengine_finalize(&pb);
  CHECK_EQ(pb.p.hole_size, 0);
}

//-----------------------------------------------------------------------------
// Every save/RTC signature recognised by the scanner.  For each one, three
// runs: a real match (one op), a near miss (no op), and a match while the op
// array is already full (the scan must stop and report failure).
//-----------------------------------------------------------------------------
#define SIGWORD     8
#define SIG_ROMWORDS 64

static const struct {
  const char *name;
  const uint16_t *sig;
  unsigned sigsize;
  uint32_t expect;
  int rtc;
} g_sigcases[] = {
  { "eeprom_v1_read", eeprom_v1_read_sig, sizeof(eeprom_v1_read_sig),
    (((OPC_EEPROM_HD) << 28) | ((EEPROM_RD_HNDLR) << 25)) + SIGWORD * 4, 0 },
  { "eeprom_v2_read", eeprom_v2_read_sig, sizeof(eeprom_v2_read_sig),
    (((OPC_EEPROM_HD) << 28) | ((EEPROM_RD_HNDLR) << 25)) + SIGWORD * 4, 0 },
  { "eeprom_v1_write", eeprom_v1_write_sig, sizeof(eeprom_v1_write_sig),
    (((OPC_EEPROM_HD) << 28) | ((EEPROM_WR_HNDLR) << 25)) + SIGWORD * 4, 0 },
  { "eeprom_v2_write", eeprom_v2_write_sig, sizeof(eeprom_v2_write_sig),
    (((OPC_EEPROM_HD) << 28) | ((EEPROM_WR_HNDLR) << 25)) + SIGWORD * 4, 0 },
  { "eeprom_v3_write", eeprom_v3_write_sig, sizeof(eeprom_v3_write_sig),
    (((OPC_EEPROM_HD) << 28) | ((EEPROM_WR_HNDLR) << 25)) + SIGWORD * 4, 0 },
  { "eeprom_v4_write", eeprom_v4_write_sig, sizeof(eeprom_v4_write_sig),
    (((OPC_EEPROM_HD) << 28) | ((EEPROM_WR_HNDLR) << 25)) + SIGWORD * 4, 0 },
  { "flash_v1_read", flash_v1_read_sig, sizeof(flash_v1_read_sig),
    (((OPC_FLASH_HD) << 28) | ((FLASH_READ_HNDLR) << 25)) + SIGWORD * 4, 0 },
  { "flash_v2_read", flash_v2_read_sig, sizeof(flash_v2_read_sig),
    (((OPC_FLASH_HD) << 28) | ((FLASH_READ_HNDLR) << 25)) + SIGWORD * 4, 0 },
  { "flash_v3_read", flash_v3_read_sig, sizeof(flash_v3_read_sig),
    (((OPC_FLASH_HD) << 28) | ((FLASH_READ_HNDLR) << 25)) + SIGWORD * 4, 0 },
  { "flash_v1_ident", flash_v1_ident_sig, sizeof(flash_v1_ident_sig),
    (((OPC_FLASH_HD) << 28) | ((FLASH_IDEN_HNDLR) << 25)) + SIGWORD * 4, 0 },
  { "flash_v2_ident", flash_v2_ident_sig, sizeof(flash_v2_ident_sig),
    (((OPC_FLASH_HD) << 28) | ((FLASH_IDEN_HNDLR) << 25)) + SIGWORD * 4, 0 },
  { "flash_v1_verify", flash_v1_verify_sig, sizeof(flash_v1_verify_sig),
    (((OPC_FLASH_HD) << 28) | ((FLASH_VERF_HNDLR) << 25)) + SIGWORD * 4, 0 },
  { "flash_v2_verify", flash_v2_verify_sig, sizeof(flash_v2_verify_sig),
    (((OPC_FLASH_HD) << 28) | ((FLASH_VERF_HNDLR) << 25)) + SIGWORD * 4, 0 },
  { "flash_v3_verify", flash_v3_verify_sig, sizeof(flash_v3_verify_sig),
    (((OPC_FLASH_HD) << 28) | ((FLASH_VERF_HNDLR) << 25)) + SIGWORD * 4, 0 },
  { "siirtc_probe", siirtc_probe_sig, sizeof(siirtc_probe_sig),
    (((OPC_RTC_HD) << 28) | ((RTC_PROBE_HNDLR) << 25)) + SIGWORD * 4, 1 },
  { "siirtc_reset", siirtc_reset_sync, sizeof(siirtc_reset_sync),
    (((OPC_RTC_HD) << 28) | ((RTC_RESET_HNDLR) << 25)) + SIGWORD * 4, 1 },
  { "siirtc_getstatus", siirtc_getstatus_sig, sizeof(siirtc_getstatus_sig),
    (((OPC_RTC_HD) << 28) | ((RTC_STSRD_HNDLR) << 25)) + SIGWORD * 4, 1 },
  { "siirtc_getdatetime", siirtc_getdatetime_sig, sizeof(siirtc_getdatetime_sig),
    (((OPC_RTC_HD) << 28) | ((RTC_GETTD_HNDLR) << 25)) + SIGWORD * 4, 1 },
};

static unsigned sig_ops(const t_patch_builder *pb, int rtc) {
  return rtc ? pb->p.rtc_ops : pb->p.save_ops;
}

static void test_signatures(void) {
  const unsigned n = sizeof(g_sigcases) / sizeof(g_sigcases[0]);
  CHECK_EQ(n, 18);

  for (unsigned c = 0; c < n; c++) {
    const unsigned idx = c;      // separate builders keep failures isolated
    t_patch_builder pb;

    // 1. Real match -> exactly one op with the expected encoding.
    patchengine_init(&pb, 0x10000);
    rom_reset();
    plant_sig(SIGWORD, g_sigcases[idx].sig, g_sigcases[idx].sigsize);
    CHECK(run_rom(&pb, SIG_ROMWORDS));
    CHECK_EQ(sig_ops(&pb, g_sigcases[idx].rtc), 1);
    CHECK_EQ(pb.p.wcnt_ops, 0);
    CHECK_EQ(pb.p.irqh_ops, 0);
    CHECK_EQ(pb.p.op[0], g_sigcases[idx].expect);

    // 2. Same first word, different body -> must not be treated as a match.
    patchengine_init(&pb, 0x10000);
    rom_reset();
    plant_sig_nearmiss(SIGWORD, g_sigcases[idx].sig, g_sigcases[idx].sigsize);
    CHECK(run_rom(&pb, SIG_ROMWORDS));
    CHECK_EQ(sig_ops(&pb, g_sigcases[idx].rtc), 0);

    // 3. Op array already full -> the scanner must bail out, not overrun.
    patchengine_init(&pb, 0x10000);
    rom_reset();
    plant_sig(SIGWORD, g_sigcases[idx].sig, g_sigcases[idx].sigsize);
    set_op_counts(&pb, 32, 32, 32, 32);
    for (unsigned i = 0; i < MAX_PATCH_OPS; i++)
      pb.p.op[i] = 0x77770000 | i;
    CHECK(!run_rom(&pb, SIG_ROMWORDS));
    CHECK_EQ(patch_total_ops(&pb.p), MAX_PATCH_OPS);
    CHECK_EQ(pb.p.op[MAX_PATCH_OPS - 1], 0x7777007F);
  }

  // A signature that would run off the end of the image must be rejected
  // instead of reading past the buffer.
  for (unsigned c = 0; c < n; c++) {
    t_patch_builder pb;
    patchengine_init(&pb, 0x10000);
    rom_reset();
    const unsigned sigw = g_sigcases[c].sigsize / 4;
    // Plant the word0 at the last word of the image: no room for the body.
    plant_sig(SIG_ROMWORDS - 1, g_sigcases[c].sig, 4);
    CHECK(run_rom(&pb, SIG_ROMWORDS));
    CHECK_EQ(sig_ops(&pb, g_sigcases[c].rtc), 0);
    CHECK(sigw > 0);
  }
}

//-----------------------------------------------------------------------------
// WAITCNT / IRQ handler constants, including the LDR-backscan validation and
// the capacity guard.
//-----------------------------------------------------------------------------
static void test_waitcnt_irq(void) {
  const unsigned w = 20;
  t_patch_builder pb;

  // Thumb pool load feeding the WAITCNT constant.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  romimg.rom[w - 2] = 0x4801;
  romimg.rom[w] = 0x04000204;
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.wcnt_ops, 1);
  CHECK_EQ(pb.p.op[0], mk_op(w * 4, OPC_WR_BUF, 0));

  // ARM pool load does the same job.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  romimg.rom[w - 3] = 0xE59F0004;
  romimg.rom[w] = 0x04000204;
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.wcnt_ops, 1);
  CHECK_EQ(pb.p.op[0], mk_op(w * 4, OPC_WR_BUF, 0));

  // Unreferenced constant: patching it would break the game.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  romimg.rom[w] = 0x04000204;
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.wcnt_ops, 0);

  // Near-WAITCNT values are not interesting.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  romimg.rom[w - 2] = 0x4801;
  romimg.rom[w] = 0x04000205;
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.wcnt_ops, 0);

  // Full op array.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  romimg.rom[w - 2] = 0x4801;
  romimg.rom[w] = 0x04000204;
  set_op_counts(&pb, 32, 32, 32, 32);
  CHECK(!run_rom(&pb, 64));

  // IRQ handler address, referenced and unreferenced.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  romimg.rom[w - 2] = 0x4801;
  romimg.rom[w] = 0x03007FFC;
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.irqh_ops, 1);
  CHECK_EQ(pb.p.op[0], mk_op(w * 4, OPC_WR_BUF, 1));

  patchengine_init(&pb, 0x10000);
  rom_reset();
  romimg.rom[w] = 0x03007FFC;
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.irqh_ops, 0);

  patchengine_init(&pb, 0x10000);
  rom_reset();
  romimg.rom[w - 3] = 0xE59F0004;
  romimg.rom[w] = 0x03007FFC;
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.irqh_ops, 1);

  patchengine_init(&pb, 0x10000);
  set_op_counts(&pb, 32, 32, 32, 32);
  rom_reset();
  romimg.rom[w - 2] = 0x4801;
  romimg.rom[w] = 0x03007FFC;
  CHECK(!run_rom(&pb, 64));

  // A WAITCNT op is inserted in front of previously found save/IRQ/RTC ops.
  patchengine_init(&pb, 0x10000);
  set_op_counts(&pb, 1, 1, 1, 1);
  pb.p.op[0] = mk_op(0x00000040, OPC_WR_BUF, 0);
  pb.p.op[1] = mk_op(0x00001000, OPC_EEPROM_HD, EEPROM_RD_HNDLR);
  pb.p.op[2] = mk_op(0x00002000, OPC_WR_BUF, 1);
  pb.p.op[3] = mk_op(0x00003000, OPC_RTC_HD, RTC_PROBE_HNDLR);
  rom_reset();
  romimg.rom[w - 2] = 0x4801;
  romimg.rom[w] = 0x04000204;
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.wcnt_ops, 2);
  CHECK_EQ(pb.p.op[0], mk_op(0x00000040, OPC_WR_BUF, 0));
  CHECK_EQ(pb.p.op[1], mk_op(w * 4, OPC_WR_BUF, 0));
  CHECK_EQ(pb.p.op[2], mk_op(0x00001000, OPC_EEPROM_HD, EEPROM_RD_HNDLR));
  CHECK_EQ(pb.p.op[3], mk_op(0x00002000, OPC_WR_BUF, 1));
  CHECK_EQ(pb.p.op[4], mk_op(0x00003000, OPC_RTC_HD, RTC_PROBE_HNDLR));
}

//-----------------------------------------------------------------------------
// Save type / RTC identification strings, and the "is there a second word?"
// bound that stops the scanner reading off the end of the image.
//-----------------------------------------------------------------------------
static void test_save_strings(void) {
  t_patch_builder pb;

  struct { const char *name; uint32_t w0, w1; unsigned guess; int rtc; } cases[] = {
    { "sram_v11", SRAM_V_WORD0, SRAM_V_WORD1, GUESS_SRAM, 0 },
    { "sram_fv", SRAM_V_WORD0, SRAM_F_WORD1, GUESS_SRAM, 0 },
    { "eeprom", EEPROM_V_WORD0, EEPROM_V_WORD1, GUESS_EEPROM, 0 },
    { "flash", FLASH_V_WORD0, FLASH_V_WORD1, GUESS_FLASH, 0 },
    { "flash512", FLASH_V_WORD0, FLASH512_WORD1, GUESS_FLASH64, 0 },
    { "flash1m", FLASH_V_WORD0, FLASH1M_WORD1, GUESS_FLASH128, 0 },
  };
  const unsigned n = sizeof(cases) / sizeof(cases[0]);

  for (unsigned c = 0; c < n; c++) {
    // Matching pair -> guess set.
    patchengine_init(&pb, 0x10000);
    rom_reset();
    romimg.rom[8] = cases[c].w0;
    romimg.rom[9] = cases[c].w1;
    CHECK(run_rom(&pb, 64));
    CHECK_EQ(pb.save_type_guess, cases[c].guess);

    // Wrong second word -> no guess.
    patchengine_init(&pb, 0x10000);
    rom_reset();
    romimg.rom[8] = cases[c].w0;
    romimg.rom[9] = 0xFFFFFFFF;
    CHECK(run_rom(&pb, 64));
    CHECK_EQ(pb.save_type_guess, 0);

    // Marker in the very last word of the image: even when the *next* word in
    // memory holds the matching second half, it is outside the image and must
    // not be looked at.  Upstream reads it and would report a save type.
    patchengine_init(&pb, 0x10000);
    rom_reset();
    romimg.rom[ROM_WORDS - 1] = cases[c].w0;
    romimg.guard[0] = cases[c].w1;
    guard_skip = 1;
    CHECK(run_rom(&pb, ROM_WORDS));
    CHECK_EQ(pb.save_type_guess, 0);
    guard_skip = 0;
    rom_reset();
  }

  // RTC string.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  romimg.rom[8] = RTC_V_WORD0;
  romimg.rom[9] = RTC_V_WORD1;
  CHECK(run_rom(&pb, 64));
  CHECK(pb.rtc_guess);

  patchengine_init(&pb, 0x10000);
  rom_reset();
  romimg.rom[8] = RTC_V_WORD0;
  CHECK(run_rom(&pb, 64));
  CHECK(!pb.rtc_guess);

  patchengine_init(&pb, 0x10000);
  rom_reset();
  romimg.rom[8] = RTC_V_WORD0;
  romimg.rom[9] = 0;
  CHECK(run_rom(&pb, 64));
  CHECK(!pb.rtc_guess);

  patchengine_init(&pb, 0x10000);
  rom_reset();
  romimg.rom[ROM_WORDS - 1] = RTC_V_WORD0;
  romimg.guard[0] = RTC_V_WORD1;
  guard_skip = 1;
  CHECK(run_rom(&pb, ROM_WORDS));
  CHECK(!pb.rtc_guess);
  guard_skip = 0;

  // Several strings at once accumulate the guesses.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  romimg.rom[8] = SRAM_V_WORD0;
  romimg.rom[9] = SRAM_V_WORD1;
  romimg.rom[16] = EEPROM_V_WORD0;
  romimg.rom[17] = EEPROM_V_WORD1;
  romimg.rom[24] = FLASH_V_WORD0;
  romimg.rom[25] = FLASH512_WORD1;
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.save_type_guess, GUESS_SRAM | GUESS_EEPROM | GUESS_FLASH64);

  // Repeated trailing words are counted, which feeds the hole calculation.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  for (unsigned i = 0; i < 32; i++)
    romimg.rom[i] = 0xFFFFFFFF;
  CHECK(run_rom(&pb, 32));
  CHECK_EQ(pb.ldatacnt, 4 * 31);
}

//-----------------------------------------------------------------------------
// Flash "setup info" structures.  The v1 branch must read its pointers from
// info1: upstream v0.21 still dereferences info2 there, which produces save
// handler patches for the wrong addresses (one word shifted in the struct).
//-----------------------------------------------------------------------------
static void fill_flash_v1(t_flash_setup_info_v1 *f, uint16_t id) {
  memset(f, 0, sizeof(*f));
  f->program_sector_fnptr = 0x08010001;
  f->erase_chip_fnptr = 0x08020001;
  f->erase_sector_fnptr = 0x08030001;
  f->wait_flash_write_fnptr = 0x08040001;
  f->timeout_lut_ptr = 0x02030000;
  f->flash_size = 65536;
  f->sector_size = 4096;
  f->shift_amount = 12;
  f->sector_count = 16;
  f->top_value = 0x1234;
  f->ws[0] = 1;
  f->ws[1] = 2;
  f->device_id = id;
}

static void fill_flash_v2(t_flash_setup_info_v2 *f, uint16_t id) {
  memset(f, 0, sizeof(*f));
  f->program_byte_fnptr = 0x08010001;
  f->program_sector_fnptr = 0x08020001;
  f->erase_chip_fnptr = 0x08030001;
  f->erase_sector_fnptr = 0x08040001;
  f->wait_flash_write_fnptr = 0x08050001;
  f->timeout_lut_ptr = 0x03000000;
  f->flash_size = 65536;
  f->sector_size = 4096;
  f->shift_amount = 12;
  f->sector_count = 16;
  f->top_value = 0x1234;
  f->ws[0] = 1;
  f->ws[1] = 2;
  f->device_id = id;
}

static void test_flash_info_v1(void) {
  t_flash_setup_info_v1 f1;
  t_patch_builder pb;
  CHECK_EQ(sizeof(f1), 44u);

  // Recognised v1 table -> three flash handler patches taken from info1.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  fill_flash_v1(&f1, 0x3D1F);
  memcpy(&romimg.rom[8], &f1, sizeof(f1));
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.save_ops, 3);
  CHECK_EQ(pb.p.op[0], mk_op(0x00020000, OPC_FLASH_HD, FLASH_CLRC_HNDLR));
  CHECK_EQ(pb.p.op[1], mk_op(0x00030000, OPC_FLASH_HD, FLASH_CLRS_HNDLR));
  CHECK_EQ(pb.p.op[2], mk_op(0x00010000, OPC_FLASH_HD, FLASH_WRTS_HNDLR));
  CHECK_EQ(pb.flash64cnt, 1);
  CHECK_EQ(pb.flash128cnt, 0);

  // Exactly one v1 structure fits at the tail: the v2 size test must fail and
  // the v1 branch must still run.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  fill_flash_v1(&f1, 0x3D1F);
  const unsigned tail = ROM_WORDS - sizeof(f1) / 4;
  memcpy(&romimg.rom[tail], &f1, sizeof(f1));
  CHECK(run_rom(&pb, ROM_WORDS));
  CHECK_EQ(pb.p.save_ops, 3);
  CHECK_EQ(pb.p.op[0], mk_op(0x00020000, OPC_FLASH_HD, FLASH_CLRC_HNDLR));

  // 128 KiB device ids bump the other counter.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  fill_flash_v1(&f1, 0x09C2);
  memcpy(&romimg.rom[8], &f1, sizeof(f1));
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.flash128cnt, 1);
  CHECK_EQ(pb.flash64cnt, 0);

  // id 0 is accepted as "unknown" but does not count towards a size guess.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  fill_flash_v1(&f1, 0x0000);
  memcpy(&romimg.rom[8], &f1, sizeof(f1));
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.save_ops, 3);
  CHECK_EQ(pb.flash64cnt, 0);
  CHECK_EQ(pb.flash128cnt, 0);

  // Unknown device id -> ignore the table, but still skip it.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  fill_flash_v1(&f1, 0x1234);
  memcpy(&romimg.rom[8], &f1, sizeof(f1));
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.save_ops, 0);

  // Inconsistent geometry -> ignore.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  fill_flash_v1(&f1, 0x3D1F);
  f1.sector_count = 8;
  memcpy(&romimg.rom[8], &f1, sizeof(f1));
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.save_ops, 0);

  // Not enough room for the whole structure -> do not inspect it.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  fill_flash_v1(&f1, 0x3D1F);
  memcpy(&romimg.rom[ROM_WORDS - 4], &f1, 16);
  CHECK(run_rom(&pb, ROM_WORDS));
  CHECK_EQ(pb.p.save_ops, 0);

  // The op array fills up part-way through the three pushes.
  for (unsigned used = 125; used <= 127; used++) {
    patchengine_init(&pb, 0x10000);
    rom_reset();
    fill_flash_v1(&f1, 0x3D1F);
    memcpy(&romimg.rom[8], &f1, sizeof(f1));
    set_op_counts(&pb, used - 3, 0, 2, 1);
    CHECK_EQ(patch_total_ops(&pb.p), used);
    if (used == 125) {
      CHECK(run_rom(&pb, 64));
      CHECK_EQ(pb.p.save_ops, 3);
    } else {
      CHECK(!run_rom(&pb, 64));
      // 126 -> two pushes fit, 127 -> only one.
      CHECK_EQ(pb.p.save_ops, 127 - used + 1);
    }
  }
}

static void test_flash_info_v2(void) {
  t_flash_setup_info_v2 f2;
  t_patch_builder pb;
  CHECK_EQ(sizeof(f2), 48u);

  patchengine_init(&pb, 0x10000);
  rom_reset();
  fill_flash_v2(&f2, 0x3D1F);
  memcpy(&romimg.rom[8], &f2, sizeof(f2));
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.save_ops, 4);
  CHECK_EQ(pb.p.op[0], mk_op(0x00030000, OPC_FLASH_HD, FLASH_CLRC_HNDLR));
  CHECK_EQ(pb.p.op[1], mk_op(0x00040000, OPC_FLASH_HD, FLASH_CLRS_HNDLR));
  CHECK_EQ(pb.p.op[2], mk_op(0x00020000, OPC_FLASH_HD, FLASH_WRTS_HNDLR));
  CHECK_EQ(pb.p.op[3], mk_op(0x00010000, OPC_FLASH_HD, FLASH_WRBT_HNDLR));
  CHECK_EQ(pb.flash64cnt, 1);

  patchengine_init(&pb, 0x10000);
  rom_reset();
  fill_flash_v2(&f2, 0x1362);
  memcpy(&romimg.rom[8], &f2, sizeof(f2));
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.flash128cnt, 1);
  CHECK_EQ(pb.flash64cnt, 0);

  patchengine_init(&pb, 0x10000);
  rom_reset();
  fill_flash_v2(&f2, 0x0000);
  memcpy(&romimg.rom[8], &f2, sizeof(f2));
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.save_ops, 4);
  CHECK_EQ(pb.flash64cnt, 0);
  CHECK_EQ(pb.flash128cnt, 0);

  // Bad id / bad geometry are still skipped, but the scanner advances 10 words.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  fill_flash_v2(&f2, 0x1234);
  memcpy(&romimg.rom[8], &f2, sizeof(f2));
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.save_ops, 0);

  patchengine_init(&pb, 0x10000);
  rom_reset();
  fill_flash_v2(&f2, 0x3D1F);
  f2.sector_count = 32;
  memcpy(&romimg.rom[8], &f2, sizeof(f2));
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.save_ops, 0);

  // Everything looks right except the program-byte pointer, which is not in
  // ROM, so the v2 layout is rejected. The same bytes read one word later do
  // form a valid v1 table though, and that shifted view is what gets used:
  // CLRC/CLRS/WRTS come from erase_chip/erase_sector/program_sector.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  fill_flash_v2(&f2, 0x3D1F);
  f2.program_byte_fnptr = 0x02000000;
  memcpy(&romimg.rom[8], &f2, sizeof(f2));
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.save_ops, 3);
  CHECK_EQ(pb.p.op[0], mk_op(0x00030000, OPC_FLASH_HD, FLASH_CLRC_HNDLR));
  CHECK_EQ(pb.p.op[1], mk_op(0x00040000, OPC_FLASH_HD, FLASH_CLRS_HNDLR));
  CHECK_EQ(pb.p.op[2], mk_op(0x00020000, OPC_FLASH_HD, FLASH_WRTS_HNDLR));
  CHECK_EQ(pb.flash64cnt, 1);

  // Break the shifted v1 view too: no interpretation applies and the scanner
  // walks the whole image without emitting anything.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  fill_flash_v2(&f2, 0x3D1F);
  f2.program_byte_fnptr = 0x02000000;
  f2.erase_sector_fnptr = 0x02000002;
  memcpy(&romimg.rom[8], &f2, sizeof(f2));
  CHECK(run_rom(&pb, 64));
  CHECK_EQ(pb.p.save_ops, 0);
  CHECK_EQ(pb.flash64cnt, 0);
  CHECK_EQ(pb.flash128cnt, 0);

  // A structure too close to the end of the image is left alone.
  patchengine_init(&pb, 0x10000);
  rom_reset();
  fill_flash_v2(&f2, 0x3D1F);
  memcpy(&romimg.rom[ROM_WORDS - 8], &f2, 32);
  CHECK(run_rom(&pb, ROM_WORDS));
  CHECK_EQ(pb.p.save_ops, 0);

  // Capacity exhausted part-way through the four pushes.
  for (unsigned used = 124; used <= 127; used++) {
    patchengine_init(&pb, 0x10000);
    rom_reset();
    fill_flash_v2(&f2, 0x3D1F);
    memcpy(&romimg.rom[8], &f2, sizeof(f2));
    set_op_counts(&pb, used - 3, 0, 2, 1);
    CHECK_EQ(patch_total_ops(&pb.p), used);
    if (used == 124) {
      CHECK(run_rom(&pb, 64));
      CHECK_EQ(pb.p.save_ops, 4);
    } else {
      CHECK(!run_rom(&pb, 64));
      CHECK_EQ(pb.p.save_ops, 127 - used + 1);
    }
  }
}

//-----------------------------------------------------------------------------
// Patch cache (de)serialization, including the validation of untrusted .patch
// files added by this fork.
//-----------------------------------------------------------------------------
// Builds a fully populated patch by hand (patchengine_finalize() would
// re-derive the save type and filter the ops again).
static void make_patch(t_patch *p) {
  t_patch_builder pb;
  patchengine_init(&pb, 0x100000);
  set_op_counts(&pb, 2, 1, 1, 1);
  pb.p.op[0] = mk_op(0x00000100, OPC_WR_BUF, 0);
  pb.p.op[1] = mk_op(0x00000200, OPC_WR_BUF, 0);
  pb.p.op[2] = mk_op(0x00001000, OPC_FLASH_HD, FLASH_CLRC_HNDLR);
  pb.p.op[3] = mk_op(0x00002000, OPC_WR_BUF, 1);
  pb.p.op[4] = mk_op(0x00003000, OPC_RTC_HD, RTC_PROBE_HNDLR);
  pb.p.save_mode = SaveTypeFlash512K;
  pb.p.hole_addr = 0x00F00000;
  pb.p.hole_size = 0x00004000;
  *p = pb.p;
}

static unsigned ser_len;
static uint8_t serbuf[2048];

static void test_serialize(void) {
  t_patch src, dst;
  make_patch(&src);
  memset(&dst, 0xA5, sizeof(dst));

  ser_len = serialize_patch(&src, serbuf);
  CHECK_EQ(ser_len, 800u);
  CHECK(memcmp(serbuf, "SUPERFWPATCHV01", 15) == 0);
  CHECK_EQ(serbuf[16], src.wcnt_ops);
  CHECK_EQ(serbuf[17], src.save_ops);
  CHECK_EQ(serbuf[18], src.save_mode);
  CHECK_EQ(serbuf[19], src.irqh_ops);
  CHECK_EQ(serbuf[20], src.rtc_ops);
  CHECK_EQ(serbuf[30], 0);
  CHECK_EQ(serbuf[31], 0);

  CHECK(unserialize_patch(serbuf, ser_len, &dst));
  CHECK_EQ(dst.wcnt_ops, src.wcnt_ops);
  CHECK_EQ(dst.save_ops, src.save_ops);
  CHECK_EQ(dst.save_mode, src.save_mode);
  CHECK_EQ(dst.irqh_ops, src.irqh_ops);
  CHECK_EQ(dst.rtc_ops, src.rtc_ops);
  CHECK_EQ(dst.hole_addr, src.hole_addr);
  CHECK_EQ(dst.hole_size, src.hole_size);
  CHECK(memcmp(dst.op, src.op, sizeof(dst.op)) == 0);
  CHECK(memcmp(dst.prgs, src.prgs, sizeof(dst.prgs)) == 0);

  // A hole of zero round-trips too (the fields are stored in 1 KiB units).
  t_patch_builder pb;
  patchengine_init(&pb, 0x100000);
  serialize_patch(&pb.p, serbuf);
  memset(&dst, 0, sizeof(dst));
  CHECK(unserialize_patch(serbuf, ser_len, &dst));
  CHECK_EQ(dst.hole_addr, 0);
  CHECK_EQ(dst.hole_size, 0);

  // Wrong length or magic must be rejected.
  t_patch p;
  memset(&p, 0, sizeof(p));
  CHECK(!unserialize_patch(serbuf, ser_len - 1, &p));
  CHECK(!unserialize_patch(serbuf, ser_len + 4, &p));
  serbuf[0] = 'X';
  CHECK(!unserialize_patch(serbuf, ser_len, &p));
  serbuf[0] = 'S';
  CHECK(unserialize_patch(serbuf, ser_len, &p));

  // Out of range save type coming from the file.
  serbuf[18] = SaveTypeFlash1024K;
  CHECK(unserialize_patch(serbuf, ser_len, &p));
  serbuf[18] = SaveTypeFlash1024K + 1;
  CHECK(!unserialize_patch(serbuf, ser_len, &p));
  serbuf[18] = 255;
  CHECK(!unserialize_patch(serbuf, ser_len, &p));
  serbuf[18] = SaveTypeFlash512K;

  // Op counts adding up to more than the fixed op array can hold.  Upstream
  // accepts these and the patch applier then walks off the end of t_patch.
  serbuf[16] = 40;
  serbuf[17] = 40;
  serbuf[19] = 25;
  serbuf[20] = 25;
  CHECK(!unserialize_patch(serbuf, ser_len, &p));
  // Exactly at the limit is fine.
  serbuf[16] = 32;
  serbuf[17] = 32;
  serbuf[19] = 32;
  serbuf[20] = 32;
  CHECK(unserialize_patch(serbuf, ser_len, &p));
  CHECK_EQ(patch_total_ops(&p), MAX_PATCH_OPS);
}

//-----------------------------------------------------------------------------
// The on-disk patch cache helpers: file name derivation and every I/O failure.
//-----------------------------------------------------------------------------
static void stage_patch_file(void) {
  t_patch src;
  make_patch(&src);
  ser_len = serialize_patch(&src, serbuf);
  memcpy(fs_read_data, serbuf, ser_len);
  fs_read_len = ser_len;
}

static void test_patch_file_helpers(void) {
  t_patch p;

  stage_patch_file();

  // load_rom_patches(): sibling .patch file next to the ROM.
  fs_reset();
  stage_patch_file();
  memset(&p, 0, sizeof(p));
  CHECK(load_rom_patches("sd:/games/rom.gba", &p));
  CHECK_EQ(fs_open_mode, FA_READ);
  CHECK(load_rom_patches("rom.gba", &p));
  CHECK(strcmp(fs_path, "rom.patch") == 0);
  CHECK_EQ(p.wcnt_ops, 2);
  CHECK_EQ(p.save_mode, SaveTypeFlash512K);

  // ROM without an extension still gets a sane name.
  fs_reset();
  stage_patch_file();
  CHECK(load_rom_patches("romgba", &p));
  CHECK(strcmp(fs_path, "romgba.patch") == 0);

  fs_reset();
  stage_patch_file();
  fs_open_ok = 0;
  CHECK(!load_rom_patches("rom.gba", &p));

  fs_reset();
  stage_patch_file();
  fs_read_ok = 0;
  CHECK(!load_rom_patches("rom.gba", &p));

  // A truncated file is rejected by unserialize_patch().
  fs_reset();
  stage_patch_file();
  fs_read_len = 16;
  CHECK(!load_rom_patches("rom.gba", &p));

  // load_cached_patches(): PATCHDB_PATH + basename of the ROM.
  fs_reset();
  stage_patch_file();
  CHECK(load_cached_patches("sd:/dir/subdir/rom.gba", &p));
  CHECK(strcmp(fs_path, PATCHDB_PATH "rom.patch") == 0);

  fs_reset();
  stage_patch_file();
  CHECK(load_cached_patches("rom.gba", &p));
  CHECK(strcmp(fs_path, PATCHDB_PATH "rom.patch") == 0);

  fs_reset();
  stage_patch_file();
  fs_open_ok = 0;
  CHECK(!load_cached_patches("rom.gba", &p));

  fs_reset();
  stage_patch_file();
  fs_read_ok = 0;
  CHECK(!load_cached_patches("rom.gba", &p));

  fs_reset();
  stage_patch_file();
  fs_read_len = 1;
  CHECK(!load_cached_patches("rom.gba", &p));

  // write_patches_cache(): creates the folders, replaces the old entry.
  t_patch src;
  make_patch(&src);
  fs_reset();
  CHECK(write_patches_cache("sd:/dir/rom.gba", &src));
  CHECK_EQ(fs_mkdir_calls, 2);
  CHECK_EQ(fs_unlink_calls, 1);
  CHECK_EQ(fs_close_calls, 1);
  CHECK_EQ(fs_open_mode, FA_WRITE | FA_CREATE_ALWAYS);
  CHECK(strcmp(fs_path, PATCHDB_PATH "rom.patch") == 0);
  CHECK_EQ(fs_write_len, 800u);
  CHECK(memcmp(fs_write_data, "SUPERFWPATCHV01", 15) == 0);

  fs_reset();
  fs_open_ok = 0;
  CHECK(!write_patches_cache("rom.gba", &src));
  CHECK_EQ(fs_close_calls, 0);

  // Write error: the half written file must be removed again.
  fs_reset();
  fs_write_ok = 0;
  CHECK(!write_patches_cache("rom.gba", &src));
  CHECK_EQ(fs_close_calls, 1);
  CHECK_EQ(fs_unlink_calls, 2);

  // Short write reports failure as well.
  fs_reset();
  fs_write_shortby = 1;
  CHECK(!write_patches_cache("rom.gba", &src));
  CHECK_EQ(fs_close_calls, 1);
}

//-----------------------------------------------------------------------------
// Progress callback: invoked every 32768 words (the scanner runs on IWRAM and
// yields to the caller so the UI can update).
//-----------------------------------------------------------------------------
static void test_progress_callback(void) {
  t_patch_builder pb;
  const unsigned words = 32768 + 1;
  uint32_t *big = (uint32_t*)malloc(words * sizeof(uint32_t));
  CHECK(big != NULL);
  if (!big)
    return;
  memset(big, 0, words * sizeof(uint32_t));

  patchengine_init(&pb, words * 4);
  progress_calls = 0;
  CHECK(patchengine_process_rom(big, words * sizeof(uint32_t), &pb, progress_count));
  CHECK_EQ(progress_calls, 2);

  progress_calls = 0;
  CHECK(patchengine_process_rom(big, 64 * sizeof(uint32_t), &pb, progress_count));
  CHECK_EQ(progress_calls, 1);

  free(big);
}

int main(void) {
  test_match_sig_prefix();
  test_find_ldrpc();
  test_op_capacity();
  test_push_helpers();
  test_flash_helpers();
  test_filter_save_ops();
  test_init();
  test_finalize();
  test_signatures();
  test_waitcnt_irq();
  test_save_strings();
  test_flash_info_v1();
  test_flash_info_v2();
  test_serialize();
  test_patch_file_helpers();
  test_progress_callback();

  printf("patchengine_test: %d checks, %d failures\n", checks, failures);
  return failures != 0;
}
