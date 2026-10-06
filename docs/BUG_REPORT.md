# SuperFW Bug Report

Four defects found while auditing the fork for the v0.21 rebase.  All of
them are plain software defects, reachable through cheat files, patch
databases or SD card errors; none is related to the Supercard hardware
compromises (CPLD glue logic, slow SDRAM, console timing margins).

## Bug #1 — `predecode_cheats` Outer Loop Variable Corrupted by Inner Loop

- **File**: `src/cheats.c`
- **Line**: ~23-44
- **Severity**: Medium (out-of-bounds read → potential crash or data corruption)
- **Trigger**: Cheat file with opcode `0x10` (multi-code) where `value` exceeds remaining entries
- **Details**:
  - Inner `for (j < h.value)` increments outer loop variable `i`
  - No guard `i < cnt` inside inner loop
  - `codes[2*i]` reads past buffer end → undefined behavior
- **Code**:
  ```c
  for (unsigned j = 0; j < h.value; j++) {
    i++;  // ← modifies outer loop var, no bounds check
    uint32_t addr = codes[2*i];
    uint16_t valu = codes[2*i+1];
  }
  ```

---

## Bug #2 — `patchmem_lookup` Program Payload Copied Without a Page Bound

- **File**: `src/patcher.c`
- **Line**: ~57-68
- **Severity**: None as it stands, latent if the constants change
- **Trigger**: A program record whose payload would cross the 512-byte page end
- **Details**:
  - `i += cnt` in loop body + `i++` in for-header = `i` advances `cnt+1`
  - `memcpy` reads `&pgrpage[i+1]` for `cnt` bytes with no check that the
    range stays inside the 512-byte program page
  - Not reachable with the current constants: `cnt` is capped at
    `sizeof(t_patch_prog.data)` (60) and the loop stops at
    `MAX_PATCH_PRG` (4) records, so the last byte the memcpy can read is
    `3 * 61 + 1 + 60 = 244`.  The page cannot be crossed unless someone
    raises those limits, which is what the added bound protects against.
- **Code**:
  ```c
  for (int i = 0; i < 512 && pgn < MAX_PATCH_PRG; i++) {
    unsigned cnt = pgrpage[i];
    ...
    memcpy(pdata->prgs[pgn++].data, &pgrpage[i+1], cnt);
    i += cnt;  // ← may cause source range to exceed 512-byte page
  }
  ```

---

## Bug #3 — `check_pending_saves` Unconditional Sentinel Deletion

- **File**: `src/main.c`
- **Line**: ~88-97
- **Severity**: High (data loss — save permanently lost on SD write failure)
- **Trigger**: Reboot after game session with pending save; SD write fails (card error / disk full)
- **Details**:
  - `f_unlink(PENDING_SAVE_FILEPATH)` is called regardless of success/failure
  - If `flush_pending_sram()` returns `ERR_SAVE_FLUSH_WRITEFAIL`, error is shown for 4 seconds
  - Then sentinel file is deleted anyway → pending save data is irrecoverable
  - No retry mechanism on next boot
- **Code**:
  ```c
  unsigned ecode = flush_pending_sram();
  if (ecode == ERR_SAVE_FLUSH_WRITEFAIL) {
    display_info_clear();
    display_info_msg("Failed to write savegame to SD!");
    wait_ms(4000);
  }
  f_unlink(PENDING_SAVE_FILEPATH);  // ← unconditional, even on failure
  ```

---

## Bug #4 — `apply_patch_ops` RTC Handler Array Out-of-Bounds

- **File**: `src/patcher.c`
- **Line**: ~307-308
- **Severity**: Medium (out-of-bounds array access → garbage code patched into ROM)
- **Trigger**: Patch DB entry with RTC opcode `0x7` and `arg >= 4`
- **Details**:
  - `rtc_fncs` array has exactly 4 elements (indices 0-3)
  - `case 0x7` accesses `rtc_fncs[arg]` without any bounds check
  - Compare: `case 0x9` (FLASH) correctly guards with `if (arg < 5)`
  - `arg >= 4` → reads garbage `ptr` and `size` → copies garbage code into ROM
- **Code**:
  ```c
  static const struct {
    const uint16_t *ptr;
    const uint32_t *size;
  } rtc_fncs[] = {  // 4 elements: indices 0-3
    { patch_rtc_probe,       &patch_rtc_probe_size },
    { patch_rtc_reset,       &patch_rtc_reset_size },
    { patch_rtc_getstatus,   &patch_rtc_getstatus_size },
    { patch_rtc_gettimedate, &patch_rtc_gettimedate_size },
  };
  ...
  case 0x7:
    copy_func16(buffer, baseaddr, bufsize, rtc_fncs[arg].ptr, moff, *rtc_fncs[arg].size);
    // ← no bounds check on `arg`
  ```

---

## Status

 - Bug 1 fixed in `src/cheats.c`: the pair count of opcodes 4 and 5 is
   validated against the buffer, and the entry size against
   `t_cheat_predec.blen`, before they are used.
 - Bug 2 covered by a bound in `patchmem_lookup` on the program payload.
   See the note above: the range is already safe with today's constants,
   the check documents and pins the assumption.
 - Bug 3 fixed in `check_pending_saves`: the sentinel is only unlinked
   once the save is provably on the SD card, so a write failure is
   retried on the next boot instead of silently destroying the save.
 - Bug 4 fixed in `apply_patch_ops`: the RTC handler index is bounds
   checked like the FLASH one already was.

Bugs 1 and 4 are exercised by `tests/hardening_test.c`.  Bug 3 lives in
`src/main.c` and is not reachable from the native tests, so it is fixed
by inspection.
