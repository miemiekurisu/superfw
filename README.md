
SuperFW
=======

An alternative firmware for Supercard GBA flash carts

This project aims to provide a more modern and better firmware for Supercard
flash carts (which are still widely used and very cheaply available). The goal
is to add many features only present in more expensive or sophisticated flash
carts. Unfortunately we are limited to the actual hardware so certain features
are impossible or very complex to implement.

Find the website and documentation at https://superfw.davidgf.net/


Installation
------------

Check https://superfw.davidgf.net/docs/install/flash/ for more details.

The firmware can be chain-loaded using another firmware (ie. the default
SuperCard firmware or SCFW) and loaded as a regular game. It can also be
installed on the internal flash device. Installing it enables some nice
features such as SDHC and exFAT compatibility.

To install the firmware you can simply load it first, and then use SuperFW
to flash itself on the flash. You will need to enable flashing in the Info
tab and then pick the .fw file and flash it. It is strongly recommended to
reboot your GBA after flashing.

Flashing is also possible using an NDS. This is particularly useful if you
_brick_ your Supercard (ie. interrupting flashing, low battery conditions
and similar situations could cause a bad flash). You will need an NDS device
and a Slot-1 cart as well. Download the .nds ROM for your Slot-1 cart at
https://github.com/davidgfnet/superfw-nds-flasher-tool/releases/ and launch
it with your Supercard on your Slot-2. You should be able to flash (as well
as backup) your flash.

GB/GBC Emulation
----------------

GameBoy and GameBoy Color ROMs can be played by using the built-in Goombacolor
emulator binary (the Lite build doesn't ship any emulator though).Picking any
.gb/.gbc file will load the emulator and the ROM and start its execution.

Other devices can also be played as long as the right emulator is installed in
the SD card (and supported by SuperFW).

Check https://superfw.davidgf.net/docs/usermanual/emulators/ for details.

ROM patching
------------

The firmware contains a patch database to patch several features. A custom
database can also be loaded from the SD card and used instead (so more games
and improvements can be added). The patches contain information about:

 - WaitCNT patches: Also called white/black screen patches, prevent games from
   updating the WAITCNT waitstates (the supercard has a slow memory). Without
   a correct patch the game won't even boot.
 - Flash/EEPROM offsets: Indicate where the relevant storage routines are so
   that they can be patched and converted to SRAM storage.
 - IRQ handler patches: Used to patch user IRQ handler routine and install a
   custom one. Used to enable in-game menu.
 - RTC patches: Used for games that contained an RTC IC in theri cart, to keep
   track of time (both time and date). There's only a handful such ROMs.

More information at https://superfw.davidgf.net/docs/usermanual/patches/

These patches are generated mostly automatically, check out the patch repo at:
https://github.com/davidgfnet/gba-patch-gen
It is also possible to use the web-based patch generator for better patches:
https://patchtool.superfw.davidgf.net/

In-game menu
------------

SuperFW features an in-game menu that allows users to pause the current game
and perform certain actions such as:

  - Resuming and resetting the game
  - Going back to the SuperFW menu (witout having to reboot your GBA)
  - Handling saves (for games that allow saving)
  - Creating and restoring savestates
  - Applying/using cheat codes
  - Changing the RTC time (for games that use an RTC)

This menu is a bit of a hack that requires patching the ROM to work. For this
reason, some games won't work well with it or will suffer from bugs (usually
graphical bugs). In this case it is advised to not use the in-game menu.

Many graphical glitches will result in the screen being "offseted" to the
left/right/up/down. In many cases this is not an issue (besides making it
harder for the user to see and play) and it goes away when entering a new
zone/level/menu. This is due to the GBA featuring some "write-only" registers,
that is, registers that can be written but never read back. For this reason
we cannot properly save and restore said registers.

Saving games
------------

Save games are stored in the cart's SRAM and preserved by the cart battery
(note that if the battery is dead the game will be lost). On reboot SuperFW
will write the savegame to the SD card to preserve it and allow loading
another save game.

When using the in-game menu, you might enter the menu and select any of the
saving options, which will write the save to the SD card. This is a good
way to save your games if you prefer to manually handle save files (ie.
disabling autosave and manually choosing when to save).

For Flash-based games (around 300 games) and EEPROM-based games (around 1400
games) it is possible to patch games so that they write directly to the SD
save game, this is called Direct-Saving mode. This makes saving more reliable
(no need for a battery!) and simpler to use (no need to reboot to ensure
saving or using the in-game menu). Games that use Flash or EEPROM will display
an option for direct-saving (this is the default choice in Auto mode).

Files and configuration on the SD card
--------------------------------------

All SuperFW related files are stored under "/.superfw" at the root of the card.
The following files are usually created:

 - .superfw/settings.txt: User settings, loaded on startup.
 - .superfw/ui-settings.txt: UI settings, loaded on startup.
 - .superfw/recent.txt: Recently played ROMs, in order.
 - .superfw/pending-save.txt: SRAM save information (temp file).
 - .superfw/pending-sram-test.txt: SRAM test flag (temp file).

Other noteworthy paths:

 - .superfw/config/: Per-ROM load configuration.
 - .superfw/patches/: Patch cache (created by PatchEngine).
 - .superfw/cheats/: Cheat database, contains .cht files.
 - .superfw/emulators/: Emulator ROMs, used to play other device's ROMs.

Limits
------

The following restrictions apply to the firmware due to memory/storage/cpu
constraints:

 - Maximum ROM size: 32MiB (Supercard's memory size)
 - File path and name limit: 255 utf-8 bytes (not exactly characters!)
 - Maximum number of files+dirs in a directory: 16384

Bug fixes (2026-05)
-------------------

A batch of confirmed bugs was fixed across the patching, save and loader
subsystems. These were reachable through specific ROM content, SD card
state or malformed input and could cause black screens, corrupted saves
or memory corruption.

Patches and patching (src/patcher.c, src/patchengine.c):

 - COPY_BYTE and COPY_WORD patch op decoding (wrong index base,
   undefined shift, partial buffer address mismatch, stream
   consumption). Partial NOR patch paths were broken for word aligned
   writes.
 - 16/32-bit write range checks in partial buffers. A patch op whose
   starting address was inside the buffer could still write past the
   end.
 - copy_func16 cross-chunk copy logic. When a function or payload
   spanned SDRAM chunk boundaries the old offset model produced
   underflowing pointers and wrong source skips. All 6 callers (RTC,
   save handlers, DirectSave payload, IGM trampoline) were rewritten to
   use interval intersection.
 - ROM signature scan lookahead (rom[i+1]) at the chunk tail, 6 sites
   guarded with the remaining byte count. The match_sig_prefix callers
   (18) were updated with an available length parameter.
 - v1 Flash setup info handler extraction used info2 fields in the
   info1 branch, producing wrong save handler addresses for
   S29AL032D/S29GL032N-type carts.
 - Generated patch op count (t_patch.op[128]) had no capacity guard.
   All 15 op-push sites now break at MAX_PATCH_OPS.
 - External patch DB (patchmem_lookup) and .super deserializer
   (unserialize_patch) now validate op counts, save_mode and structural
   bounds.

Save system (src/directsave_emu.c, src/save.c):

 - DirectSave EEPROM (block_num * 8) and Flash sector (sectnum * 4096)
   boundary checks had off by one and integer overflow issues, replaced
   with division based comparisons.
 - ds_read_flash "offset + bytecount > msize" guard rearranged into
   "bytecount > msize - offset" to prevent an overflow bypass.
 - rotate_savefile now checks the final ".tmp.sav -> .sav" rename
   return code to prevent silent data loss.
 - File handle leaks fixed in flush_pending_sram (3 error paths),
   file_is_contiguous (failure path) and copy_save_contiguous_file
   (input open failure without closing the output).

Loader, menu and cheats (src/menu.c, src/cheats.c, src/main.c):

 - External patch DB load (load_patchdb_action) capped at
   PATCHDB_MAX_SIZE, buffer zero filled, short read checked, and file
   handle closed on all paths.
 - menu_apply_action clamps the extemu file size to 512 MiB to prevent
   a negative uint32_t cast.
 - Cheat parser (parse_cheat_codes) accepts CRLF line endings and
   tab/CR separators, has a capacity guard against buffer overflow, and
   caps the title length at 251 to prevent a uint8_t slen wrap.
   open_read_cheats closes the file handle on all error paths.
 - predecode_cheats walked past the code buffer when a multi-code entry
   declared more pairs than were actually present.
 - The RTC handler index was not validated against the handler table.
 - A failed savegame flush deleted the pending save sentinel anyway,
   losing the only remaining copy of the save.

Four more defects were found and fixed while auditing for the v0.21
port and are documented in docs/BUG_REPORT.md. The program payload copy
in patchmem_lookup got an explicit bound for the end of its 512-byte
page as well: it is unreachable with the current program size and
program count limits, but it is the assumption those limits build upon.

Chinese localized ROMs
----------------------

Some Chinese patched ROMs (typically those retaining the original game
code and version but replacing text and assets) have been tested and
load, boot and save reliably with this firmware. Compatibility is not
universal though: ROMs that significantly modify the code layout or use
non standard memory regions may still require specific WaitCNT/IRQ
patches or manual configuration. The game by game patch database
coverage is the governing factor, the bug fixes above do not by
themselves make a previously broken ROM patchable.

Upstream sync (2026-10)
-----------------------

The fork base was updated from v0.20 to upstream v0.21 and the firmware
now reports v0.21. This brings in the upper mirror mapping fix, the
SuperChis UI fixes, the new IGM/I/O register handling, the reworked NOR
save path, NOR games in the recent games list and the slimmer built-in
patch database.

The upstream changes came in as a normal branch merge and our fixes were
forward ported on top of them, instead of replacing one tree with the
other, so nothing from the previous sections was dropped on the way.
Still ours and not present in upstream v0.21: the copy_func16 interval
intersection rewrite, the full width 16/32-bit patch range checks, the
ROM tail scan bound, the info1 v1 Flash setup fix, the MAX_PATCH_OPS
guards and the overflow safe DirectSave bounds. Building the host tests
with MSVC also required two portability fixes, neither of which changes
the generated code (the SD image came out byte for byte identical with
and without them):

 - compiler.h: NOINLINE and EXTERNAL only expand to the GCC attributes
   when the compiler actually is GCC.
 - cheats.h: t_cheathdr_ext embedded a struct ending in a flexible array
   member, which standard C forbids. The four header bytes are now
   mirrored by t_cheathdr_head, plus static assertions pinning the
   layout the block copy relies upon.

Testing
-------

The regression tests are native programs, no GBA hardware is needed:

    cd tests
    make host-tests CC=gcc        # build and run 8 test binaries
    make host-coverage CC=gcc     # gcov summary through cov_report.py

host-coverage reports the coverage of the four hardened sources
(src/patcher.c, src/patchengine.c, src/directsave_emu.c and
src/cheats.c). Every executable line is covered; of the branch outcomes
93% are taken, the rest being untaken sides of the bounds guards and of
the Flash setup info heuristics. The same suite is built and run with a
second compiler using "python tests/msvc_build.py", which locates
cl.exe with vswhere.

Firmware images
---------------

"make BOARD=sd" (also lite and chis) produces the flashable image as
superfw.gba. Check an image before putting it on a card:

    python tools/verify-fw.py dist/*.fw

This repeats on a PC the checks the in-cart updater performs before it
dares to erase anything: the SUPERFW~DAVIDGF magic, the hardware
variant, the advertised size, the truncated SHA256 header checksum, the
GBA cartridge header complement, and the firmware partition budget of
the flavour.
Licenses
--------

Most of SuperFW was written by davidgf and is published under GPL license.
Some components use third party code, such as: nanoprintf (public domain),
heapsort (3-BSD), fatfs (1-BSD-like) and apultra/upkr (only used at
build-time). Some linkerscript/crt0 code was adapted from AntonioND's work
under CC0.


