
COV_FLAGS=-ftest-coverage -fprofile-arcs
MEMCHK_FLAGS=-fsanitize=address -lasan
CFLAGS = -O0 -ggdb -I../src/ -Wall $(COV_FLAGS)

all:
	$(CC) $(CFLAGS) $(MEMCHK_FLAGS) -o cimpl_test.bin cimpl_test.c ../src/cimpl.c -DBUILTIN_PREFIX=superfw_
	./cimpl_test.bin
	lcov -c -d . -o cimpl_test.info
	$(CC) $(CFLAGS) $(MEMCHK_FLAGS) -o util_test.bin util_test.c ../src/util.c ../src/nanoprintf.c ../src/fileutil.c -I../
	./util_test.bin
	lcov -c -d . -o util_test.info
	$(CC) $(CFLAGS) $(MEMCHK_FLAGS) -o utf_util_test.bin utf_util_test.c ../src/utf_util.c -I../
	./utf_util_test.bin
	lcov -c -d . -o utf_util_test.info
	$(CC) $(CFLAGS) $(MEMCHK_FLAGS) -o sha256_test.bin sha256_test.c ../src/sha256.c -lcrypto
	./sha256_test.bin
	lcov -c -d . -o sha256_test.info
	$(CC) $(CFLAGS) -o cheats_test.bin cheats_test.c ../src/cheats.c ../src/util.c ../src/nanoprintf.c -I../
	./cheats_test.bin
	lcov -c -d . -o cheats_test.info
	$(CC) $(CFLAGS) $(MEMCHK_FLAGS) -o crc_test.bin crc_test.c ../src/crc.c
	./crc_test.bin
	lcov -c -d . -o crc_test.info

	lcov -a cimpl_test.info -a util_test.info -a utf_util_test.info -a crc_test.info -a sha256_test.info -a cheats_test.info -o total.info
	rm -rf coverage/
	genhtml -o coverage/ total.info

clean:
	rm -f *.bin *.gcda *.gcno *.info *.gcov.json.gz
	rm -f *_test$(EXE) cov_*$(EXE) *.o hardening_test.cht
	rm -rf coverage/ msvc-build/

cli_tests:
	$(CC) -flto -O0 -ggdb -I../src/ -Wall $(MEMCHK_FLAGS) -o cli_patchengine.bin cli_patchengine.c ../src/patchengine.c  ../src/util.c  -I../  -ffunction-sections -fdata-sections  -Wl,--gc-sections

#-----------------------------------------------------------------------------
# Native host builds of the regression tests.
#
# The "all" target above needs gcov/lcov and libasan.  "host-tests" only needs
# a plain C compiler, so it also runs on Windows (MSYS2/MinGW) and is what CI
# can use without the coverage toolchain.  Run with:  make host-tests
#-----------------------------------------------------------------------------
EXE = $(if $(filter Windows_NT,$(OS)),.exe,)
SH = sh
HOST_CFLAGS = -O1 -ggdb -I../src/ -I../ -Wall

host-tests: host-cimpl host-util host-utf host-crc host-cheats \
	host-patch-hardening host-directsave host-patchengine

host-cimpl:
	$(CC) $(HOST_CFLAGS) -o cimpl_test$(EXE) cimpl_test.c ../src/cimpl.c -DBUILTIN_PREFIX=superfw_
	$(SH) -c "./cimpl_test$(EXE)"

host-util:
	$(CC) $(HOST_CFLAGS) -o util_test$(EXE) util_test.c ../src/util.c ../src/nanoprintf.c ../src/fileutil.c
	$(SH) -c "./util_test$(EXE)"

host-utf:
	$(CC) $(HOST_CFLAGS) -o utf_util_test$(EXE) utf_util_test.c ../src/utf_util.c
	$(SH) -c "./utf_util_test$(EXE)"

host-crc:
	$(CC) $(HOST_CFLAGS) -o crc_test$(EXE) crc_test.c ../src/crc.c
	$(SH) -c "./crc_test$(EXE)"

host-cheats:
	$(CC) $(HOST_CFLAGS) -o cheats_test$(EXE) cheats_test.c ../src/cheats.c ../src/util.c ../src/nanoprintf.c
	$(SH) -c "./cheats_test$(EXE)"

# Bounds/hardening regression tests for the ROM patch pipeline and the cheat
# loader.  hardening_test.c #includes src/patcher.c to reach its statics.
host-patch-hardening:
	$(CC) $(HOST_CFLAGS) -o hardening_test$(EXE) hardening_test.c ../src/cheats.c ../src/util.c ../src/nanoprintf.c
	$(SH) -c "./hardening_test$(EXE)"

# DirectSave bounds tests.  Needs to be able to map the 0x0E000000 GBA SRAM
# mirror inside the host process.
host-directsave:
	$(CC) $(HOST_CFLAGS) -o directsave_test$(EXE) directsave_test.c
	$(SH) -c "./directsave_test$(EXE)"

# Patch engine scanner tests.  patchengine_test.c #includes src/patchengine.c
# and fakes FatFS so the ROM walker can be driven entirely from memory.
host-patchengine:
	$(CC) $(HOST_CFLAGS) -o patchengine_test$(EXE) patchengine_test.c \
		../src/util.c ../src/nanoprintf.c
	$(SH) -c "./patchengine_test$(EXE)"

#-----------------------------------------------------------------------------
# gcov-based coverage report for the four hardened sources (patcher.c,
# cheats.c, directsave_emu.c, patchengine.c).  Stale .gcda files silently
# inflate the numbers, so wipe them first.  Run with:  make host-coverage
#-----------------------------------------------------------------------------
COV_CFLAGS = -O0 -ggdb -I../src/ -I../ -Wall --coverage

host-coverage:
	$(SH) -c "rm -f cov_*.gcda cov_*.gcno *.gcov.json.gz"
	$(CC) $(COV_CFLAGS) -o cov_hard$(EXE) hardening_test.c \
		../src/cheats.c ../src/util.c ../src/nanoprintf.c
	$(SH) -c "./cov_hard$(EXE)"
	$(CC) $(COV_CFLAGS) -o cov_ds$(EXE) directsave_test.c
	$(SH) -c "./cov_ds$(EXE)"
	$(CC) $(COV_CFLAGS) -o cov_pe$(EXE) patchengine_test.c \
		../src/util.c ../src/nanoprintf.c
	$(SH) -c "./cov_pe$(EXE)"
	$(SH) -c "gcov -j -b -c -u -o . cov_*.gcda"
	$(SH) -c "python cov_report.py"
