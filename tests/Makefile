CLANG   := clang
LLC     := llc
OBJCOPY	:= llvm-objcopy

BPFJIT      := ../compile.py
BPFJIT_DEPS := ../bpf.py ../disasm.py

CFLAGS  := -O2 -Wall
LDFLAGS :=

TESTS := add hello ret-if fib

.SUFFIXES:
.SECONDARY:

.PHONY: test
test: $(addprefix test-,$(TESTS))

test-%: %-native.txt %-jit.txt
	diff $^

%-jit.txt: %-jit
	./$< > $@

%-native.txt: %-native
	./$< > $@

%-jit: %-jit.o harness-native.o
	$(CLANG) $(LDFLAGS) $^ -o $@

%-native: %-native.o harness-native.o
	$(CLANG) $(LDFLAGS) $^ -o $@

%-native.o: %.c
	$(CLANG) $(CFLAGS) -c $< -o $@

%-jit.o: %-jit.ll
	$(CLANG) $(CFLAGS) -Wno-override-module $< -c -o $@

%-jit.ll: %-bpf.bin $(BPFJIT) $(BPFJIT_DEPS)
	$(BPFJIT) $< > $@

%-bpf.ll: %.c
	$(CLANG) $(CFLAGS) -target bpfel -S -emit-llvm -c $< -o $@

%-bpf.o: %-bpf.ll
	$(LLC) -march=bpfel -mcpu=v3 -filetype=obj $< -o $@

%-bpf.bin: %-bpf.o
	$(OBJCOPY) -O binary -j .text $< $@

.PHONY: clean
clean:
	rm -f *.bin *.o *.ll *-{jit,native}{,.txt}
