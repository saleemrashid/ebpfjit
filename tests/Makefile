CLANG   := clang
LLC     := llc
OBJCOPY := llvm-objcopy

BREW := $(shell command -v brew)

ifneq ($(BREW),)
LLVM_BINDIR := $(shell $(BREW) --prefix --installed llvm)/bin
CLANG       := $(LLVM_BINDIR)/$(CLANG)
LLC         := $(LLVM_BINDIR)/$(LLC)
OBJCOPY     := $(LLVM_BINDIR)/$(OBJCOPY)
endif

BPFJIT      := ../compile.py
BPFJIT_DEPS := ../bpf.py ../disasm.py  ../linker.py

CFLAGS  := -O2 -Wall
LDFLAGS :=

BPF_CFLAGS   := -target bpfel -fno-builtin
BPF_LLCFLAGS := -march=bpfel -mcpu=v3

TESTS := add hello ret-if fib fib-rec printf

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

%-jit.ll: %-bpf.o $(BPFJIT) $(BPFJIT_DEPS)
	$(BPFJIT) $< > $@

%-bpf.ll: %.c
	$(CLANG) $(CFLAGS) $(BPF_CFLAGS) -S -emit-llvm -c $< -o $@

%-bpf.o: %-bpf.ll
	$(LLC) $(BPF_LLCFLAGS) -filetype=obj $< -o $@

.PHONY: clean
clean:
	rm -f *.o *.ll *-{jit,native}{,.txt}
