CLANG  	:= clang
LLC	   	:= llc
OBJCOPY	:= llvm-objcopy

CFLAGS 	:= -O2 -Wall

.SUFFIXES:
.SECONDARY:

%.bc: %.c
	$(CLANG) $(CFLAGS) -target bpf -S -emit-llvm -c $< -o $@

%.o: %.bc
	$(LLC) -march=bpf -mcpu=v3 -filetype=obj $< -o $@

%.bin: %.o
	$(OBJCOPY) -O binary -j .text $< $@

.PHONY: clean
clean:
	rm -f *.bin *.o *.bc
