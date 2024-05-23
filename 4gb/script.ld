SECTIONS {
    .shim.data : AT(0x80000000) ALIGN(0x80000000) {
        shim_segment_addr = .;
        . = ALIGN(CONSTANT(MAXPAGESIZE));
        shim_stack_start = .;
        . += ALIGN(. + 0x800000, CONSTANT(MAXPAGESIZE));
        shim_stack_end = .;
        *(.data.shim_data)
        *(.data.shim_rodata)
        . += ALIGN(CONSTANT(MAXPAGESIZE));
        shim_heap_start_ = .;
        . = ALIGN(0x80000000);
        shim_heap_end = .;
    }
}

INSERT AFTER /DISCARD/;
