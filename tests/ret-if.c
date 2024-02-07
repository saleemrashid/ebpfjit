long bpf_main(long arg) {
    if (arg == 0xdeadbeef) {
        return 100;
    } else {
        return 200;
    }
}
