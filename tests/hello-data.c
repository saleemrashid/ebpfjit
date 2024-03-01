long data[32];

long bpf_main(long arg) {
  data[0] = arg;
  return data[1];
}
