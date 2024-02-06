unsigned long bpf_main(void) {
  const char *s = "Hello";
  asm volatile("" : "+r,m"(s)::"memory");

  unsigned long hash = 5381;
  for (unsigned int i = 0; i < 5; i++) {
    hash = ((hash << 5) + hash) + s[i];
  }
  return hash;
}
