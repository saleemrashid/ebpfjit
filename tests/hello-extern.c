extern const char s[];

int printf(const char *fmt, ...);

unsigned long bpf_main(void) {
  printf("s = %s\n", s);

#if 0
  unsigned long hash = 5381;
  for (unsigned int i = 0; i < 5; i++) {
    hash = ((hash << 5) + hash) + s[i];
  }
  return hash;
#endif
}
