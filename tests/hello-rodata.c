int printf(const char *fmt, ...);

unsigned long bpf_main(void) {
  const char *s = "Hello";
  asm volatile("" : "+r,m"(s)::"memory");
  printf("s = %s\n", s);

  unsigned long hash = 5381;
  for (unsigned int i = 0; i < 5; i++) {
    hash = ((hash << 5) + hash) + s[i];
  }

  s = "World";
  asm volatile("" : "+r,m"(s)::"memory");
  printf("s = %s\n", s);

  for (unsigned int i = 0; i < 5; i++) {
    hash = ((hash << 5) + hash) + s[i];
  }
  return hash;
}
