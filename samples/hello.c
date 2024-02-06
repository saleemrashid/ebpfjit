static void inline hash_appendc(unsigned long *hash, char c) {
  asm volatile("" : "+r,m"(c)::"memory");
  *hash = ((*hash << 5) + *hash) + c;
}

unsigned long bpf_main(void) {
  unsigned long hash = 5381;
  hash_appendc(&hash, 'H');
  hash_appendc(&hash, 'e');
  hash_appendc(&hash, 'l');
  hash_appendc(&hash, 'l');
  hash_appendc(&hash, 'o');
  return hash;
}
