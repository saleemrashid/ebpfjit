int printf(const char *fmt, ...);

#define printf(FMT, ...)        \
  do {                          \
    char fmt[] = FMT;           \
    printf(fmt, ##__VA_ARGS__); \
  } while (0)

static long (*black_box(void *p))(void) {
  asm volatile("" : "+r,m"(p)::"memory");
  return p;
}

static long hello(void) {
  printf("hello\n");
  return 4567;
}

static long goodbye(void) {
  printf("goodbye\n");
  return 1234;
}

long bpf_main(void) {
  black_box(hello)();
  return black_box(goodbye)();
}
