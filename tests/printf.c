int printf(const char *fmt, ...);

#define printf(FMT, ...)        \
  do {                          \
    char fmt[] = FMT;           \
    printf(fmt, ##__VA_ARGS__); \
  } while (0)

long bpf_main(long arg) {
  printf("Hello, World: %lld\n", 12);
  return 0;
}
