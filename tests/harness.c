#include <stdio.h>

extern long long bpf_main(long long arg);

int main(int argc, char **argv) {
  long long tests[] = {1234, 0xdeadbeef};

  for (size_t i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
    long long arg = tests[i];
    printf("bpf_main(%lld) = %lld\n", arg, bpf_main(arg));
  }

  return 0;
}
