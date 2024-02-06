#include <stdio.h>

extern long long bpf_main(long long i);

int main(int argc, char **argv) {
  printf("bpf_main() = %lld\n", bpf_main(1234));
  return 0;
}
