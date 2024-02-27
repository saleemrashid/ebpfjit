static int fib(int n);

long bpf_main(unsigned int arg) { return fib(20); }

static int fib(int n) {
  if (n <= 1) {
    return 1;
  }
  return fib(n - 1) + fib(n - 2);
}
