long bpf_main(long arg) {
  /* XXX(saleem): mcpu=v3 can't do sdiv, maybe change? */
  int n = ((unsigned int)arg) % 30;

  int a = 1;
  int b = 1;
  for (int i = 0; i < n; i++) {
    int tmp = a + b;
    a = b;
    b = tmp;
  }

  return b;
}
