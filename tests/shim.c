#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern inline void allow_region(void) {}
extern inline void unallow_region(void) {}

enum mode { READ, WRITE };

static inline const char *modestr(enum mode mode) {
  switch (mode) {
    case READ:
      return "read";
    case WRITE:
      return "write";
  }
}

static inline void access(uintptr_t addr, size_t size, enum mode mode);

static __attribute__((cold)) __attribute__((noreturn))
__attribute__((format(printf, 1, 2))) void
panic(const char *format, ...);

#define _DEFINE_LOAD(T, F)        \
  T F(const T *src) {             \
    access((uintptr_t) src, sizeof(T), READ); \
    return *src;                  \
  }

#define _DEFINE_STORE(T, F)        \
  void F(T *dst, T src) {          \
    access((uintptr_t) dst, sizeof(T), WRITE); \
    *dst = src;                    \
  }

#define _MEM_ACCESS0(T, L, S) _DEFINE_LOAD(T, L) _DEFINE_STORE(T, S)
#define MEM_ACCESS(N) _MEM_ACCESS0(uint##N##_t, shim_load##N, shim_store##N)

MEM_ACCESS(8)
MEM_ACCESS(16)
MEM_ACCESS(32)
MEM_ACCESS(64)

extern uint8_t shim_data_start[];
extern uint8_t shim_data_end[];
extern uint8_t shim_rodata_start[];
extern uint8_t shim_rodata_end[];

#define CHECK(ADDR, NAME) check((ADDR), NAME##_start, NAME##_end)

static inline bool check(uintptr_t addr, void *start, void *end) {
    return addr >= (uintptr_t) start && addr < (uintptr_t) end;
}

static inline void access(uintptr_t addr, size_t size, enum mode mode) {
    if (CHECK(addr, shim_data)) {
        return;
    }
    if (CHECK(addr, shim_rodata)) {
        if (mode == WRITE) {
            panic("cannot %s rodata at 0x%zx of size %zu", modestr(mode), addr, size);
        }
        return;
    }
    /* panic("cannot %s at 0x%zu of size %zu", modestr(mode), addr, size); */
}

static void panic(const char *format, ...) {
  va_list arg;
  va_start(arg, format);
  flockfile(stderr);
  vfprintf(stderr, format, arg);
  fputc('\n', stderr);
  funlockfile(stderr);
  va_end(arg);
  /* TODO(saleem): jumping out of the sandbox would be ideal */
  abort();
}
