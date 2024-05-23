#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

static __attribute__((cold)) __attribute__((noreturn))
__attribute__((format(printf, 1, 2))) void
panic(const char *format, ...);

/* Allocator implementation */

/* 1GB should be enough :) */
#define STACK_SIZE (1024 * 1024 * 1024)

extern uint8_t shim_segment_addr[];
extern uint8_t shim_stack_start[];
extern uint8_t shim_stack_end[];
extern uint8_t shim_heap_start_[];
extern uint8_t shim_heap_end[];

static size_t stack_offset = 0;

void *shim_stack_alloc(size_t size) {
    stack_offset += size;
    return shim_stack_end - stack_offset;
}

void shim_stack_dealloc(size_t size) {
    stack_offset -= size;
}

/* 1GB should be enough :) */
#define HEAP_SIZE (1024 * 1024 * 1024)

void *shim_heap_start(void) {
    return shim_heap_start_;
}

size_t shim_heap_size(void) {
    return shim_heap_end - shim_heap_start_;
}

/* Load/store functions */

enum mode { READ, WRITE };

static inline const char *modestr(enum mode mode) {
  switch (mode) {
    case READ:
      return "read";
    case WRITE:
      return "write";
  }
}

#define ADDR_MASK 0x7fffffff

static inline uintptr_t addr(uintptr_t p) {
    return ((uintptr_t) shim_segment_addr) | (p & ADDR_MASK);
}

#define ADDR(X) ((typeof(X)) addr((uintptr_t) (X)))

#define _DEFINE_LOAD(T, F)        \
  T F(const T *src) {             \
    return *ADDR(src);                  \
  }

#define _DEFINE_STORE(T, F)        \
  void F(T *dst, T src) {          \
    *ADDR(dst) = src;                    \
  }

#define _MEM_ACCESS0(T, L, S) _DEFINE_LOAD(T, L) _DEFINE_STORE(T, S)
#define MEM_ACCESS(N) _MEM_ACCESS0(uint##N##_t, shim_load##N, shim_store##N)

MEM_ACCESS(8)
MEM_ACCESS(16)
MEM_ACCESS(32)
MEM_ACCESS(64)

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
