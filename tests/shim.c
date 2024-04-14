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

void *stack_start = NULL;
void *stack_end = NULL;
void *stack_top = NULL;

static inline void stack_init(void) {
    if (stack_start != NULL) {
        return;
    }
    stack_start = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack_start == NULL) {
        panic("could not allocate stack");
    }
    stack_end = stack_start + STACK_SIZE;
    stack_top = stack_end;
}

void *shim_stack_alloc(size_t size) {
    stack_init();

    uintptr_t new_top = (uintptr_t) stack_top - size;
    if (new_top < (uintptr_t) stack_start || new_top > (uintptr_t) stack_end) {
        fprintf(stderr, "start:%p top:%p end:%p\n", stack_start, stack_top, stack_end);
        panic("could not alloc %zu bytes on the stack", size);
    }

    stack_top = (void *) new_top;
    return stack_top;
}

void shim_stack_dealloc(size_t size) {
    stack_init();

    uintptr_t new_top = (uintptr_t) stack_top + size;
    if (new_top < (uintptr_t) stack_start || new_top > (uintptr_t) stack_end) {
        panic("could not dealloc %zu bytes on the stack", size);
    }

    stack_top = (void *) new_top;
}

/* 1GB should be enough :) */
#define HEAP_SIZE (1024 * 1024 * 1024)

void *heap_start = NULL;
void *heap_end = NULL;

static inline void heap_init(void) {
    if (heap_start != NULL) {
        return;
    }
    heap_start = mmap(NULL, HEAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (heap_start == NULL) {
        panic("could not allocate heap");
    }
    heap_end = stack_start + HEAP_SIZE;
}

void *shim_heap_start(void) {
    heap_init();
    return heap_start;
}

size_t shim_heap_size(void) {
    heap_init();
    return HEAP_SIZE;
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

static inline void access(uintptr_t addr, size_t size, enum mode mode);

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
#ifndef SHIM_UNCHECKED
    if (CHECK(addr, stack)) {
        return;
    }
    if (CHECK(addr, heap)) {
        return;
    }
    if (CHECK(addr, shim_data)) {
        return;
    }
    if (CHECK(addr, shim_rodata)) {
        if (mode == WRITE) {
            panic("cannot %s rodata at 0x%zx of size %zu", modestr(mode), addr, size);
        }
        return;
    }
    panic("cannot %s at 0x%zu of size %zu", modestr(mode), addr, size);
#endif
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
