# heap-allocator-lib

This is a simple heap allocator library that provides the following functions:

- `void *malloc(size_t size)`: Allocates a block of memory of the given size and returns a pointer to the beginning of the block.
- `*heap_calloc(size_t number, size_t size)`: Allocates a block of memory for an array of number elements of the given size and initializes all its bits to zero. Returns a pointer to the beginning of the block.
- `void *heap_realloc(void *memblock, size_t count)`: Changes the size of the block of memory pointed to by the given pointer to the given size and returns a pointer to the beginning of the block.
- `void heap_free(void *memblock);`: Frees the block of memory pointed to by the given pointer.

The library utilizes a simple fence protection mechanism to detect buffer overflows and underflows. The library also provides a function to check the integrity of the heap.

## Usage

Example usage of the library:

```c
#include "include/heap.h"

int main() {
  heap_setup();

  void *ptr = heap_calloc(1, 10);
  for (size_t i = 0; i < 10; i++) {
    *((char *)ptr + i) = 'a' + i;
  }

  for (size_t i = 0; i < 10; i++) {
    printf("%c", *((char *)ptr + i));
  }
  printf("\n");

  heap_realloc(ptr, 20);

  for (size_t i = 0; i < 20; i++) {
    printf("%c", *((char *)ptr + i) ? *((char *)ptr + i) : '0');
  }

  heap_free(ptr);
  heap_clean();
  return 0;
}
```

## Building

To build the library, run the following commands:

```bash
gcc -o main example_main.c lib/heap.c
```

## TODO:

- [ ] Implement heap_*_aligned for aligned memory allocation and reallocation.
- [ ] Implement heap_*_debug for debugging purposes like from which file and line the allocation was made.
- [ ] Implement heap_*_stats for getting statistics about the heap.
- [ ] Make functions thread-safe.