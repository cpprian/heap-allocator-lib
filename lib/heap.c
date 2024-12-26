#include "../include/heap.h"

struct memory_manager_t memory_manager;

size_t heap_get_largest_used_block_size(void) {
  if (memory_manager.memory_start == NULL) {
    return 0;
  }
  if (heap_validate()) {
    printf("Heap is not valid\n");
    return 0;
  }

  size_t max_size = 0;
  struct memory_chunk_t *chunk = memory_manager.first_chunk;
  while (chunk != NULL) {
    if (!chunk->free && chunk->size > max_size) {
      max_size = chunk->size;
    }
    chunk = chunk->next;
  }
  return max_size;
}

int is_pointer_within_heap(const void *pointer) {
  return (char *)pointer >= (char *)memory_manager.memory_start &&
         (char *)pointer <
             (char *)memory_manager.memory_start + memory_manager.memory_size;
}

enum pointer_type_t get_pointer_type(const void *const pointer) {
  if (pointer == NULL) {
    return pointer_null;
  }
  if (!is_pointer_within_heap(pointer)) {
    return pointer_heap_corrupter;
  }

  int check = 0;
  struct memory_chunk_t *chunk =
      (struct memory_chunk_t *)memory_manager.first_chunk;
  while (chunk != NULL) {
    if (is_allocated(pointer, chunk)) {
      return pointer_valid;
    } else if (is_unallocated(pointer, chunk)) {
      return pointer_unallocated;
    } else if ((check = is_inside_data_block(pointer, chunk))) {
      if (check == 2) {
        return pointer_unallocated;
      }
      return pointer_inside_data_block;
    } else if ((check = is_inside_fences(pointer, chunk))) {
      if (check == 2) {
        return pointer_unallocated;
      }
      return pointer_inside_fences;
    } else if (is_inside_control_block(pointer, chunk)) {
      return pointer_control_block;
    }
    chunk = chunk->next;
  }
  return pointer_unallocated;
}

int is_inside_data_block(const void *const pointer,
                         struct memory_chunk_t *chunk) {
  long ptr = (char *)pointer - (char *)chunk;
  long head_block = ptr - MEMORY_CHUNK_SIZE - FENCEPOST_SIZE;
  long tail_block = (char *)chunk + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE +
                    chunk->size - (char *)pointer;
  if (head_block > 0 && tail_block > 0) {
    if (chunk->free) {
      return 2;
    }
    return 1;
  }
  return 0;
}

int is_inside_fences(const void *const pointer, struct memory_chunk_t *chunk) {
  long ptr = (char *)chunk - (char *)pointer;
  if (ptr <= 0) {
    long right_fence = ptr * -1 - FENCEPOST_SIZE - MEMORY_CHUNK_SIZE;
    if (right_fence * -1 >= 0 && right_fence * -1 <= (long)FENCEPOST_SIZE) {
      if (chunk->free == 1) {
        return 2;
      }
      return 1;
    } else if (right_fence - (long)chunk->size >= 0 &&
               right_fence - (long)chunk->size < (long)FENCEPOST_SIZE) {
      if (chunk->free == 1) {
        return 2;
      }
      return 1;
    }
  } else {
    long left_fence = ptr - FENCEPOST_SIZE;
    if (left_fence >= 0 && left_fence <= (long)FENCEPOST_SIZE) {
      if (chunk->free == 1) {
        return 2;
      }
      return 1;
    }
  }
  return 0;
}

int is_inside_control_block(const void *const pointer,
                            struct memory_chunk_t *chunk) {
  long ptr = (char *)chunk - (char *)pointer;
  long is_inside_cb = ptr * -1 - (long)(MEMORY_CHUNK_SIZE);
  if ((is_inside_cb > 0 && is_inside_cb < (long)MEMORY_CHUNK_SIZE) ||
      (is_inside_cb < 0 &&
       is_inside_cb * -1 - ptr <= (long)MEMORY_CHUNK_SIZE)) {
    return 1;
  }
  return 0;
}

int is_unallocated(const void *const pointer, struct memory_chunk_t *chunk) {
  long ptr =
      (char *)chunk - (char *)pointer + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE;
  long padding = check_is_space_between_two_chunks(chunk);
  if (-1 * padding + (long)chunk->size >= ptr * -1 &&
      -1 * ptr - (long)FENCEPOST_SIZE >= (long)chunk->size) {
    return 1;
  }
  return chunk->free && ptr * -1 >= 0 && ptr * -1 <= (long)chunk->size;
}

int is_allocated(const void *const pointer, struct memory_chunk_t *chunk) {
  long ptr =
      (char *)chunk - (char *)pointer + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE;
  return !chunk->free && ptr == 0;
}

int heap_setup(void) {
  if (memory_manager.memory_start != NULL) {
    heap_clean();
  }

  // TODO: implement own sbrk
  memory_manager.memory_start = sbrk(0);
  if (memory_manager.memory_start == (void *)-1) {
    return 1;
  }

  memory_manager.memory_size = 0;
  memory_manager.first_chunk = NULL;
  return 0;
}

void heap_clean(void) {
  if (memory_manager.memory_start == NULL) {
    return;
  }

  // clear first_chunk
  struct memory_chunk_t *chunk = memory_manager.first_chunk;
  while (chunk != NULL) {
    chunk->size = 0;
    chunk->prev = NULL;
    struct memory_chunk_t *next = chunk->next;
    chunk->next = NULL;
    chunk = next;
  }

  // clear sbrk
  sbrk(-memory_manager.memory_size);
  memory_manager.memory_size = 0;

  // clear memory_manager
  memory_manager.memory_start = NULL;
  memory_manager.first_chunk = NULL;
}

int heap_validate(void) {
  if (memory_manager.memory_start == NULL) {
    return 2;
  }

  for (struct memory_chunk_t *chunk = memory_manager.first_chunk; chunk != NULL;
       chunk = chunk->next) {
    // Check if user wrote to control block
    if (sum_control_block(chunk) != chunk->checksum) {
      return 3;
    }
    // Check if user wrote to fenceposts
    if (!chunk->free) {
      char *chunk_start = (char *)chunk + MEMORY_CHUNK_SIZE;
      char *chunk_end = chunk_start + FENCEPOST_SIZE + chunk->size;
      for (size_t i = 0; i < FENCEPOST_SIZE; i++) {
        if (chunk_start[i] != FENCEPOST_VALUE ||
            chunk_end[i] != FENCEPOST_VALUE) {
          return 1;
        }
      }
    }
  }

  return 0;
}

size_t sum_control_block(struct memory_chunk_t *chunk) {
  size_t sum = 0;
  struct memory_chunk_t temp = *chunk;
  temp.checksum = 0;
  char *ptr = (char *)&(temp.size);
  for (size_t i = 0; i < sizeof(chunk->size); i++) {
    sum += ptr[i];
  }
  ptr = (char *)&(temp.free);
  for (size_t i = 0; i < sizeof(chunk->free); i++) {
    sum += ptr[i];
  }
  ptr = (char *)&(temp.next);
  for (size_t i = 0; i < sizeof(chunk->next); i++) {
    sum += ptr[i];
  }
  ptr = (char *)&(temp.prev);
  for (size_t i = 0; i < sizeof(chunk->prev); i++) {
    sum += ptr[i];
  }
  ptr = (char *)&(temp.checksum);
  for (size_t i = 0; i < sizeof(chunk->checksum); i++) {
    sum += ptr[i];
  }
  return sum;
}

void checksum_all_chunks() {
  for (struct memory_chunk_t *chunk = memory_manager.first_chunk; chunk != NULL;
       chunk = chunk->next) {
    chunk->checksum = sum_control_block(chunk);
  }
}

void *heap_malloc(size_t size) {
  if (size <= 0) {
    return NULL;
  }
  // align size
  // size = ALIGN(size);

  // find free chunk
  void *ptr = find_free_chunk(size);
  if (ptr != NULL) {
    return ptr;
  }

  // allocate memory
  void *memory = sbrk(size + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE * 2);
  if (memory == (void *)-1) {
    return NULL;
  }
  memory_manager.memory_size += size + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE * 2;

  struct memory_chunk_t *chunk = NULL;

  // update memory_manager
  if (memory_manager.first_chunk == NULL) {
    chunk = (struct memory_chunk_t *)memory;
    chunk->size = size;
    chunk->next = NULL;
    chunk->prev = NULL;
    chunk->free = 0;

    memory_manager.first_chunk = chunk;
  } else {
    chunk = memory_manager.first_chunk;
    while (chunk->next != NULL) {
      chunk = chunk->next;
    }

    chunk->next = (struct memory_chunk_t *)memory;
    chunk->next->size = size;
    chunk->next->next = NULL;
    chunk->next->prev = chunk;
    chunk->next->free = 0;

    chunk = chunk->next;
  }

  add_fenceposts(chunk);
  // chunk->checksum = sum_control_block(chunk);
  checksum_all_chunks();
  return (char *)memory + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE;
}

void *heap_calloc(size_t number, size_t size) {
  if (number <= 0 || size <= 0) {
    return NULL;
  }
  void *ptr = heap_malloc(number * size);
  if (ptr == NULL) {
    return NULL;
  }
  memset(ptr, 0, number * size);
  return ptr;
}

void *heap_realloc(void *memblock, size_t count) {
  if (memory_manager.memory_start == NULL) {
    return NULL;
  }
  if (memblock == NULL) {
    return heap_malloc(count);
  } else if (count <= 0) {
    heap_free(memblock);
    return NULL;
  }

  struct memory_chunk_t *chunk =
      (struct memory_chunk_t *)((char *)memblock - MEMORY_CHUNK_SIZE -
                                FENCEPOST_SIZE);
  if ((long)chunk->size <= -20000 || (long)chunk->size >= 20000) {
    return NULL;
  }

  size_t temp_size = chunk->size;
  heap_free(memblock);

  if (chunk->next == NULL && chunk->size < count) {
    size_t to_add = count - chunk->size;
    void *memory = sbrk(to_add + FENCEPOST_SIZE);
    if (memory == (void *)-1) {
      chunk->free = 0;
      chunk->size = temp_size;
      chunk->checksum = sum_control_block(chunk);
      add_fenceposts(chunk);
      return NULL;
    }
    memory_manager.memory_size += to_add + FENCEPOST_SIZE;

    chunk->size += to_add;
    // chunk->checksum = sum_control_block(chunk);
    checksum_all_chunks();
    for (size_t i = 0; i < FENCEPOST_SIZE; i++) {
      *((char *)chunk + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE + chunk->size + i) =
          FENCEPOST_VALUE;
    }
  }

  if (chunk->size >= count) {
    chunk->size = count;
    chunk->free = 0;
    for (size_t i = 0; i < FENCEPOST_SIZE; i++) {
      *((char *)chunk + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE + chunk->size + i) =
          FENCEPOST_VALUE;
    }
  } else if (chunk->free == 1 && chunk->next != NULL &&
             chunk->next->free == 1 &&
             chunk->size + chunk->next->size + MEMORY_CHUNK_SIZE +
                     FENCEPOST_SIZE * 2 >=
                 count) {
    chunk->size = count;
    if (chunk->next->next != NULL) {
      chunk->next->next->prev = chunk;
    }
    chunk->next = chunk->next->next;
    chunk->free = 0;
    checksum_all_chunks();
    for (size_t i = 0; i < FENCEPOST_SIZE; i++) {
      *((char *)chunk + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE + chunk->size + i) =
          FENCEPOST_VALUE;
    }
  } else if (chunk->size < count) {
    void *ptr = heap_malloc(count);
    if (ptr == NULL) {
      chunk->free = 0;
      chunk->size = temp_size;
      // chunk->checksum = sum_control_block(chunk);
      checksum_all_chunks();
      add_fenceposts(chunk);
      return NULL;
    }
    memcpy(ptr, memblock, chunk->size);

    memblock = ptr;
    return memblock;
  }
  // chunk->checksum = sum_control_block(chunk);
  checksum_all_chunks();
  return memblock;
}

void heap_free(void *memblock) {
  if (memory_manager.memory_start == NULL) {
    return;
  }
  if (memblock == NULL) {
    return;
  }
  if (get_pointer_type(memblock) != pointer_valid) {
    printf("ERROR: invalid pointer\n");
    return;
  }

  struct memory_chunk_t *chunk =
      (struct memory_chunk_t *)((char *)memblock - MEMORY_CHUNK_SIZE -
                                FENCEPOST_SIZE);
  if (chunk->free == 1) {
    return;
  }
  chunk->free = 1;
  // chunk->checksum = sum_control_block(chunk);
  checksum_all_chunks();

  // add add unalocated size to chunk
  long free_space = check_is_space_between_two_chunks(chunk);
  if (free_space < 0) {
    chunk->size += free_space * -1;
    // chunk->checksum = sum_control_block(chunk);
    checksum_all_chunks();
  }

  // merge free chunks
  merge_chunks(chunk);
}

void merge_chunks(struct memory_chunk_t *chunk) {
  if (chunk->next != NULL && chunk->next->free == 1) {
    chunk->size += chunk->next->size + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE;
    chunk->next = chunk->next->next;
    if (chunk->next != NULL) {
      chunk->next->prev = chunk;
    }
    checksum_all_chunks();
  }

  if (chunk->prev != NULL && chunk->prev->free == 1) {
    chunk->prev->size += chunk->size + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE;
    chunk->prev->next = chunk->next;
    if (chunk->next != NULL) {
      chunk->next->prev = chunk->prev;
    }
    checksum_all_chunks();
  }
}

long check_is_space_between_two_chunks(struct memory_chunk_t *chunk) {
  long size = 0;
  if (chunk->next == NULL) {
    size = (char *)chunk - (char *)memory_manager.memory_start +
           memory_manager.memory_size;
  } else {
    size = (char *)chunk - (char *)chunk->next;
  }
  return size + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE * 2 + chunk->size;
}

void *find_free_chunk(size_t size) {
  for (struct memory_chunk_t *chunk = memory_manager.first_chunk; chunk != NULL;
       chunk = chunk->next) {
    if (chunk->free == 1 && chunk->size >= size) {
      chunk->free = 0;
      chunk->size = size;
      add_fenceposts(chunk);
      if ((void *)chunk == memory_manager.memory_start) {
        chunk->checksum = sum_control_block(chunk);
        return (char *)memory_manager.memory_start + MEMORY_CHUNK_SIZE +
               FENCEPOST_SIZE;
      }
      checksum_all_chunks();
      return (char *)chunk + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE;
    }
  }
  return NULL;
}

void add_fenceposts(struct memory_chunk_t *chunk) {
  for (size_t i = 0; i < FENCEPOST_SIZE; i++) {
    *((char *)chunk + MEMORY_CHUNK_SIZE + i) = FENCEPOST_VALUE;
    *((char *)chunk + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE + chunk->size + i) =
        FENCEPOST_VALUE;
  }
}