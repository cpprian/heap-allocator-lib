#include "heap.h"

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
    struct memory_chunk_t* chunk = memory_manager.first_chunk;
    while (chunk != NULL) {
        if (!chunk->free && chunk->size > max_size) {
            max_size = chunk->size;
        }
        chunk = chunk->next;
    }
    return max_size;
}

int is_pointer_within_heap(const void* pointer) {
    return (char*)pointer >= (char*)memory_manager.memory_start &&
           (char*)pointer < (char*)memory_manager.memory_start + memory_manager.memory_size;
}

enum pointer_type_t get_pointer_type(const void* const pointer) {
    if (pointer == NULL) {
        return pointer_null;
    }
    if (!is_pointer_within_heap(pointer)){
        return pointer_heap_corrupter;
    }

    int check = 0;
    struct memory_chunk_t* chunk = (struct memory_chunk_t*)memory_manager.first_chunk;
    while (chunk != NULL) {
        if (is_allocated(pointer, chunk)) {
            return pointer_valid;
        } else if (is_unallocated(pointer, chunk)) {
            return pointer_unallocated;
        } else if (check = is_inside_data_block(pointer, chunk)) {
            if (check == 2) {
                return pointer_unallocated;
            }
            return pointer_inside_data_block;
        } else if (check = is_inside_fences(pointer, chunk)) {
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

int is_inside_data_block(const void* const pointer, struct memory_chunk_t* chunk) {
    long ptr = (char*)pointer - (char*)chunk;
    long head_block = ptr - MEMORY_CHUNK_SIZE - FENCEPOST_SIZE;
    long tail_block = (char*)chunk + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE + chunk->size - (char*)pointer;
    if (head_block > 0 && tail_block > 0) {
        if (chunk->free) {
            return 2;
        }
        return 1;
    }
    return 0;
}

int is_inside_fences(const void* const pointer, struct memory_chunk_t* chunk) {
    long ptr = (char*)chunk - (char*)pointer;
    if (ptr <= 0) {
        long right_fence = ptr * -1 - FENCEPOST_SIZE - MEMORY_CHUNK_SIZE;
        if (right_fence * -1 >= 0 && right_fence * -1 <= (long)FENCEPOST_SIZE) {
            if (chunk->free == 1) {
                return 2;
            }
            return 1;
        } else if (right_fence - (long)chunk->size >= 0 && right_fence - (long)chunk->size < (long)FENCEPOST_SIZE) {
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

int is_inside_control_block(const void* const pointer, struct memory_chunk_t* chunk) {
    long ptr = (char*)chunk - (char*)pointer;
    long is_inside_cb = ptr * -1 - (long)(MEMORY_CHUNK_SIZE);
    if ((is_inside_cb > 0 && is_inside_cb < (long)MEMORY_CHUNK_SIZE) ||
        (is_inside_cb < 0 && is_inside_cb * -1 - ptr <= (long)MEMORY_CHUNK_SIZE)) 
    {
        return 1;
    }
    return 0;
}

int is_unallocated(const void* const pointer, struct memory_chunk_t* chunk) {
    long ptr = (char*)chunk - (char*)pointer + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE;
    long padding = check_is_space_between_two_chunks(chunk);
    if (-1 * padding + (long)chunk->size >= ptr * -1 &&
        -1 * ptr - (long)FENCEPOST_SIZE >= (long)chunk->size) 
    {
        return 1;
    }
    return chunk->free && ptr * -1 >= 0 && ptr * -1 <= (long)chunk->size;
}

int is_allocated(const void* const pointer, struct memory_chunk_t* chunk) {
    long ptr = (char*)chunk - (char*)pointer + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE;
    return !chunk->free && ptr == 0;
}

int heap_setup(void) {
    if (memory_manager.memory_start != NULL) {
        heap_clean();
    }

    // TODO: implement own custom_sbrk
    memory_manager.memory_start = custom_sbrk(0);
    if (memory_manager.memory_start == (void*) -1) {
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
    for (struct memory_chunk_t* chunk = memory_manager.first_chunk; 
        chunk != NULL;) 
    {
        chunk->size = 0;
        chunk->prev = NULL;

        struct memory_chunk_t* next = chunk->next;
        if (next != NULL) {
            break;
        }
        chunk->next = NULL;
        chunk = next;
    }

    // clear sbrk
    custom_sbrk(-memory_manager.memory_size);
    memory_manager.memory_size = 0;

    // clear memory_manager
    memory_manager.memory_start = NULL;
}

int heap_validate(void) {
    if (memory_manager.memory_start == NULL) {
        return 2;
    }

    for (struct memory_chunk_t* chunk = memory_manager.first_chunk; 
        chunk != NULL; 
        chunk = chunk->next) 
    {
        // check is user write to control block
        size_t checksum = sum_control_block(chunk);
        if (checksum != chunk->checksum) {
            return 3;
        }
        // check is user write to fenceposts
        for (size_t i = 0; i < FENCEPOST_SIZE; i++) {
            if ((*((char*)chunk + MEMORY_CHUNK_SIZE + i) != FENCEPOST_VALUE ||
                *((char*)chunk + MEMORY_CHUNK_SIZE + FENCEPOST_SIZE + chunk->size + i) != FENCEPOST_VALUE) &&
                chunk->free == 0) 
            {
                return 1;
            }
        }
    }

    return 0;
}

size_t sum_control_block(struct memory_chunk_t* chunk) {
    size_t sum = 0;
    struct memory_chunk_t temp = *chunk;
    temp.checksum = 0;
    char* ptr = (char*)&(temp.size);
    for (size_t i = 0; i < sizeof(chunk->size); i++) {
        sum += ptr[i];
    }
    ptr = (char*)&(temp.free);
    for (size_t i = 0; i < sizeof(chunk->free); i++) {
        sum += ptr[i];
    }
    ptr = (char*)&(temp.next);
    for (size_t i = 0; i < sizeof(chunk->next); i++) {
        sum += ptr[i];
    }
    ptr = (char*)&(temp.prev);
    for (size_t i = 0; i < sizeof(chunk->prev); i++) {
        sum += ptr[i];
    }
    ptr = (char*)&(temp.checksum);
    for (size_t i = 0; i < sizeof(chunk->checksum); i++) {
        sum += ptr[i];
    }
    return sum;
}

void checksum_all_chunks() {
    for (struct memory_chunk_t* chunk = memory_manager.first_chunk; 
        chunk != NULL; 
        chunk = chunk->next) 
    {
        chunk->checksum = sum_control_block(chunk);
    }
}