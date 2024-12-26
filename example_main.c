#include "include/heap.h"

int main() {
    heap_setup();
    
    void* ptr = heap_calloc(1, 10);
    for (size_t i = 0; i < 10; i++) {
        *((char*)ptr + i) = 'a' + i;
    }

    for (size_t i = 0; i < 10; i++) {
        printf("%c", *((char*)ptr + i));
    }
    printf("\n");

    heap_realloc(ptr, 20);

    for (size_t i = 0; i < 20; i++) {
        printf("%c", *((char*)ptr + i) ? *((char*)ptr + i) : '0');
    }

    heap_free(ptr);
    heap_clean();
    return 0;
}