#include "vm/frame.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include <stdio.h>

static struct lock vm_lock;

void
frame_table_init(void) {
    lock_init(&vm_lock);
}

void *
frame_alloc(enum palloc_flags flag) {
    void *kpage;
    flag |= PAL_USER;

    lock_acquire(&vm_lock);
    kpage = palloc_get_page(flag);
    if (kpage == NULL) {
        lock_release(&vm_lock);
        PANIC("Out of memory");
    }
    lock_release(&vm_lock);


    return kpage;
}

void
frame_free(void *kpage) {
    if (!kpage)
        return;

    lock_acquire(&vm_lock);
    palloc_free_page(kpage);
    lock_release(&vm_lock);
    
    return;
}
