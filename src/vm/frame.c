#include "vm/frame.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include <stdio.h>
#include "lib/kernel/bitmap.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"

static struct lock vm_lock;
struct bitmap *frame_bitmap;
void        **frame_kpages;
size_t        frame_count;

void
frame_table_init(void) {
    size_t pool_bytes = palloc_get_pool_size(PAL_USER);
    frame_count = pool_bytes / PGSIZE;

    frame_bitmap = bitmap_create(frame_count);
    frame_kpages  = malloc(sizeof(void*) * frame_count);

    for (size_t i = 0; i < frame_count; i++) {
        bitmap_reset(frame_bitmap, i);
        frame_kpages[i] = NULL;
    }

    lock_init(&vm_lock);
}

void *
frame_alloc(enum palloc_flags flag) {
    void *kpage;
    flag |= PAL_USER;

    lock_acquire(&vm_lock);
    size_t idx = bitmap_scan_and_flip(frame_bitmap, 0, 1, false);
    if (idx == BITMAP_ERROR) {
        lock_release(&vm_lock);
        return NULL;
    }
    kpage = palloc_get_page(flag | PAL_ASSERT | PAL_ZERO);
    if (!kpage) {
        bitmap_reset(frame_bitmap, idx);
        lock_release(&vm_lock);
        return NULL;
    }

    frame_kpages[idx] = kpage;
    lock_release(&vm_lock);

    return kpage;
}

void
frame_free(void *kpage) {
    if (!kpage)
        return;

    lock_acquire(&vm_lock);
    uintptr_t base = (uintptr_t)palloc_get_pool_start(PAL_USER);
    size_t idx = ((uintptr_t)kpage - base) / PGSIZE;

    if (idx < frame_count && frame_kpages[idx] == kpage) {
        bitmap_reset(frame_bitmap, idx);
        frame_kpages[idx] = NULL;
        palloc_free_page(kpage);
    } else {
        PANIC("frame_free");
    }

    lock_release(&vm_lock);
    return;
}
