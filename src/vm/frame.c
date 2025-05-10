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
#include "threads/thread.h"
#include "vm/swap.h"

static struct lock vm_lock;
struct bitmap *frame_bitmap;
void        **frame_kpages;
size_t        frame_count;
static struct vm_entry **frame_rev_map;
static size_t clock_ptr;

void
frame_table_init(void) {
    size_t pool_bytes = palloc_get_pool_size(PAL_USER);
    frame_count = pool_bytes / PGSIZE;

    frame_bitmap = bitmap_create(frame_count);
    frame_kpages  = malloc(sizeof(void*) * frame_count);
    frame_rev_map = malloc(sizeof(struct vm_entry*) * frame_count);

    for (size_t i = 0; i < frame_count; i++) {
        bitmap_reset(frame_bitmap, i);
        frame_kpages[i] = NULL;
        frame_rev_map[i] = NULL;
    }

    lock_init(&vm_lock);
    clock_ptr = 0;
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
    kpage = palloc_get_page(flag | PAL_ZERO);
    if (!kpage) {
        struct vm_entry *victim = NULL;
        while (true) {
            victim = frame_rev_map[clock_ptr];
            if (victim == NULL
                || !pagedir_is_accessed(thread_current()->pagedir,
                                        victim->vaddr))
                break;
            pagedir_set_accessed(thread_current()->pagedir,
                                 victim->vaddr, false);
            clock_ptr = (clock_ptr + 1) % frame_count;
        }
        idx = clock_ptr;
        if (victim != NULL
            && pagedir_is_dirty(thread_current()->pagedir,
                                victim->vaddr)) {
            int slot = swap_out(frame_kpages[idx]);
            victim->swap_slot = slot;
        }
        

        if (victim)
            pagedir_clear_page(thread_current()->pagedir,
                               victim->vaddr);
        frame_rev_map[idx] = NULL;
        frame_kpages[idx]  = NULL;
        clock_ptr = (clock_ptr + 1) % frame_count;
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

void
frame_set_rev_map(void *kpage, struct vm_entry *vme) 
{
  uintptr_t base = (uintptr_t) palloc_get_pool_start(PAL_USER);
  size_t idx    = ((uintptr_t) kpage - base) / PGSIZE;
  lock_acquire(&vm_lock);
  frame_rev_map[idx] = vme;
  lock_release(&vm_lock);
}