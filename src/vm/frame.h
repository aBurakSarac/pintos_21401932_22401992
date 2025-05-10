#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"
#include "vm/page.h"


extern struct bitmap *frame_bitmap;
extern void **frame_kpages;
extern unsigned frame_count;

void frame_table_init(void);
void *frame_alloc(enum palloc_flags flags);
void frame_free(void *kpage);
void frame_set_rev_map(void *kpage, struct vm_entry *vme) ;


#endif 
