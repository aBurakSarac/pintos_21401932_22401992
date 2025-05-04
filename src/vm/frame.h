#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"


extern struct bitmap *frame_bitmap;
extern void **frame_kpages;
extern unsigned frame_count;

void frame_table_init(void);
void *frame_alloc(enum palloc_flags flags);
void frame_free(void *kpage);
void *frame_get_page(enum palloc_flags);

#endif 
