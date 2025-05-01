#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"

void frame_table_init(void);

void *frame_alloc(enum palloc_flags flags);

void frame_free(void *kpage);

#endif 
