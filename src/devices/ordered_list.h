#ifndef ORDERED_LIST_H
#define ORDERED_LIST_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "threads/thread.h"
#include "threads/palloc.h"


struct ordered_list_elem {
    struct thread *t;                   // Pointer to the sleeping thread
    int64_t wake_up_time;                // Tick when the thread should wake up
    struct ordered_list_elem *next;      // Pointer to the next element in the list
};


struct ordered_list {
    struct ordered_list_elem *head;  // Pointer to the first element (earliest wake-up time)
};

void ordered_list_init(struct ordered_list *list);
void ordered_list_insert(struct ordered_list *list, struct thread *t, int64_t wake_up_time);
struct thread *ordered_list_pop(struct ordered_list *list);
bool ordered_list_is_empty(struct ordered_list *list);
int64_t ordered_list_peek(struct ordered_list *list);

#endif 
