#include "ordered_list.h"
#include <stdlib.h>
#include "threads/palloc.h"

void ordered_list_init(struct ordered_list *list) {
    list->head = NULL;
}

void ordered_list_insert(struct ordered_list *list, struct thread *t, int64_t wake_up_time) {
    struct ordered_list_elem *new_elem = palloc_get_page(PAL_ZERO);
    new_elem->t = t;
    new_elem->wake_up_time = wake_up_time;
    new_elem->next = NULL;

    if (list->head == NULL || wake_up_time < list->head->wake_up_time) {
        new_elem->next = list->head;
        list->head = new_elem;
    }
    else{
        struct ordered_list_elem *cur = list->head;
        while (cur->next != NULL && cur->next->wake_up_time <= wake_up_time) {
            cur = cur->next;
        }
        new_elem->next = cur->next;
        cur->next = new_elem;
    }
}

struct thread *ordered_list_pop(struct ordered_list *list) {
    if (list->head == NULL) {
        return NULL;
    }
    struct ordered_list_elem *first = list->head;
    list->head = first->next;
    struct thread *t = first->t;
    palloc_free_page(first);
    return t;
}

bool ordered_list_is_empty(struct ordered_list *list) {
    return list->head == NULL;
}


int64_t ordered_list_peek(struct ordered_list *list) {
    if (list->head == NULL) {
        return -1;
    }else{
        return list->head->wake_up_time;
    }
}
