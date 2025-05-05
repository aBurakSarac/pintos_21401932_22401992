#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <stdbool.h>

void swap_init(void);
int  swap_out(void *kpage);
bool swap_in(int slot, void *kpage);
void swap_free(int slot);
#endif
