#include "vm/swap.h"
#include "lib/kernel/bitmap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include <debug.h>
#include "threads/vaddr.h"

static struct block *swap_block;
static struct bitmap *swap_bitmap;
static struct lock swap_lock;
static size_t swap_slots;

void
swap_init(void) {
  swap_block = block_get_role(BLOCK_SWAP);
  ASSERT(swap_block != NULL);

  swap_slots = block_size(swap_block) / (PGSIZE / BLOCK_SECTOR_SIZE);
  swap_bitmap = bitmap_create(swap_slots);
  bitmap_set_all(swap_bitmap, false);
  lock_init(&swap_lock);
}

int
swap_out(void *kpage) {
  lock_acquire(&swap_lock);

  size_t slot = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
  if (slot == BITMAP_ERROR)
    PANIC("swap_out");
  for (size_t i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++){
    block_write(swap_block, slot*(PGSIZE/BLOCK_SECTOR_SIZE)+i, kpage + i*BLOCK_SECTOR_SIZE);
  }

  lock_release(&swap_lock);
  return (int)slot;
}

bool
swap_in(int slot, void *kpage) {
  lock_acquire(&swap_lock);

  if (slot >= swap_slots || !bitmap_test(swap_bitmap, slot)) {
    lock_release(&swap_lock);
    return false;
  }
  for (size_t i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++){
    block_read(swap_block, slot*(PGSIZE/BLOCK_SECTOR_SIZE)+i, kpage + i*BLOCK_SECTOR_SIZE);
  }
  bitmap_reset(swap_bitmap, slot);

  lock_release(&swap_lock);
  return true;
}

void
swap_free (int slot)
{
  ASSERT (slot >= 0 && slot < swap_slots);
  lock_acquire(&swap_lock);
  bitmap_reset(swap_bitmap, slot);
  lock_release(&swap_lock);
}