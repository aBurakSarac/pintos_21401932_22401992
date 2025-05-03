#include "vm/page.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "lib/kernel/hash.h"
#include "threads/vaddr.h"

static unsigned
vm_hash(const struct hash_elem *e, void *aux UNUSED) {
    struct vm_entry *vme = hash_entry(e, struct vm_entry, helem);
    return hash_bytes(&vme->vaddr, sizeof vme->vaddr);
}

static bool
vm_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    struct vm_entry *va = hash_entry(a, struct vm_entry, helem);
    struct vm_entry *vb = hash_entry(b, struct vm_entry, helem);
    return va->vaddr < vb->vaddr;
}

void
spt_init(struct supplemental_page_table *spt) {
    lock_init(&spt->page_lock);
    hash_init(&spt->pages, vm_hash, vm_less, NULL);
}

bool
spt_insert(struct supplemental_page_table *spt,
           struct vm_entry *vme) {
    lock_acquire(&spt->page_lock);
    struct hash_elem *old = hash_insert(&spt->pages, &vme->helem);
    lock_release(&spt->page_lock);
    return old == NULL;
}

struct vm_entry *
spt_find(struct supplemental_page_table *spt, void *addr) {
    void *page = pg_round_down(addr);
    struct vm_entry tmp;
    struct hash_elem *e;

    tmp.vaddr = page;
    lock_acquire(&spt->page_lock);
    e = hash_find(&spt->pages, &tmp.helem);
    lock_release(&spt->page_lock);
    if (e) {
        return hash_entry(e, struct vm_entry, helem);
    } else {
        return NULL;
    }
}

struct vm_entry *
spt_remove(struct supplemental_page_table *spt, void *addr) {
    void *page = pg_round_down(addr);
    struct vm_entry tmp;
    struct hash_elem *e;
    tmp.vaddr = page;
    lock_acquire(&spt->page_lock);
    e = hash_delete(&spt->pages, &tmp.helem);
    lock_release(&spt->page_lock);

    if (e) {
        return hash_entry(e, struct vm_entry, helem);
    } else {
        return NULL;
    }
}
