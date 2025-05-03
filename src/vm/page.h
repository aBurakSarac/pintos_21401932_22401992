#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "filesys/file.h"
#include "threads/synch.h"

enum vm_type { VM_BIN, VM_FILE, VM_ANON };

struct vm_entry {
    void *vaddr;
    bool writable;
    enum vm_type type;
    struct file *file;
    off_t offset;
    size_t read_bytes;
    size_t zero_bytes;
    bool loaded; 
    struct hash_elem helem;
};

struct supplemental_page_table {
    struct hash pages;
    struct lock page_lock;
};

void spt_init(struct supplemental_page_table *spt);
void spt_destroy(struct supplemental_page_table *spt);
bool spt_insert(struct supplemental_page_table *spt, struct vm_entry *vme);
struct vm_entry *spt_find(struct supplemental_page_table *spt, void *vaddr);
struct vm_entry *spt_remove(struct supplemental_page_table *spt, void *vaddr);

#endif 
