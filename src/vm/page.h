#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "filesys/file.h"
#include "threads/synch.h"

enum vm_type { VM_BIN, VM_FILE, VM_ANON, VM_MMAP };

struct vm_entry {
    void *vaddr;
    bool writable;
    enum vm_type type;
    struct file *file;
    off_t offset;
    size_t read_bytes;
    size_t zero_bytes;
    bool loaded; 
    int mapid;
    int swap_slot;
    struct hash_elem helem;
};

struct supplemental_page_table {
    struct hash pages;
    struct lock page_lock;
};

struct mmap_desc {
    int mapid;
    struct file *file;       
    void *base_addr;      
    size_t page_cnt;    
    struct list_elem elem;
};

void spt_init(struct supplemental_page_table *spt);
void spt_destroy(struct supplemental_page_table *spt);
bool spt_insert(struct supplemental_page_table *spt, struct vm_entry *vme);
struct vm_entry *spt_find(struct supplemental_page_table *spt, void *vaddr);
struct vm_entry *spt_remove(struct supplemental_page_table *spt, void *vaddr);
bool should_grow_stack(void *fault_addr, void *esp) ;

#endif 
