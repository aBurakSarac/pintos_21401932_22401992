#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "../lib/kernel/console.h"
#include "threads/vaddr.h" 
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);
static void check_user_address(const void *addr);
static int sys_write(int fd, const void *buffer, unsigned size);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f) {
  int syscall_number;
  check_user_address(f->esp);
  syscall_number = *(int *)f->esp;
  
  if(syscall_number==SYS_EXIT){
    int status;
    check_user_address(f->esp + sizeof(int));
    status = *(int *)(f->esp + sizeof(int));
    thread_exit();
  }
  else if(syscall_number==SYS_WRITE){
    int fd;
    const void *buffer;
    unsigned size;
        
    check_user_address(f->esp + sizeof(int));
    fd = *(int *)(f->esp + sizeof(int));
        
    check_user_address(f->esp + 2 * sizeof(int));
    buffer = *(const void **)(f->esp + 2 * sizeof(int));
        
    check_user_address(f->esp + 3 * sizeof(int));
    size = *(unsigned *)(f->esp + 3 * sizeof(int));  

    check_user_address(buffer);
    if (fd == 1) {
      putbuf(buffer, size);
    }

    f->eax = size;
  }
}

static void check_user_address(const void *addr) {
  if (!is_user_vaddr(addr) || pagedir_get_page(thread_current()->pagedir, addr) == NULL)
    thread_exit();
}
