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
    thread_current()->exit_code = status;
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
  else if(syscall_number==SYS_EXEC){
    check_user_address(f->esp + sizeof(int));
    char *cmd = *(char **)(f->esp + sizeof(int));
    check_user_address(cmd);
    f->eax = process_execute(cmd);
  }
}

static void check_user_address(const void *addr) {
  for (int i = 0; i < sizeof(int); i++) {
    if (!is_user_vaddr(addr + i) || pagedir_get_page(thread_current()->pagedir, addr+i) == NULL)
    {
      thread_current()->exit_code = -1;
      thread_exit();
    }
  } 
}
