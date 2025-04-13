#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "../lib/kernel/console.h"
#include "threads/vaddr.h" 
#include "userprog/pagedir.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);
static void check_user_address(const void *addr);
static int sys_write(int fd, const void *buffer, unsigned size);
static void check_user_buffer (const void *buffer, unsigned size);
static int sys_open (const char *file_name);
static int sys_read (int fd, void *buffer, unsigned size);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f) {
  int syscall_number;
  check_user_address(f->esp);
  syscall_number = *(int *)f->esp;
  if (syscall_number == SYS_HALT) {
    //passes tests?
  }
  else if(syscall_number==SYS_EXIT){
    int status;
    check_user_address(f->esp + sizeof(int));
    status = *(int *)(f->esp + sizeof(int));
    thread_current()->exit_code = status;
    thread_exit();
  }
  else if (syscall_number==SYS_EXEC){
    const char *cmd_line;
    check_user_address(f->esp + sizeof(int));
    cmd_line = *(const char **)(f->esp + sizeof(int));
    check_user_address(cmd_line);
    f->eax = process_execute(cmd_line);
  }
  else if(syscall_number==SYS_WAIT){
    int child_tid;
    check_user_address(f->esp + sizeof(int));
    child_tid = *(int *)(f->esp + sizeof(int));
    f->eax = process_wait(child_tid);
  }
  else if(syscall_number==SYS_CREATE){
    const char *file_name;
    unsigned initial_size;
        
    check_user_address(f->esp + sizeof(int));
    file_name = *(const char **)(f->esp + sizeof(int));
        
    check_user_address(f->esp + 2 * sizeof(int));
    initial_size = *(unsigned *)(f->esp + 2 * sizeof(int));

    check_user_address(file_name);
        
    f->eax = filesys_create(file_name, initial_size);
  }
  else if(syscall_number==SYS_REMOVE){
    
  }
  else if(syscall_number==SYS_OPEN){
    char *file_name = *((char **)(f->esp + sizeof(char *)));
    check_user_address(file_name);
    int fd = sys_open(file_name);
    f->eax = fd; 
  }
  else if(syscall_number==SYS_FILESIZE){

  }
  else if(syscall_number==SYS_READ){
    int fd = *((int *)(f->esp + sizeof(int)));
    void *buffer = *((void **)(f->esp + sizeof(int) * 2));
    unsigned size = *((unsigned *)(f->esp + sizeof(int) * 3));
    check_user_address(buffer);

    int read = sys_read(fd, buffer, size);
    f->eax = read;
    
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
  else if(syscall_number==SYS_SEEK){
    
  }
  else if(syscall_number==SYS_TELL){
    
  }
  else if(syscall_number==SYS_CLOSE){
    
  }
  else{
    thread_current()->exit_code = -1;
    thread_exit();
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


int sys_open (const char *file_name)
{
  struct file_descriptor *fd_struct = malloc(sizeof(struct file_descriptor));
  if (fd_struct == NULL) {
    return -1;
  }

  struct file *f = filesys_open(file_name);
  if (f == NULL)
    return -1;

  fd_struct->file_id = thread_current()->next_fd; 
  fd_struct->file = f;
  thread_current()->next_fd++;
  list_push_back(&thread_current()->open_files, &fd_struct->elem);

  return fd_struct->file_id;
}

int
sys_read (int fd, void *buffer, unsigned size) {

  struct thread *cur = thread_current();
  struct list_elem *e;
  struct file_descriptor *fd_struct = NULL;
  struct file_descriptor *temp;
  for (e = list_begin(&cur->open_files); e != list_end(&cur->open_files); e = list_next(e)) {
    temp = list_entry(e, struct file_descriptor, elem);
    if (temp->file_id == fd) {
      fd_struct = temp;
      break;
    }
  }

  if (fd_struct == NULL)
    return -1;

  return file_read(fd_struct->file, buffer, size);
}