#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "../lib/kernel/console.h"
#include "threads/vaddr.h" 
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

static void syscall_handler (struct intr_frame *);
static void check_user_address(const void *addr);
static int sys_write(int fd, const void *buffer, unsigned size);
static void check_user_buffer (const void *buffer, unsigned size);
static int sys_open (const char *file_name);
static int sys_read (int fd, void *buffer, unsigned size);
static struct file *get_file_by_fd (int fd);
static bool sys_remove(const char *file_name);
static struct lock file_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void syscall_handler (struct intr_frame *f) {
  int syscall_number;
  check_user_address(f->esp);
  syscall_number = *(int *)f->esp;
  switch (syscall_number) {
    case SYS_HALT:
      shutdown_power_off();
      break;

    case SYS_EXIT: {
      int status;
      check_user_address(f->esp + 4);
      status = *(int *)(f->esp + 4);
      thread_current()->exit_code = status;
      thread_exit();
      break;
    }

    case SYS_EXEC: {
      const char *cmd_line;
      check_user_address(f->esp + 4);
      cmd_line = *(const char **)(f->esp + 4);
      check_user_address(cmd_line);
      f->eax = process_execute(cmd_line);
      break;
    }

    case SYS_WAIT: {
      int child_tid;
      check_user_address(f->esp + 4);
      child_tid = *(int *)(f->esp + 4);
      f->eax = process_wait(child_tid);
      break;
    }

    case SYS_CREATE: {
      const char *file_name;
      unsigned initial_size;

      check_user_address(f->esp + 4);
      file_name = *(const char **)(f->esp + 4);

      check_user_address(f->esp + 8);
      initial_size = *(unsigned *)(f->esp + 8);

      check_user_address(file_name);

      f->eax = filesys_create(file_name, initial_size);
      break;
    }

    case SYS_REMOVE: {
      check_user_address(f->esp + 4);
      const char *file_name = *(const char **)(f->esp + 4);
      check_user_address(file_name);
      lock_acquire(&file_lock);
      f->eax = sys_remove(file_name);
      lock_release(&file_lock);
      break;
    }

    case SYS_OPEN: {
      char *file_name = *((char **)(f->esp + 4));
      check_user_address(file_name);
      int fd = sys_open(file_name);
      f->eax = fd;
      break;
    }

    case SYS_FILESIZE: {
      int fd = *(int *)(f->esp + 4);
      struct file *f_obj = get_file_by_fd(fd);
      if (f_obj == NULL) {
        f->eax = -1;
      } else {
        f->eax = file_length(f_obj);
      }
      break;
    }

    case SYS_READ: {
      int fd = *((int *)(f->esp + 4));
      void *buffer = *((void **)(f->esp + 8));
      unsigned size = *((unsigned *)(f->esp + 12));
      check_user_address(buffer);

      int read = sys_read(fd, buffer, size);
      f->eax = read;
      break;
    }

    case SYS_WRITE: {
      int fd;
      const void *buffer;
      unsigned size;

      check_user_address(f->esp + 4);
      fd = *(int *)(f->esp + 4);

      check_user_address(f->esp + 8);
      buffer = *(const void **)(f->esp + 8);

      check_user_address(f->esp + 12);
      size = *(unsigned *)(f->esp + 12);

      check_user_address(buffer);
      if (fd == 1) {
        lock_acquire(&file_lock);
        putbuf(buffer, size);
        lock_release(&file_lock);
        f->eax = size;
      } else {
        struct file_descriptor *temp = NULL;
        struct list_elem *e;
        lock_acquire(&file_lock);
        for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e)) {
          temp = list_entry(e, struct file_descriptor, elem);
          if (temp->file_id == fd) {
            f->eax = file_write(temp->file, buffer, size);
            break;
          }
        }
        lock_release(&file_lock);
        if (temp == NULL) {
          f->eax = -1;
        }
      }
      break;
    }

    case SYS_SEEK: {
      check_user_address(f->esp + 4);
      int fd = *(int *)(f->esp + 4);
      check_user_address(f->esp + 8);
      unsigned position = *(unsigned *)(f->esp + 8);
      struct file *file = get_file_by_fd(fd);
      if (file != NULL) {
        lock_acquire(&file_lock);
        file_seek(file, position);
        lock_release(&file_lock);
      }
      break;
    }

    case SYS_TELL: {
      check_user_address(f->esp + 4);
      int fd = *(int *)(f->esp + 4);
      struct file *file = get_file_by_fd(fd);
      if (file != NULL) {
        lock_acquire(&file_lock);
        f->eax = file_tell(file);
        lock_release(&file_lock);
      } else {
        f->eax = -1;
      }
      break;
    }

    case SYS_CLOSE: {
      check_user_address(f->esp + 4);
      int fd = *(int *)(f->esp + 4);
      struct thread *cur = thread_current();
      struct list_elem *e;
      struct file_descriptor *fd_struct = NULL;

      lock_acquire(&file_lock);
      for (e = list_begin(&cur->open_files); e != list_end(&cur->open_files); e = list_next(e)) {
        fd_struct = list_entry(e, struct file_descriptor, elem);
        if (fd_struct->file_id == fd) {
          list_remove(&fd_struct->elem);
          break;
        }
      }
      if (fd_struct != NULL) {
        file_close(fd_struct->file);
        free(fd_struct);
      }
      lock_release(&file_lock);
      break;
    }

    default:
      thread_current()->exit_code = -1;
      thread_exit();
      break;
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
  lock_acquire(&file_lock);
  struct file *f = filesys_open(file_name);
  if (f == NULL){
    lock_release(&file_lock);
    free(fd_struct);
    return -1;
  }
  lock_release(&file_lock);
  fd_struct->file_id = thread_current()->next_fd; 
  fd_struct->file = f;
  thread_current()->next_fd++;
  lock_acquire(&file_lock);
  list_push_back(&thread_current()->open_files, &fd_struct->elem);
  lock_release(&file_lock);

  return fd_struct->file_id;
}

int
sys_read (int fd, void *buffer, unsigned size) {

  struct thread *cur = thread_current();
  struct list_elem *e;
  struct file_descriptor *fd_struct = NULL;
  struct file_descriptor *temp;
  lock_acquire(&file_lock);
  for (e = list_begin(&cur->open_files); e != list_end(&cur->open_files); e = list_next(e)) {
    temp = list_entry(e, struct file_descriptor, elem);
    if (temp->file_id == fd) {
      fd_struct = temp;
      break;
    }
  }
  lock_release(&file_lock);
  if (fd_struct == NULL)
    return -1;
  lock_acquire(&file_lock);
  int read = file_read(fd_struct->file, buffer, size);
  lock_release(&file_lock);
  return read;

}

bool
sys_remove(const char *file_name) {
    if (file_name == NULL)
        return false;
    bool success = filesys_remove(file_name);
    return success;
}


static struct file *get_file_by_fd (int fd) {
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct file_descriptor *fd_struct;
  lock_acquire(&file_lock);
  for (e = list_begin(&cur->open_files); e != list_end(&cur->open_files); e = list_next(e)) {
    fd_struct = list_entry(e, struct file_descriptor, elem);
    if (fd_struct->file_id == fd) {
      lock_release(&file_lock);
      return fd_struct->file;
    }
  }
  lock_release(&file_lock);
  return NULL;
}