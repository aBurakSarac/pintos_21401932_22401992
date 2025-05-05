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
#include "round.h"
#include "threads/malloc.h"

static void syscall_handler (struct intr_frame *);
static void check_user_address(const void *addr);
static int sys_open (const char *file_name);
static struct file *get_file_by_fd (int fd);
static int sys_io(int fd, const void *buffer, unsigned size, bool is_write);
static int sys_mmap (int fd, void *uaddr);
static int sys_munmap (int mapid) ;            
static bool page_already_mapped (void *uaddr);    

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
  check_user_address(f->esp + 4);
  syscall_number = *(int *)f->esp;
  switch (syscall_number) {
    case SYS_HALT:
      shutdown_power_off();
      break;

    case SYS_EXIT: {
      int status = *(int *)(f->esp + 4);
      thread_current()->exit_code = status;
      thread_exit();
      break;
    }

    case SYS_EXEC: {
      const char *cmd_line;
      cmd_line = *(const char **)(f->esp + 4);
      check_user_address(cmd_line);
      f->eax = process_execute(cmd_line);
      break;
    }

    case SYS_WAIT: {
      int child_tid;
      child_tid = *(int *)(f->esp + 4);
      f->eax = process_wait(child_tid);
      break;
    }

    case SYS_CREATE: {
      const char *file_name;
      file_name = *(const char **)(f->esp + 4);
      check_user_address(file_name);
      check_user_address(f->esp + 8);

      unsigned initial_size;
      initial_size = *(unsigned *)(f->esp + 8);

      f->eax = filesys_create(file_name, initial_size);
      break;
    }

    case SYS_REMOVE: {
      const char *file_name ;
      file_name = *(const char **)(f->esp + 4);
      check_user_address(file_name);

      
      if (file_name == NULL)
        f->eax = false;
      lock_acquire(&file_lock);
      bool success = filesys_remove(file_name);
      lock_release(&file_lock);
      f->eax = success;

      break;
    }

    case SYS_OPEN: {
      char *file_name ;
      file_name = *((char **)(f->esp + 4));
      check_user_address(file_name);
      
      int fd = sys_open(file_name);
      f->eax = fd;
      break;
    }

    case SYS_FILESIZE: {
      int *fd;
      fd = *(int *)(f->esp + 4);

      struct file *file = get_file_by_fd(fd);
      if (file == NULL) {
        f->eax = -1;
      } else {
        lock_acquire(&file_lock);
        f->eax = file_length(file);
        lock_release(&file_lock);
      }
      break;
    }

    case SYS_READ: {
      int fd = *((int *)(f->esp + 4));

      check_user_address(f->esp + 8);
      void *buffer = *((void **)(f->esp + 8));
      check_user_address(buffer);

      check_user_address(f->esp + 12);
      unsigned size = *((unsigned *)(f->esp + 12));

      int read = sys_io(fd, buffer, size, false);
      f->eax = read;
      break;
    }

    case SYS_WRITE: {
      int fd = *((int *)(f->esp + 4));

      check_user_address(f->esp + 8);
      void *buffer = *((void **)(f->esp + 8));
      check_user_address(buffer);

      check_user_address(f->esp + 12);
      unsigned size = *((unsigned *)(f->esp + 12));

      f->eax = sys_io(fd, buffer, size, true);
      break;
    }

    case SYS_SEEK: {
      int fd = *(int *)(f->esp + 4);
      check_user_address(f->esp + 8);
      unsigned position = *(unsigned *)(f->esp + 8);

      struct file *file = get_file_by_fd(fd);
      if (file == NULL) {
        f->eax = -1;
      } else {
        lock_acquire(&file_lock);
        file_seek(file, position);
        lock_release(&file_lock);
      }
      break;
    }

    case SYS_TELL: {
      int *fd;
      fd = *(int *)(f->esp + 4);

      struct file *file = get_file_by_fd(fd);
      if (file == NULL) {
        f->eax = -1;
      } else {
        lock_acquire(&file_lock);
        f->eax = file_tell(file);
        lock_release(&file_lock);
      }
      break;
    }

    case SYS_CLOSE: {
      int fd = *(int *)(f->esp + 4);
      struct thread *cur = thread_current();
      struct list_elem *e;
      struct file_descriptor *temp = NULL;

      lock_acquire(&file_lock);
      for (e = list_begin(&cur->open_files); e != list_end(&cur->open_files); e = list_next(e)) {
        temp = list_entry(e, struct file_descriptor, elem);
        if (temp->file_id == fd) {
          list_remove(&temp->elem);
          break;
        }
      }
      if (temp != NULL) {
        file_close(temp->file);
      }
      lock_release(&file_lock);
      break;
    }

    case SYS_MMAP:
    {
      int fd = *(int *)(f->esp + 4);
      void *uaddr = *(void **)(f->esp + 8);
      f->eax = sys_mmap (fd, uaddr);
      break;
    }

    case SYS_MUNMAP:
    {
      int mapid = *(int *)(f->esp + 4);
      f->eax = sys_munmap (mapid);
      sys_munmap (mapid);
      break;
    }

    default:
      thread_current()->exit_code = -1;
      thread_exit();
      break;
  }
}

static void check_user_address(const void *addr) {
  for (int i = 0; i < 4; i++) {
    if (!is_user_vaddr(addr + i) || pagedir_get_page(thread_current()->pagedir, addr+i) == NULL)
    {
      thread_current()->exit_code = -1;
      thread_exit();
    }
  } 
}


int sys_open (const char *file_name)
{
  struct file_descriptor *fd = malloc(sizeof(struct file_descriptor));
  if (fd == NULL) {
    return -1;
  }
  lock_acquire(&file_lock);
  struct file *f = filesys_open(file_name);
  if (f == NULL){
    lock_release(&file_lock);
    free(fd);
    return -1;
  }
  lock_release(&file_lock);
  fd->file_id = thread_current()->next_fd; 
  fd->file = f;
  thread_current()->next_fd++;
  lock_acquire(&file_lock);
  list_push_back(&thread_current()->open_files, &fd->elem);
  lock_release(&file_lock);

  return fd->file_id;
}


sys_io(int fd, const void *buffer, unsigned size, bool is_write) {
  if (fd == 1 && is_write) {
    lock_acquire(&file_lock);
    putbuf(buffer, size);
    lock_release(&file_lock);
    return size;
  } else {
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
    int result;
    lock_acquire(&file_lock);
    if(is_write) {
      result = file_write(fd_struct->file, buffer, size);
    } else {
      result = file_read(fd_struct->file, buffer, size);
    }
    lock_release(&file_lock);
    return result;
  }
}

static int
sys_mmap (int fd, void *uaddr)
{
  if ((uintptr_t)uaddr % PGSIZE != 0 || uaddr == NULL)
    return -1;
  if (uaddr >= PHYS_BASE)
    return -1;

  struct file *file = get_file_by_fd(fd); 
  if (file == NULL)
    return -1;

  off_t length = file_length (file);
  if (length == 0)
    return -1;

  int page_cnt = DIV_ROUND_UP (length, PGSIZE);
  if ((uint8_t *)uaddr + page_cnt * PGSIZE > (uint8_t *)PHYS_BASE)
    return -1;
  for (int i = 0; i < page_cnt; i++)
    if (page_already_mapped (uaddr + i * PGSIZE))
      return -1;

  struct thread *cur = thread_current ();
  struct mmap_desc *md = malloc (sizeof *md);
  if (!md) return -1;
  md->mapid     = cur->next_mapid++;
  md->file      = file_reopen (file);
  file_deny_write(md->file);
  md->base_addr = uaddr;
  md->page_cnt  = page_cnt;
  list_push_back (&cur->mmap_list, &md->elem);

  off_t offset = 0;
  for (int i = 0; i < page_cnt; i++, offset += PGSIZE)
    {
      size_t read_bytes  = length >= PGSIZE ? PGSIZE : length;
      size_t zero_bytes  = PGSIZE - read_bytes;
      length -= read_bytes;

      struct vm_entry *vme = malloc (sizeof *vme);

      vme->vaddr       = uaddr + i * PGSIZE;
      vme->writable    = true;
      vme->type        = VM_MMAP;
      vme->file        = md->file;
      vme->offset      = offset;
      vme->read_bytes  = read_bytes;
      vme->zero_bytes  = zero_bytes;
      vme->loaded      = false;
      vme->mapid       = md->mapid;
      vme->swap_slot   = -1;

      if (!spt_insert (&cur->spt, vme))
        return -1;
    }

  return md->mapid;
}

static int
sys_munmap (int mapid) 
{
    struct thread *cur = thread_current ();
    struct list_elem *e = list_begin (&cur->mmap_list);

    while (e != list_end (&cur->mmap_list)) 
    {
        struct mmap_desc *md = list_entry (e, struct mmap_desc, elem);
        if (md->mapid == mapid) 
        {
            e = list_remove (e);
            for (int i = 0; i < md->page_cnt; i++) 
            {
                void *uaddr = md->base_addr + i * PGSIZE;
                struct vm_entry *vme = spt_remove (&cur->spt, uaddr);
                if (!vme)
                  continue;
                if (vme->loaded)
                {
                  void *kpage = pagedir_get_page (cur->pagedir, uaddr);
                  if (kpage && pagedir_is_dirty (cur->pagedir, uaddr)) 
                  {
                      file_write_at (md->file, kpage, vme->offset, vme->read_bytes);
                      pagedir_set_dirty (cur->pagedir, uaddr, false);
                  }
                  pagedir_clear_page (cur->pagedir, uaddr);
                  if (kpage)
                      frame_free (kpage);
                }
                if (vme->swap_slot != -1) 
                {
                    swap_free (vme->swap_slot);
                    free (vme);
                }
            }
         
            file_allow_write (md->file);
            file_close (md->file);
            free (md);
            return 0;
        }
        e = list_next (e);
    }
    return -1;
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

static bool
page_already_mapped (void *uaddr)
{
  struct thread *cur = thread_current ();
  if (pagedir_get_page (cur->pagedir, uaddr) != NULL)
    return true;
  if (spt_find (&cur->spt, uaddr) != NULL)
    return true;

  return false;
}