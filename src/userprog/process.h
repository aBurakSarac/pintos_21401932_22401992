#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct process_block {
      tid_t tid;
      int exit_status;
      bool is_exited;
      bool waited;
      struct semaphore exit_sema;
      struct semaphore load_sema;
      bool load_status;
      struct list_elem elem;
  };

struct file_descriptor {
    int file_id;           
    struct file *file;
    struct list_elem elem; 
};


#endif /* userprog/process.h */
