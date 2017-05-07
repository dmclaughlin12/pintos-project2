#include "threads/thread.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/*
 * This struct maps a fd to a file.  Threads are able to keep track of 
 * their open files through this.
 */
struct map_fd_to_file {
  /* Variable to hold the file descriptor. */
  int fd; 
  /*  Struct to hold the file pointer of the current file. */  
  struct file* file;              
  /* This lets us put the file into a list. */
  struct list_elem file_elem;       
};

void syscall_init (void);

#endif /* userprog/syscall.h */

