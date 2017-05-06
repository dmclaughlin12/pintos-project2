#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

struct fd_elem {
  /* Variable to hold the file descriptor. */
  int fd; 
  /*  Struct to hold the file pointer of the current file. */  
  struct file* file;              
  /* This lets us put the file into a list. */
  struct list_elem file_elem;       
};
#endif /* userprog/syscall.h */

