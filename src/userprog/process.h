#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <list.h>
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);


struct pass_in {
    bool load_success;
    char* file_name;
    struct semaphore load_sema;
    struct data_in_both* shared;
};


#endif /* userprog/process.h */

