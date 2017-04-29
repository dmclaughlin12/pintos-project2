#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "lib/kernel/console.h"
#include "lib/user/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <string.h>
#include "devices/shutdown.h"

int * get_fd_arg(struct intr_frame *f);
char ** get_buffer_arg(struct intr_frame *f);
unsigned* get_size_arg(struct intr_frame *f);
void is_valid_buffer(char ** buffer, unsigned * size);
static void syscall_handler (struct intr_frame *);
static struct lock file_lock;
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  int* sys_call_number = (int*) f->esp;
  is_valid(sys_call_number);
  switch(*sys_call_number){
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
      // Retrieve arguments and is_valid.
      int *exit_code = (int*) ((char*)f->esp + 4);
      is_valid(exit_code);
      f->eax = *exit_code;
      exit(exit_code);
      break;
    }
    case SYS_EXEC: {
      // Retrieve arguments and is_valid.
      char** raw = (char**) ((char*)f->esp+4);
      is_valid(raw);
      is_valid(*raw);
      for(unsigned int i = 0; i < strlen(*raw); ++i){
        is_valid(*raw + i);
      }
      f->eax = process_execute(*raw);
      break;
    }
    case SYS_WAIT: {
      // Retrieve arguments and is_valid.
      pid_t *wait_pid = (pid_t*) ((char*)f->esp + 4);
      is_valid(wait_pid);
      f->eax = process_wait(*wait_pid);
      break;
    }
    case SYS_CREATE: {
      // Retrieve arguments and is_valid.
      char** raw = (char**) ((char*)f->esp+4);
      is_valid(raw);
      is_valid(*raw);
      for(unsigned int i = 0; i < strlen(*raw); ++i){
        is_valid(*raw + i);
      }
      unsigned *size = (unsigned*) ((char*)f->esp+8);
      is_valid(size);
      f->eax = sys_create(*raw,*size);
      break;
    }
    case SYS_REMOVE: {
      // Retrieve arguments and is_valid.
      char** raw = (char**) ((char*)f->esp+4);
      is_valid(raw);
      is_valid(*raw);
      for(unsigned int i = 0; i < strlen(*raw); ++i){
      is_valid(*raw + i);
      }
      f->eax = sys_remove(*raw);
      break;
    }
    case SYS_OPEN: {
      // Retrieve arguments and is_valid.
      char** raw = (char**) ((char*)f->esp+4);
      is_valid(raw);
      is_valid(*raw);
      for(unsigned int i = 0; i < strlen(*raw); ++i){
        is_valid(*raw + i);
      }
      f->eax = sys_open(*raw);
      break;
    }
    case SYS_FILESIZE: {
      // Retrieve arguments and is_valid.
      int *fd = (int*) ((char*)f->esp +4);
      is_valid(fd);

      f->eax = sys_filesize(*fd);

      break;
    }
    case SYS_READ:
      // Retrieve arguments and is_valid.
      int* fd = get_fd_arg(f);
      char** buffer = get_buffer_arg(f);
      unsigned* size = get_size_arg(f);
      is_valid(fd);
      is_valid(buffer);
      is_valid(size);
      is_valid_buffer(buffer, size);

      f->eax = sys_read(*fd,*buffer,*size);
      break;
    case SYS_WRITE: {
      // Retrieve arguments and is_valid.
      int* fd = get_fd_arg(f);
      is_valid(fd);

      unsigned* size = get_size_arg(f);
      is_valid(size);

      char** buffer = get_buffer_arg(f);
      is_valid_buffer(buffer);

      f->eax = sys_write(*fd,*buffer,*size);

      break;
    }
    case SYS_SEEK: {
      // Retrieve arguments and is_valid.
      int* fd = (int*) ((char*)f->esp + 4);
      is_valid(fd);
      unsigned* pos = (unsigned*) ((char*)f->esp + 8);
      is_valid(pos);
      sys_seek(*fd,*pos);
      break;
    }
    case SYS_TELL: {
      // Retrieve arguments and is_valid.
      int* fd = (int*) ((char*)f->esp + 4);
      is_valid(fd);
      f->eax = sys_tell(*fd);
      break;
    }
    case SYS_CLOSE: {
      // Retrieve arguments and is_valid.
      int* fd = (int*) ((char*)f->esp + 4);
      is_valid(fd);
      sys_close(*fd);
      break;
    }
    default: {
      break;
    }
  }
}
void exit(int exit_code){
  struct thread *t = thread_current();
  t->parent_share->exit_code = exit_code;
  thread_exit();
}

int s_open(char* file){
  // Acquire the file operation lock.
    lock_acquire(&file_lock);
    struct thread *t = thread_current();
    int retval;
    struct file* op = filesys_open(file);
    // Create a new fd_elem struct, which contains a mapping from a
    // file descriptor to an inode.
    struct fd_elem* fm = (struct fd_elem*) malloc(sizeof(struct fd_elem));
    if(op == NULL){
      retval = -1;
    }else{
      // Get the next available file descriptor.
      fm->fd = ++t->next_fd;
      // Set the file pointer to the opened file.
      fm->file = op;
      // Add file to the list of this thread's files.
      list_push_back(&t->files,&fm->file_elem);
      // Return value is the file descriptor.
      retval = fm->fd;
    }
    // Release the file operation lock.
    lock_release(&file_lock);
    return retval;
}

int s_create(char* file, unsigned size) {
    // Acquire the file operation lock.
    lock_acquire(&file_lock);
    int retval;
    // Call filesys_create with the given file and size.
    retval = filesys_create(file,size);
    // Release the file system lock.
    lock_release(&file_lock);
    return retval;
}

int s_filesize(int fd) {
    // Acquire the file operation lock.
    lock_acquire(&file_lock);
    // Return value defaults to negative 1.
    int retval = -1;
    struct thread* t = thread_current();
    struct list_elem *e;
    // Loop through list to find the file with the given file descriptor.
    for (e = list_begin (&t->files); e != list_end (&t->files);
      e = list_next (e))
      {
        struct fd_elem* fd_e = list_entry (e, struct fd_elem, file_elem);
        if(fd_e->fd == fd){
            // Set return value if found.
            retval = file_length(fd_e->file);
            break;
          }
      
      }
    // Release the file operation lock.
    lock_release(&file_lock);
    return retval;
}
int s_read(int fd, char* buf, unsigned size){
    // Acquire the file operation lock.
    lock_acquire(&file_lock);
    // Initialize retval to 0.
    int retval = 0;
    // Check if this is a console read.
    if(fd == 0){
      // Get as many characters from the console as specified in
      // The size argument.
      for(unsigned int i = 0; i < size; ++i){
        buf[i] = input_getc();
      }
        retval = size;
    }
    // Otherwise, it is a file read. Search for the file in the thread's
    // file descriptor list.
    else{
      struct thread* t = thread_current();
      struct list_elem *e;
      for (e = list_begin (&t->files); e != list_end (&t->files);
        e = list_next (e))
        {
          struct fd_elem* fd_e = list_entry (e, struct fd_elem, file_elem);
          if(fd_e->fd == fd){
            // If found read the file.
            retval = file_read(fd_e->file,buf,size);
            break;
          }
        }
    }
    // Release the file operation lock.
    lock_release(&file_lock);
    // Return the number of bytes read.
    return retval;
}
int sys_write(int fd, char* buf, unsigned size){
      // Get the file operation lock.
      lock_acquire(&file_lock);
      // Initialize return value to 0.
      int retval = 0;
      // If this is a console write, call putbuf().
      if (fd == 1){
        putbuf(buf,size);
        retval = size;
      }
      // Otherwise, this is a file write, so search for the correct file
      // descriptor in the thread's fd_elem.
      else{
        struct thread* t = thread_current();
        struct list_elem *e;
        for (e = list_begin (&t->files); e != list_end (&t->files);
          e = list_next (e))
          {
            struct fd_elem* fd_e = list_entry (e, struct fd_elem, file_elem);
            if(fd_e->fd == fd){
              // Write to the file if found.
              retval = file_write(fd_e->file,buf,size);
              break;
            }
          }
      }
      // Release the file operation lock.
      lock_release(&file_lock);
      return retval;
}

void s_seek(int fd, unsigned position){
    // Get the file operation lock.
    lock_acquire(&file_lock);
    struct thread* t = thread_current();
    struct list_elem *e;
    for (e = list_begin (&t->files); e != list_end (&t->files);
      e = list_next (e))
      {
        struct fd_elem* fd_e = list_entry (e, struct fd_elem, file_elem);
        if(fd_e->fd == fd){
            // Seek to requested position if the file is found.
            file_seek(fd_e->file,position);
            break;
        }
      }
    // Release the file operation lock.
    lock_release(&file_lock);
}

unsigned s_tell(int fd) {
    struct thread* t = thread_current();
    struct list_elem *e;
    int retval = 0;
    // Get the file operation lock.
    lock_acquire(&file_lock);
    for (e = list_begin (&t->files); e != list_end (&t->files);
      e = list_next (e))
      {
        struct fd_elem* fd_e = list_entry (e, struct fd_elem, file_elem);
        if(fd_e->fd == fd){
            // Return the position of the cursor in the file.
            retval = file_tell(fd_e->file);
            break;
        }
      }
    // Release the file operation lock.
    lock_release(&file_lock);
    return retval;
}

void s_close(int fd){
    struct thread* t = thread_current();
    // Get the file operation lock.
    lock_acquire(&file_lock);
    if(fd != 0 && fd != 1){
      struct list_elem *e;
      // Loop through each file in the thread's fd list.
      for (e = list_begin (&t->files); e != list_end (&t->files);
        e = list_next (e))
        {
          struct fd_elem* fd_e = list_entry (e, struct fd_elem, file_elem);
          if(fd_e->fd == fd){
            // Remove from the list.
            list_remove(e);
            // Close the file.
            file_close(fd_e->file);
            // Free the memory used for this file.
            free(fd_e);
            break;
          }
        }
    }
    // Release the file operation lock.
    lock_release(&file_lock);
}

int s_remove(char* name){
    // Get the file operation lock.
    lock_acquire(&file_lock);
    int retval;
    // Remove the file with the given.
    retval = filesys_remove(name);
    // Release the file operation lock.
    lock_release(&file_lock);
    return retval;
}

void is_valid(void* addr){
  for(int i = 0; i < 4; ++i){
    if(addr+i == NULL || !is_user_vaddr(addr+i) || pagedir_get_page(thread_current()->pagedir,addr+i) == NULL){
      exit(-1);
    }
  }
}
int * get_fd_arg(struct intr_frame *f)
{
  return (int *)((char*) f->esp + 4);
}
char ** get_buffer_arg(struct intr_frame *f)
{
  return (char**) ((char*) f->esp +8);
}
unsigned * get_size_arg(struct intr_frame *f)
{
  return (unsigned*) ((char*) f->esp + 12);
}

void is_valid_buffer(char ** buffer, unsigned * size)
{
  is_valid_pointer(buffer);
  is_valid_pointer(*buffer);
  for(unsigned int i = 0; i < *size; ++i)
  {
        is_valid_pointer(*buffer + i);
    }
}
