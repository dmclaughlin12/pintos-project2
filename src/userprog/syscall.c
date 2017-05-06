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

#define fisrtArg (int *)((char*) f->esp + 4)
#define secondArg (char**) ((char*) f->esp +8)
#define thirdArg   ((char*) f->esp + 12)

void is_valid(void* addr);
void is_valid_buffer_size(char ** buffer, unsigned* size);
void is_valid_buffer(char ** buffer);
static void syscall_handler (struct intr_frame *);
static struct lock file_lock;
void halt(void);
void exit(int status);
pid_t exec (const char*cmd_line);
int wait(pid_t pid);
bool create (const char*file, unsigned initial_size);
bool remove(const char *file);
int open (const char *file);
int filesize(intfd);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

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
    case SYS_HALT: {
      halt();
      break;
    }
    case SYS_EXIT: {
      int *status = fisrtArg;
      is_valid(status);
      f->eax = *status;
      exit(*status);
      break;
    }
    case SYS_EXEC: {
      char** buffer = (char**) fisrtArg;
      is_valid(buffer);
      is_valid(*buffer);
      is_valid_buffer(buffer);
      f->eax = exec(*buffer);
      break;
    }
    case SYS_WAIT: {
      pid_t *wait_pid = (pid_t*) fisrtArg;
      is_valid(wait_pid);
      f->eax = wait(*wait_pid);
      break;
    }
    case SYS_CREATE: {
      char** buffer = (char**) fisrtArg;
      is_valid(buffer);
      is_valid(*buffer);
      is_valid_buffer(buffer);
      unsigned *size = (unsigned*) secondArg;
      is_valid(size);
      f->eax = create(*buffer,*size);
      break;
    }
    case SYS_REMOVE: {
      char** buffer = (char**) fisrtArg;
      is_valid(buffer);
      is_valid(*buffer);
      is_valid_buffer(buffer);

      f->eax = remove(*buffer);
      break;
    }
    case SYS_OPEN: {
      char** buffer = (char**) fisrtArg;
      is_valid(buffer);
      is_valid(*buffer);
      is_valid_buffer(buffer);

      f->eax = open(*buffer);
      break;
    }
    case SYS_FILESIZE: {
      int *fd = fisrtArg;
      is_valid(fd);
      f->eax = filesize(*fd);
      break;
    }
    case SYS_READ: {
      int* fd = fisrtArg;
      char** buffer = secondArg;
      unsigned* size = thirdArg;
      is_valid(fd);
      is_valid(buffer);
      is_valid(size);
      is_valid_buffer_size(buffer, size);
      f->eax = sys_read(*fd,*buffer,*size);
      break;
    }
    case SYS_WRITE: {
      int* fd = fisrtArg;
      is_valid(fd);
      unsigned* size = thirdArg;
      is_valid(size);
      char** buffer = secondArg;
      is_valid(buffer);
      is_valid(*buffer);
      is_valid_buffer_size(buffer, size);
      f->eax = sys_write(*fd,*buffer,*size);
      break;
    }
    case SYS_SEEK: {
      int* fd = fisrtArg;
      is_valid(fd);
      unsigned* pos = (unsigned*) secondArg;
      is_valid(pos);
      seek(*fd,*pos);
      break;
    }
    case SYS_TELL: {
      int* fd = fisrtArg;
      is_valid(fd);
      f->eax = tell(*fd);
      break;
    }
    case SYS_CLOSE: {
      int* fd = fisrtArg;
      is_valid(fd);
      close(*fd);
      break;
    }
    default: {
      break;
    }
  }
}
/*
 * Terminates Pintos by calling shutdown_power_off(). This 
 * should be avoided because you lose some information about possible
 * deadlock situations, etc.
 */
void 
halt(void)
{
  shutdown_power_off();
}
/*
 * Terminates the current user program, returning status to the kernel.
 * If the process's parent waits for it, this is the status that will
 * be returned.
 */
void 
exit(int status)
{
  struct thread *t = thread_current();
  t->child_is_sharing->status = status;
  thread_exit();
}

/*
 * Runs the executable whose name is given in cmd_line, passing any given
 * argumaents, and returns the new process's program id.  Must return pid 
 * -1 which otherwise should not be a vild pid, if the program cannot 
 *  load or run for any reason.
 */
pid_t 
exec(const char* cmd_line)
{
  pid_t id = process_execute(cmd_line);
  return id;
}

/*
 * Waits for a chld process pid and retrieves the child's exit status.
 */
int 
wait(pid_t pid)
{
  int status = process_wait(pid);
  return status;
}

/*
 * Creates a new file called file initially initial_size bytes in size
 * returns true if successful, false otherwise.
 */
bool 
create(const char* file, unsigned initial_size) 
{
  lock_acquire(&file_lock);
  bool successfully_creates_file; 
  successfully_creates_file= filesys_create(file,initial_size);
  lock_release(&file_lock);
  return successfully_creates_file;
}

/*
 * Deletes the file called file.  Returns true if successful, false otherwise.
 * A file may be removed regardless of whether it is open or closed, and removing
 * an open file does not close it.
 */
bool remove(const char *file)
{
  lock_acquire(&file_lock);
  bool successfully_deleted_file;
  successfully_deleted_file = filesys_remove(file);
  lock_release(&file_lock);
  return successfully_deleted_file;
}

/*
 * Opens the file called file.  Returns a nonnegative integer handle called
 * a file descriptor or -1 if the file could not be opened.
 */
int 
open(const char* file)
{
  lock_acquire(&file_lock);
  struct thread *t = thread_current();
  int return_value;
  struct file* open_file = filesys_open(file);
  struct fd_elem* fm = (struct fd_elem*) malloc(sizeof(struct fd_elem));
  if(open_file == NULL)
  {
    return_value = -1;
  }
  else
  {
    fm->fd = ++t->next_fd;
    fm->file = open_file;
    list_push_back(&t->open_files,&fm->file_elem);
    return_value = fm->fd;
  }
  lock_release(&file_lock);
  return return_value;
}

int 
filesize(int fd) 
{
  lock_acquire(&file_lock);
  int return_value = -1;
  struct thread* t = thread_current();
  struct list_elem *e;
  for (e = list_begin (&t->open_files); e != list_end (&t->open_files);
    e = list_next (e))
    {
      struct fd_elem* fd_e = list_entry (e, struct fd_elem, file_elem);
      if(fd_e->fd == fd)
      {
        return_value = file_length(fd_e->file);
        break;
      }
      
    }
  lock_release(&file_lock);
  return return_value;
}

int 
sys_read(int fd, char* buf, unsigned size)
{
    // Acquire the file operation lock.
    lock_acquire(&file_lock);
    // Initialize return_value to 0.
    int return_value = 0;
    // Check if this is a console read.
    if(fd == 0){
      // Get as many characters from the console as specified in
      // The size argument.
      for(unsigned int i = 0; i < size; ++i){
        buf[i] = input_getc();
      }
        return_value = size;
    }
    // Otherwise, it is a file read. Search for the file in the thread's
    // file descriptor list.
    else{
      struct thread* t = thread_current();
      struct list_elem *e;
      for (e = list_begin (&t->open_files); e != list_end (&t->open_files);
        e = list_next (e))
        {
          struct fd_elem* fd_e = list_entry (e, struct fd_elem, file_elem);
          if(fd_e->fd == fd){
            // If found read the file.
            return_value = file_read(fd_e->file,buf,size);
            break;
          }
        }
    }
    // Release the file operation lock.
    lock_release(&file_lock);
    // Return the number of bytes read.
    return return_value;
}
int 
sys_write(int fd, char* buf, unsigned size)
{
      lock_acquire(&file_lock);
      int return_value = 0;
      if (fd == 1){
        putbuf(buf,size);
        return_value = size;
      }
      else{
        struct thread* t = thread_current();
        struct list_elem *e;
        for (e = list_begin (&t->open_files); e != list_end (&t->open_files);
          e = list_next (e))
          {
            struct fd_elem* fd_e = list_entry (e, struct fd_elem, file_elem);
            if(fd_e->fd == fd){
              return_value = file_write(fd_e->file,buf,size);
              break;
            }
          }
      }
      lock_release(&file_lock);
      return return_value;
}

/*
 * Changes the next byte to be read or written in open file fd to position,
 * expressed in bytes from the beginning of the file.
 */
void 
seek(int fd, unsigned position)
{
  lock_acquire(&file_lock);
  struct thread* t = thread_current();
  struct list_elem *e;
  for (e = list_begin (&t->open_files); e != list_end (&t->open_files);
    e = list_next (e))
    {
      struct fd_elem* fd_e = list_entry (e, struct fd_elem, file_elem);
      if(fd_e->fd == fd)
      {
        file_seek(fd_e->file,position);
        break;
      }
    }
    lock_release(&file_lock);
}

/*
 * Returns the position of the next byte to be read or written in open file
 * fd, expressed in bytes from the beginning of the file.
 */
unsigned 
tell(int fd) 
{
  struct thread* t = thread_current();
  struct list_elem *e;
  int return_value = 0;
  lock_acquire(&file_lock);
  for (e = list_begin (&t->open_files); e != list_end (&t->open_files);
      e = list_next (e))
  {
    struct fd_elem* fd_e = list_entry (e, struct fd_elem, file_elem);
    if(fd_e->fd == fd)
    {
      return_value = file_tell(fd_e->file);
      break;
    }
  }
  lock_release(&file_lock);
  return return_value;
}

/*
 * Closes the file descriptor fd. Exiting or terminating a process implicitly
 * closes all of its open file descriptors as if by calling this function for 
 * each one.
 */
void 
close(int fd)
{
  struct thread* t = thread_current();
  lock_acquire(&file_lock);
  if(fd != 0 && fd != 1)
  {
    struct list_elem *e;
    for (e = list_begin (&t->open_files); e != list_end (&t->open_files);
         e = list_next (e))
    {
      struct fd_elem* fd_e = list_entry (e, struct fd_elem, file_elem);
      if(fd_e->fd == fd)
      {
        list_remove(e);
        file_close(fd_e->file);
        free(fd_e);
        break;
      }
    }
  }
  lock_release(&file_lock);
}

void is_valid(void* addr){
  for(int i = 0; i < 4; ++i){
    if(addr+i == NULL || !is_user_vaddr(addr+i) || pagedir_get_page(thread_current()->pagedir,addr+i) == NULL){
      exit(-1);
    }
  }
}

void is_valid_buffer_size(char ** buffer, unsigned * size)
{
    for(unsigned int i = 0; i < *size; ++i){
      is_valid(*buffer+i);
    }
}

void is_valid_buffer(char ** buffer)
{
  int size = strlen(*buffer);
  for (int i = 0; i < size; ++i)
  {
    is_valid(*buffer+i);
  }
}
