#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"


struct lock sysfile_lock;

static void syscall_handler (struct intr_frame *);
int sys_add_file(struct file *f);
struct file* sys_get_file(int fd);
void get_stack_args(struct intr_frame *f, int * arg, int arg_count);
void sys_halt(void);
void sys_exit(int status);
pid_t sys_exec(const char *cmd_line);
int sys_wait(pid_t pid);
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
int * get_fd_arg(struct intr_frame *f);
char ** get_buffer_arg(struct intr_frame *f);
unsigned* get_size_arg(struct intr_frame *f);
void is_valid_buffer(char ** buffer, unsigned * size);


void
syscall_init (void) 
{
	lock_init(&sysfile_lock);
  	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{

	//create array with size of 3, the maximum amount of args
  int args[MAX_ARGS];
  int * sp =  (int*) f->esp;
  
  is_valid_pointer(sp);
  switch(*sp)
  {
  	case SYS_HALT:
  		sys_halt();
  		break;
  	case SYS_EXIT:
  		get_stack_args(f, args, 1);
  		sys_exit(args[0]);
  		break;
  	case SYS_OPEN:
  		get_stack_args(f, args, 1);
  		f->eax = sys_open((char *) args[0]);
  		break;
  	case SYS_EXEC:
  		get_stack_args(f, args, 1);
  		f->eax = sys_exec((char*) args[0]);
  		break;
  	case SYS_WAIT:
  		get_stack_args(f, args, 1);
		f->eax = sys_wait(args[0]);
  		break;
  	case SYS_CREATE:
  		get_stack_args(f, args, 2);
  		f->eax = sys_create((char*) args[0], (unsigned) args[1]);
  		break;
  	case SYS_REMOVE:
  		get_stack_args(f, args, 1);
  		f->eax = sys_remove((char*) args[0]);
  		break;
  	case SYS_FILESIZE:
  		get_stack_args(f, args, 1);
  		f->eax = sys_filesize(args[0]);
  		break;
  	case SYS_READ:
  		get_stack_args(f, &args[0], 3);
  		args[1] = user_to_kernel_ptr((const void *) args[1]);
  		f->eax = sys_read(args[0], (void *)args[1], (unsigned) args[2]);
  		break;
  	case SYS_WRITE:
  		int* fd = get_fd_arg(f);
		unsigned* size = get_size_arg(f);
		char** buffer = get_buffer_arg(f);
		is_valid_pointer(fd);
	    is_valid_pointer(buffer);
      	is_valid_pointer(*buffer);
      	is_valid_buffer(buffer, size);

      	f->eax = sys_write(*fd,*buffer,*size);
  		break;
  	case SYS_SEEK:
  		get_stack_args(f, args, 2);
  		sys_seek(args[0], (unsigned) args[1]);
  		break;
  	case SYS_TELL:
  		get_stack_args(f, args, 1);
  		f->eax = sys_tell(args[0]);
  		break;
  	case SYS_CLOSE:
  		get_stack_args(f, args, 1);
  		sys_close(args[0]);
  		break;

  }
}

	/* 	Terminates Pintos by calling shutdown_power_off()
	*	This should be seldom used because you lose info about deadlock situations
	*/
void
sys_halt(void)
{
	shutdown_power_off();
}

	/*	Terminates the current user program, returning the status to the kernel
	*	If the process's parent waits for it this is the status that will be returned
	*	Conventionally, a status of 0 indicates a success and a nonzero indicates errors
	*/
void
sys_exit(int status)
{
	struct thread *cur = thread_current();
	thread_exit();
}
	
/* 	Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid). 
*	Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. 
*	Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable. 
*	You must use appropriate synchronization to ensure this.
*/
pid_t
sys_exec(const char *cmd_line)
{
	return process_execute(cmd_line);
}


/*	Waits for a child process pid and retrieves the child's exit status. */
int
sys_wait(pid_t pid)
{
	process_wait(pid);
}

/* Creates a new file called file initially initial_size bytes in size. Returns true if successful, false otherwise. */
bool
sys_create(const char *file, unsigned initial_size)
{
	lock_acquire(&sysfile_lock);
	bool create_success = filesys_create(file, initial_size);
	lock_release(&sysfile_lock);
	return create_success;
}

/* Deletes the file called file. Returns true if successful, false otherwise. */
bool
sys_remove(const char *file)
{
	return filesys_remove(file);
}

/* 	Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), 
*	or -1 if the file could not be opened. */
int
sys_open(const char *file)
{
	struct file *sf = filesys_open(file);
	//Check if file is null/able to be opened
	if(sf == NULL)
		return -1;
	
	int fd = sys_add_file(file);
	return fd; 
}

/*	Returns the size, in bytes, of the file open as fd */
int
sys_filesize(int fd)
{
	struct file *cf = sys_get_file(fd);
	if(cf == NULL)
	{
		//returns -1 if file could not be found
		return -1;
	}
	//get file length and return size
	int size = file_length(cf);
	return size;
}

/* 	Reads size bytes from the file open as fd into buffer. 
*	Returns the number of bytes actually read (0 at end of file), or -1 if the file could not be read */
int
sys_read(int fd, void *buffer, unsigned size)
{
	lock_acquire(&sysfile_lock);
	//if fd is 0, read from keyboard
	if(fd == 0)
	{
		uint8_t* read_buffer = (uint8_t *) buffer;
		for(int i = 0; i < size; i++)
		{
			read_buffer[i] = input_getc();
		}

		return size;
	}
	//if not reading from keyboard, get the file
	struct file *rf = sys_get_file(fd);
	//Make sure a file was found
	if(rf == NULL)
		lock_release(&sysfile_lock);
		return -1;
	int file_size = file_read(rf, buffer, size);
	lock_release(&sysfile_lock);
	return file_size;
}

/*	Writes size bytes from buffer to the open file fd. 
*	Returns the number of bytes actually written, which may be less than size if some bytes could not be written. */
int
sys_write(int fd, const void *buffer, unsigned size)
{
	lock_acquire(&sysfile_lock);
	int written_bytes = 0;

	//if fd is 1, this is a console write
	if(fd == 1)
	{
		//since its a console write, use putbuf()
		putbuf(buffer, size);
		return size;
	}
        struct thread *cur = thread_current();
        struct list_elem *e;
        for (e = list_begin (&cur->files); e != list_end (&cur->files); e = list_next (e))
        {
            struct fd_elem* fd_e = list_entry (e, struct fd_elem, fd_e);
            if(fd_e->fd == fd){
              // Write to the file if found.
              written_bytes = file_write(fd_e->file,buf,size);
            }
        }
	lock_release(&sysfile_lock);
	return written_bytes;
}

/* 	Changes the next byte to be read or written in open file fd to position, 
*	expressed in bytes from the beginning of the file. (Thus, a position of 0 is the file's start.) */
void
sys_seek(int fd, unsigned position)
{
	struct file * f = sys_get_file(fd);
	//make sure file is found
	if(f==NULL)
	{
		return;
	}
	file_seek(f, position);
}

/* 	Returns the position of the next byte to be read or written in open file fd, 
*	expressed in bytes from the beginning of the file.  */
unsigned
sys_tell(int fd)
{
	struct file *f = sys_get_file(fd);
	if(f==NULL)
	{
		return -1;
	}
	off_t offset = file_tell(f);

	return offset;
}

/*	Close file descriptor fd. */
void
sys_close(int fd)
{
	struct thread *cur = thread_current();
	struct list_elem *next, *cf;
	struct fd_elem *fe;

	cf = list_begin(&cur->file_list);

	while(cf != list_end(&cur->file_list))
	{
		next = list_next(cf);
		fe = list_entry(cf, struct fd_elem, elem);
		if(fd == fe->fd || fd == -1)
		{
			file_close(fe->file);
			list_remove(&fe->elem);
			free(fe);
			if(fd != -1)
				return;
		}
		cf = next;
	}
}

/*	Creates fd_elem, allocates memory for struct and builds it. Pushes it onto the end of the current threads file list
*	Returns file descriptor (fd) value */
int sys_add_file(struct file *f)
{
	//allocate memory for struct
	struct fd_elem *af = malloc(sizeof(struct fd_elem));
	//assign properties to af from file passed in and current thread
	af->file = f;
	af->fd = thread_current()->fd;
	//push to back of current threads file list
	list_push_back(&thread_current()->file_list, &af->elem);

	return af->fd;
}

/*	Traverses current threads file list comparing fd value to get file */
struct file*
sys_get_file(int fd)
{
	struct thread *cur = thread_current();
	struct list_elem *le;
	
	//Find using list element from current threads file_list, through comparison of file descriptor value (fd)
	for(le = list_begin(&cur->file_list); le != list_end(&cur->file_list); le = list_next(le))
	{
		struct fd_elem *checker_file = list_entry(le, struct fd_elem, elem);
		if(fd == checker_file->fd)
			return checker_file->file;
	}

	//if no file was found return null
	return NULL;
}

/*	Per the pintos manual, to avoid duplicate code pull arguments off the stack
* 	The 80x86 convention for function return values is to place them in the EAX register.
*	Each system call argument, whether an integer or a pointer, takes up 4 bytes on the stack.
*	Arg 0 - fd
*	Arg 1 - buffer
*	Arg 2 - size
*	Gets the amount of args needed. Multiplies the byte_count by the current position of i, grab from stack and put into array.
*/
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

void
is_valid_pointer(void *p)
{
	//check if is a virtual address return with status
	for(int i = 0; i < 4; ++i)
	{
    	if(p+i == NULL || !is_user_vaddr(p+i) || pagedir_get_page(thread_current()->pagedir,p+i) == NULL)
    	{
      		exit(-1);
    	}
	}

}

void is_valid_buffer(char ** buffer, unsigned * size)
{
	for(unsigned int i = 0; i < *size; ++i)
	{
        is_valid_pointer(*buffer + i);
    }
}

void exit(int status)
{
	struct thread * cur = thread_current();
	//do something to store status
	thread_exit();
}



