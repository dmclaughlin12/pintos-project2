#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
void syscall_init (void);
void exit(int);

// Accepts an address, calls exit(-1) if the address is out of range
void is_valid(void* addr);

/* 	Reads size bytes from the file open as fd into buffer. 
*	Returns the number of bytes actually read (0 at end of file), or -1 if the file could not be read */
int sys_read(int fd, char* buf, unsigned size);

/*	Writes size bytes from buffer to the open file fd. 
*	Returns the number of bytes actually written, which may be less than size if some bytes could not be written. */
int sys_write(int fd, char* buf, unsigned size);

/* Creates a new file called file initially initial_size bytes in size. Returns true if successful, false otherwise. */
int sys_create(char* file, unsigned size);

/* 	Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), 
*	or -1 if the file could not be opened. */
int sys_open(char* file);

/*	Close file descriptor fd. */
void sys_close(int fd);

/* 	Changes the next byte to be read or written in open file fd to position, 
*	expressed in bytes from the beginning of the file. (Thus, a position of 0 is the file's start.) */
void sys_seek(int fd, unsigned position);

/* 	Returns the position of the next byte to be read or written in open file fd, 
*	expressed in bytes from the beginning of the file.  */
unsigned sys_tell(int fd);

/*	Returns the size, in bytes, of the file open as fd */
int sys_filesize(int fd);

/* Deletes the file called file. Returns true if successful, false otherwise. */
int s_remove(char* name);
#endif /* userprog/syscall.h */

