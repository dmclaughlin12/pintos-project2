#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
void syscall_init (void);
void exit(int);

// Accepts an address, calls exit(-1) if the address is out of range
void validate(void* addr);

// Reads from a file represented by fd.
int sys_read(int fd, char* buf, unsigned size);

// Writes to a file represented by fd.
int sys_write(int fd, char* buf, unsigned size);

// Creates a file with name 'file' and size 'size'.
int sys_create(char* file, unsigned size);

// Opens the file with filename 'file'.
int sys_open(char* file);

// Closes file represented by fd.
void sys_close(int fd);

// Moves to position 'position' in file 'fd'.
void sys_seek(int fd, unsigned position);

// Returns the location of the cursor in 'fd'.
unsigned sys_tell(int fd);

// Returns the filesize of the file represented by fd.
int sys_filesize(int fd);


int sys_remove(char* name);
#endif /* userprog/syscall.h */

