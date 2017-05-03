#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
void syscall_init (void);
void exit(int);

// Accepts an address, calls exit(-1) if the address is out of range
void validate(void* addr);


// Writes to a file represented by fd.
int s_write(int fd, char* buf, unsigned size);

// Creates a file with name 'file' and size 'size'.
int s_create(char* file, unsigned size);


// Closes file represented by fd.
void s_close(int fd);

// Moves to position 'position' in file 'fd'.
void s_seek(int fd, unsigned position);

// Returns the location of the cursor in 'fd'.
unsigned s_tell(int fd);



int s_remove(char* name);
#endif /* userprog/syscall.h */

