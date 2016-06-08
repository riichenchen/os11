#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

int read_arg32(void *ptr);

void syscall_init(void);
void sys_exit(int status);
void sys_write(int fd, void *buffer, unsigned size);
bool sys_create(const char *file, unsigned i_size);
bool sys_remove(const char *file);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
int sys_open(const char *file);
void sys_close(int fd);

#endif /* userprog/syscall.h */

