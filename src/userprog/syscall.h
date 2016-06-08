#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
void sys_exit(int status);
int sys_write(int fd, void *buffer, unsigned size);
int read_arg32(void *ptr);

#endif /* userprog/syscall.h */

