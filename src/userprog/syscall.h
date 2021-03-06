#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "threads/thread.h"
#include "userprog/process.h"

int read_arg32(void *ptr);

void syscall_init(void);
void sys_exit(int status);
int sys_write(int fd, void *buffer, unsigned size);
bool sys_create(const char *file, unsigned i_size);
bool sys_remove(const char *file);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
int sys_open(const char *file);
void sys_close(int fd);
int sys_wait(tid_t pid);
int sys_exec(const char *cmd_line);


#endif /* userprog/syscall.h */

