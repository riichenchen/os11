#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"

static void syscall_handler(struct intr_frame *);
static int readbyte_user(const uint8_t *uaddr);


void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f UNUSED) {
    void *stack_ptr = f->esp;
    int syscall_no = read_arg32(stack_ptr);

    switch (syscall_no) {
        case SYS_HALT:
            shutdown_power_off();
            break;
        case SYS_EXIT:
            sys_exit(read_arg32(stack_ptr + sizeof(int32_t)));
            break;
        case SYS_WRITE:
            sys_write(read_arg32(stack_ptr + sizeof(int32_t)), 
                      (void *) read_arg32(stack_ptr + sizeof(int32_t) * 2),
                      read_arg32(stack_ptr + sizeof(int32_t) * 3));
            break;
        case SYS_EXEC:
        case SYS_WAIT:
        case SYS_CREATE:
        case SYS_REMOVE:
        case SYS_OPEN:
        case SYS_FILESIZE:
        case SYS_READ:
        case SYS_SEEK:
        case SYS_TELL:
        case SYS_CLOSE:
        default:
            printf("system call: %d!\n", syscall_no);
            thread_exit();
    }

}

void sys_exit(int status) {
    struct thread *curr = thread_current();
    curr->exit_status = status;
    printf("%s: exit(%d)\n", curr->name, status);
    thread_exit();
}

void sys_write(int fd, void *buffer, unsigned size) {
    if (fd == 1) {
        if (readbyte_user((uint8_t *) buffer) == -1 ||
            readbyte_user((uint8_t *)(buffer + size - 1)) == -1) {
            sys_exit(-1);
        }

        /* Output buffers longer than 300 in chunks */
        while (size > 300) {
            putbuf((char *) buffer, 300);
            buffer += 300;
            size -= 300;
        }
        putbuf((char *) buffer, (size_t) size);
    }
    else {
        printf("write to non-console %d\n", fd);
        thread_exit();
    }

}

int read_arg32(void *ptr) {
    if (readbyte_user((uint8_t *) ptr) == -1) {
        sys_exit(-1);
    }
    return *((uint32_t *) ptr);
}

static int readbyte_user(const uint8_t *uaddr) {
    if (!uaddr || !is_user_vaddr(uaddr)) {
        return -1;
    }
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a" (result) : "m" (*uaddr));
    return result;
}