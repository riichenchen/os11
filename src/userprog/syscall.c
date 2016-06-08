#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"

#define BUFFER_CHUNK 256

static void syscall_handler(struct intr_frame *);
static int readbyte_user(const uint8_t *uaddr);


void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*
   Handler for system calls. Retreives the stack pointer from an interrupt
   frame, and gets the syscall number. The appropriate syscall is then 
   executed via a switch statement.
   @param f The interrupt frame
*/
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

/* ===================Functions to validate user pointers===================*/

/*
   Reads a 32-bit integer at ptr. Terminates if the given pointer is invalid
   @param ptr The address to dereference
   @return The deferenced integer
*/
int read_arg32(void *ptr) {
    if (readbyte_user((uint8_t *) ptr) == -1) {
        sys_exit(-1);
    }
    return *((uint32_t *) ptr);
}

/*
   Attempts to read a single byte at uaddr. Checks that the address is in 
   user space, then dereferences. The page fault handler returns -1 if the
   page is unmapped.
   @param uddr The address to dereference
   @return The deferenced value, or -1 if an error occurred
*/
static int readbyte_user(const uint8_t *uaddr) {
    if (!uaddr || !is_user_vaddr(uaddr)) {
        return -1;
    }
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a" (result) : "m" (*uaddr));
    return result;
}

/*
   Prints an exit message, sets the thread's exit status, then exits.
   @param status The status to exit with (0 success, error otherwise)
*/
void sys_exit(int status) {
    struct thread *curr = thread_current();
    curr->exit_status = status;
    printf("%s: exit(%d)\n", curr->name, status);
    thread_exit();
}

/*
   Writes a specified number of bytes from a buffer to a file. Checks that
   the buffer lies completely within user space, then writes. Returns the
   number of bytes written.
   @param fd The file descriptor of the file to write to
   @param buffer The buffer to copy from
   @param size The number of bytes to write
   @return The number of bytes written
*/
void sys_write(int fd, void *buffer, unsigned size) {
    /* fd == 1: Write to console */
    if (fd == 1) {
        if (readbyte_user((uint8_t *) buffer) == -1 ||
            readbyte_user((uint8_t *)(buffer + size - 1)) == -1) {
            sys_exit(-1);
        }

        /* Output buffers longer than 300 in chunks */
        while (size > BUFFER_CHUNK) {
            putbuf((char *) buffer, BUFFER_CHUNK);
            buffer += BUFFER_CHUNK;
            size -= BUFFER_CHUNK;
        }
        putbuf((char *) buffer, (size_t) size);
    }
    else {
        printf("write to non-console %d\n", fd);
        thread_exit();
    }

}

