#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/thread.h"

#define BUFFER_CHUNK 256

static void syscall_handler(struct intr_frame *);
static int readbyte_user(const uint8_t *uaddr);
static void validate_buffer(void *buf, unsigned size);

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
            f->eax = sys_write(read_arg32(stack_ptr + sizeof(int32_t)), 
                     (void *) read_arg32(stack_ptr + sizeof(int32_t) * 2),
                     read_arg32(stack_ptr + sizeof(int32_t) * 3));
            break;
        case SYS_EXEC:
            f->eax = sys_exec((char *)read_arg32(stack_ptr + sizeof(int32_t)));
            break;
        case SYS_WAIT:
            f->eax = sys_wait((tid_t)read_arg32(stack_ptr + sizeof(int32_t)));
            break;
        case SYS_CREATE:
            f->eax = sys_create((char *)read_arg32(stack_ptr + sizeof(int32_t)),
                                read_arg32(stack_ptr + sizeof(int32_t) * 2));
            break;
        case SYS_REMOVE:
            f->eax = sys_remove((char *)read_arg32(stack_ptr + sizeof(int32_t)));
            break;
        case SYS_FILESIZE:
            f->eax = sys_filesize(read_arg32(stack_ptr + sizeof(int32_t)));
            break;
        case SYS_READ:
            f->eax = sys_read(read_arg32(stack_ptr + sizeof(int32_t)), 
                     (void *) read_arg32(stack_ptr + sizeof(int32_t) * 2),
                     read_arg32(stack_ptr + sizeof(int32_t) * 3));
            break;
        case SYS_SEEK:
            sys_seek(read_arg32(stack_ptr + sizeof(int32_t)),
                     read_arg32(stack_ptr + sizeof(int32_t) * 2));
            break;
        case SYS_TELL:
            f->eax = sys_tell(read_arg32(stack_ptr + sizeof(int32_t)));
            break;
        case SYS_OPEN:
            f->eax = sys_open((char *)read_arg32(stack_ptr + sizeof(int32_t)));
            break;
        case SYS_CLOSE:
            sys_close(read_arg32(stack_ptr + sizeof(int32_t)));
            break;
        default:
            printf("Invalid system call: %d!\n", syscall_no);
            thread_exit();
    }

}

/* ===================Functions to validate user pointers================== */

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
   Checks that the entirety of a buffer is valid by checking the first and
   last position in the buffer. Exits if either is invalid.
   @param buf The address of the start of the buffer
   @param size The number of bytes to read
*/
static void validate_buffer(void *buf, unsigned size) {
    if (readbyte_user((uint8_t *) buf) == -1 ||
        readbyte_user((uint8_t *)(buf + size - 1)) == -1) {
        sys_exit(-1);
    }
}
/* ======================================================================== */

/* ==============================System Calls============================== */
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
    Waiting.
*/
int sys_wait(tid_t pid) {
    return process_wait(pid);
}

/*
    Execute cmd_line
*/
int sys_exec(const char *cmd_line) {
    printf("sys_exec cmd_line = %s\n", cmd_line);
    int status = process_execute(cmd_line);
    printf("sys_exec status = %d\n", status);
    if(status == TID_ERROR) {
        printf("sys_exec TID_ERROR\n");
        sys_exit(-1);
    }
    return status;
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
int sys_write(int fd, void *buffer, unsigned size) {
    int bytes_written = 0;

    validate_buffer(buffer, size);

    /* fd == 1: Write to console */
    if (fd == 1) {
        /* Output buffers longer than 300 in chunks */
        while (size > BUFFER_CHUNK) {
            putbuf((char *) buffer, BUFFER_CHUNK);
            buffer += BUFFER_CHUNK;
            size -= BUFFER_CHUNK;
            bytes_written += BUFFER_CHUNK;
        }
        putbuf((char *) buffer, (size_t) size);
        return bytes_written + size;
    } else {
        struct file *file = file_lookup_from_fd(fd);
        return file ? file_write(file, buffer, size) : -1;
    }

    return bytes_written;

}

/* 
   Creates a file with name file and initial size i_size, returning true if
   the creation succeeded and false otherwise. Exits upon encountering any
   invalid buffer pointers.
*/
bool sys_create(const char *file, unsigned i_size) {
    if (readbyte_user((uint8_t *) file) == -1) {
        sys_exit(-1);
    }
    return filesys_create(file, i_size);
}

/*
   Removes the file with name file. Returns true of the file was successfully
   removed and false other (regardless of failure reason)
   @param The filename to remove.
   @return If the removal was successful
*/
bool sys_remove(const char *file) {
    if (readbyte_user((uint8_t *) file) == -1) {
        sys_exit(-1);
    }
    return filesys_remove(file);
}

/*
   Returns the length (in bytes) of the file open as file descriptor fd
   @param fd The file descriptor for the relevant file
   @return The length, in bytes, of the open file
*/
int sys_filesize(int fd) {
    return file_length(file_lookup_from_fd(fd));
}

/*
   Reads size bytes from the file open as fd to buffer. Validates that the
   buffer is within valid memory regions, then reads and returns the actual
   number of bytes read (may be less than size if EOF is reached). Returns -1
   if the file descriptor is invalid, reads from keyboard if fd is 0.
   @param fd The file descriptor of the file to read from
   @param buffer Pointer to the buffer to store read data to
   @param size The number of bytes to read
   @return The actual number of bytes read.
*/
int sys_read(int fd, void *buffer, unsigned size) {
    validate_buffer(buffer, size);

    /* Read size bytes from keyboard if fd is 0 */
    if (fd == 0) {
        char *i;
        for (i = (char *)buffer; i < (char *)(buffer + size); i++) {
            *i = input_getc();
        }
        return size;
    }
    else {
        struct file *file = file_lookup_from_fd(fd);
        return file ? file_read(file, buffer, size) : -1;
    }
}

/* 
   Changes the position marker in the file open as fd to position.
   @param fd The file descriptor of the file to seek in
   @param position The position to seek to
*/
void sys_seek(int fd, unsigned position) {
    file_seek(file_lookup_from_fd(fd), position);
}

/*
   Returns the position of the next byte to read/write in the file open as fd.
   @param fd The file descriptor of the file we want the position of
   @return Location of the next byte to read/write, expressed as number of
   bytes from the beginning of the file.
*/
unsigned sys_tell(int fd) {
    return file_tell(file_lookup_from_fd(fd));
}

/*
   Opens the file with name file, assigning it a file descriptor and returning
   that file descriptor. Valid file descriptors are integers greater than 1.
   @param file The name of the file to open
   @return The file descriptor of the opened file, or -1 if the file could not
   be opened
*/
int sys_open(const char *file) {
    if (readbyte_user((uint8_t *) file) == -1) {
        sys_exit(-1);
    }
    struct file *f = filesys_open_and_hash(file);
    if (f == NULL) {
        return -1;
    }
    else {
        struct thread *curr = thread_current();
        /* Need to assign file descriptor to thread? */
        return f->fd;
    }
}

/*
   Closes fd. File may still be accessed through other file descriptors.
   @param fd The file descriptor to close
*/
void sys_close(int fd) {
    filesys_unhash(fd);
    file_close(file_lookup_from_fd(fd));
    /* Remove file from current thread list? */
}
