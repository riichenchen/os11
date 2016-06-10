#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/malloc.h"
#include <hash.h>

/*! Partition that contains the file system. */
struct block *fs_device;

static void do_format(void);
/* Hash table for accessing the file from the fd. */
static struct hash *hash_table;
static int next_fd;

/*! Initializes the file system module.
    If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
    fs_device = block_get_role(BLOCK_FILESYS);
    if (fs_device == NULL)
        PANIC("No file system device found, can't initialize file system.");

    inode_init();
    free_map_init();

    next_fd = 2;
    hash_table = (struct hash *)malloc(sizeof(struct hash));
    /* Initialize the hash table for converting fd to file */
    if(!hash_init(hash_table, fd_hash, fd_less, NULL)) {
        PANIC("Unable to initialize the hash table");
    }

    if (format) 
        do_format();

    free_map_open();

}

/*! Shuts down the file system module, writing any unwritten data to disk. */
void filesys_done(void) {
    free_map_close();
}

/*! Creates a file named NAME with the given INITIAL_SIZE.  Returns true if
    successful, false otherwise.  Fails if a file named NAME already exists,
    or if internal memory allocation fails. */
bool filesys_create(const char *name, off_t initial_size) {
    block_sector_t inode_sector = 0;
    struct dir *dir = dir_open_root();
    bool success = (dir != NULL &&
                    free_map_allocate(1, &inode_sector) &&
                    inode_create(inode_sector, initial_size) &&
                    dir_add(dir, name, inode_sector));
    if (!success && inode_sector != 0) 
        free_map_release(inode_sector, 1);
    dir_close(dir);

    return success;
}

/*! Opens the file with the given NAME.  Returns the new file if successful
    or a null pointer otherwise.  Fails if no file named NAME exists,
    or if an internal memory allocation fails. */
struct file * filesys_open(const char *name) {
    struct dir *dir = dir_open_root();
    struct inode *inode = NULL;

    if (dir != NULL)
        dir_lookup(dir, name, &inode);
    dir_close(dir);

    return file_open(inode);
}

/*! Opens the file with the given name, assigns it a file descriptor, and 
    inserts the mapping into the hash table. Fails if either filesys_open or
    hashing fails. */
struct file * filesys_open_and_hash(const char *name) {
    struct file *file = filesys_open(name);
    if (!file) {
        return NULL;
    }
    file->fd = next_fd;
    next_fd++;
        
    struct hash_elem *success = hash_insert(hash_table, &file->hash_elem);
    ASSERT(success == NULL);     

    return file;
}

/*! Deletes the file named NAME.  Returns true if successful, false on failure.
    Fails if no file named NAME exists, or if an internal memory allocation
    fails. */
bool filesys_remove(const char *name) {
    struct dir *dir = dir_open_root();
    bool success = dir != NULL && dir_remove(dir, name);
    dir_close(dir);

    return success;
}

/*! Formats the file system. */
static void do_format(void) {
    printf("Formatting file system...");
    free_map_create();
    if (!dir_create(ROOT_DIR_SECTOR, 16))
        PANIC("root directory creation failed");
    free_map_close();
    printf("done.\n");
}

/*! Returns a file from the file descriptor via a lookup in the hash table. */
struct file *file_lookup_from_fd(int fd) {
    struct file f;
    struct hash_elem *e;
    f.fd = fd;
    e = hash_find(hash_table, &f.hash_elem);
    return e != NULL ? hash_entry (e, struct file, hash_elem) : NULL;
}

/*! Removes a file descriptor from the hash table, if it is there */
void filesys_unhash(int fd) {
    struct file f;
    struct hash_elem *e;
    f.fd = fd;
    e = hash_find(hash_table, &f.hash_elem);
    if (e) {
        hash_delete(hash_table, e);
    }
}