#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/*! Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define NUM_DIRECT 108
#define NUM_INDIRECT 16
#define NUM_DOUBLE_INDIRECT 1
#define NUM_SECTORS_IN_BLOCK BLOCK_SECTOR_SIZE / 4;
#define NUM_SECTORS_INDIRECT NUM_INDIRECT * NUM_SECTORS_IN_BLOCK;
#define NUM_SECTORS_DOUBLE_INDIRECT NUM_DOUBLE_INDIRECT * NUM_SECTORS_IN_BLOCK * NUM_SECTORS_IN_BLOCK;

int min(int a, int b);

/*! On-disk inode.
    Must be exactly BLOCK_SECTOR_SIZE bytes long. */
// struct inode_disk {
//     block_sector_t start;               /*!< First data sector. */
//     off_t length;                       /*!< File size in bytes. */
//     unsigned magic;                     /*!< Magic number. */
//     uint32_t unused[125];               /*!< Not used. */
// };

struct inode_disk {
    block_sector_t start;               /* First data sector */
    off_t length;                       /* File size in bytes */
    unsigned magic;                     /* Magic number */
    block_sector_t direct[NUM_DIRECT];
    block_sector_t indirect[NUM_INDIRECT];
    block_sector_t double_indirect[NUM_DOUBLE_INDIRECT];
};

/* inode_single_indirect and inode_double_indirect are literally the
same thing. I just define two different structs to keep myself sane. */
struct sng_indir {
    block_sector_t direct[NUM_SECTORS_IN_BLOCK];
};

struct dbl_indir {
    block_sector_t indirect[NUM_SECTORS_IN_BLOCK];
};

/*! Returns the number of sectors to allocate for an inode SIZE
    bytes long. */
static inline size_t bytes_to_sectors(off_t size) {
    return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE);
}

/*! In-memory inode. */
struct inode {
    struct list_elem elem;              /*!< Element in inode list. */
    block_sector_t sector;              /*!< Sector number of disk location. */
    int open_cnt;                       /*!< Number of openers. */
    bool removed;                       /*!< True if deleted, false otherwise. */
    int deny_write_cnt;                 /*!< 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /*!< Inode content. */
};



/*! Returns the block device sector that contains byte offset POS
    within INODE.
    Returns -1 if INODE does not contain data for a byte at offset
    POS. */
static block_sector_t byte_to_sector(const struct inode *inode, off_t pos) {
    ASSERT(inode != NULL);
    if (pos < inode->data.length)
        return inode->data.start + pos / BLOCK_SECTOR_SIZE;
    else
        return -1;
}

/*! List of open inodes, so that opening a single inode twice
    returns the same `struct inode'. */
static struct list open_inodes;

/*! Initializes the inode module. */
void inode_init(void) {
    list_init(&open_inodes);
}

/*! Initializes an inode with LENGTH bytes of data and
    writes the new inode to sector SECTOR on the file system
    device.
    Returns true if successful.
    Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
    struct inode_disk *disk_inode = NULL;
    bool success = false;

    ASSERT(length >= 0);

    /* If this assertion fails, the inode structure is not exactly
       one sector in size, and you should fix that. */
    ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

    disk_inode = calloc(1, sizeof *disk_inode);
    if (disk_inode == NULL) {
        return success;
    }

    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    // if (free_map_allocate(sectors, &disk_inode->start)) {
    //     block_write(fs_device, sector, disk_inode);
    //     if (sectors > 0) {
    //         static char zeros[BLOCK_SECTOR_SIZE];
    //         size_t i;
          
    //         for (i = 0; i < sectors; i++) 
    //             block_write(fs_device, disk_inode->start + i, zeros);
    //     }
    //     success = true; 
    // }

    int i, num_direct = 0, num_indirect = 0, num_double_indirect = 0;
    static char zeros[BLOCK_SECTOR_SIZE];
    num_direct = (sectors <= NUM_DIRECT) ? sectors : NUM_DIRECT;
    sectors -= NUM_DIRECT;
    
    for(i = 0; i < num_direct; i++) {
        if(!free_map_allocate(1, &disk_inode->direct[i])) {
            free(disk_inode);
            return success;
        }
        block_write(fs_device, disk_inode->direct[i], zeros);
    }

    /* Singly indirect blocks */
    /* I hope this isn't too confusing. If only there were math functions... */
    if(sectors > 0) {
        num_indirect = sectors / NUM_SECTORS_IN_BLOCK + (sectors % NUM_SECTORS_IN_BLOCK > 0);

        /* Allocate the indirect blocks */
        for(i = 0; i < num_indirect; i++) {
            if(!free_map_allocate(1, &disk_inode->indirect[i])) {
                free(disk_inode);
                return success;
            }
        }

        /* Allocate the inode_single_indirect blocks */
        for(i = 0; i < num_indirect - 1; i++) {
            for(j = 0; j < NUM_SECTORS_IN_BLOCK; j++) {
                if(!free_map_allocate(1, &((struct sng_indir) disk_inode->indirect[i])[j])) {
                    free(disk_inode);
                    return success;
                }
                block_write(fs_device, &((struct sng_indir) disk_inode->indirect[i])[j], zeros);
            }
        }

        /* Do the really awkward single indirect block which may not have all of the
        direct blocks under allocated */
        for(j = 0; j < (sectors - 1) % NUM_SECTORS_IN_BLOCK + 1; j++) {
            if(!free_map_allocate(1, &((struct sng_indir) disk_inode->indirect[num_indirect - 1])[j])) {
                free(disk_inode);
                return success;
            }
            block_write(fs_device, &((struct sng_indir) disk_inode->indirect[num_indirect - 1])[j], zeros);
        }
    }
    sectors -= NUM_SECTORS_INDIRECT;

    /* Double indirects */
    /* If I want this to handle things greater than 8MB, then I'd add more
    to calculate the double indirects. But for now, who cares. */
    if(sectors > 0) {
        num_double_indirect = 1;

        /* Allocate the double indirect block */
        if(!free_map_allocate(1, &disk_inode->double_indirect[0])) {
            free(disk_inode);
            return success;
        }

        /* Iterate throught he singly indirect inodes and allocate them */
        for(i = 0; i < NUM_SECTORS_IN_BLOCK && sectors > 0; i++) {
            for(j = 0; j < NUM_SECTORS_IN_BLOCK && sectors > 0; j++) {
                struct dbl_indir *dbl = (struct dbl_indir *)(&disk_inode->double_indirect[0]);
                if(!free_map_allocate(1, ((struct inode_double_indirect) &disk_inode->double_indirect[0])[i])) {
                    free(disk_inode);
                    return success;
                }
                block_write(fs_device, ((struct inode_double_indirect) &disk_inode->double_indirect[0])[j], zeros);
                sectors--;
            }
        }
    }

    // if(free_map_allocate(num_direct + num_indirect + num_double_indirect), &disk_inode->start) {

    // }
    
    /* Allocate 1 block at a time so we can store the block_sector address
    in a nice array as we have set it up */
    if (free_map_allocate(num_direct, &disk_inode->start)) {
        block_write(fs_device, sector, disk_inode);
        if (num_direct > 0) { /* If we just allocated something, zero it out */
            static char zeros[BLOCK_SECTOR_SIZE];
            size_t i;
            for (i = 0; i < sectors; i++) 
                block_write(fs_device, disk_inode->start + i, zeros);
        }

        if(free_map_allocate(num_indirect, ))


        success = true; 
    }

    free(disk_inode);
    return success;
}

/*! Reads an inode from SECTOR
    and returns a `struct inode' that contains it.
    Returns a null pointer if memory allocation fails. */
struct inode * inode_open(block_sector_t sector) {
    struct list_elem *e;
    struct inode *inode;

    /* Check whether this inode is already open. */
    for (e = list_begin(&open_inodes); e != list_end(&open_inodes);
         e = list_next(e)) {
        inode = list_entry(e, struct inode, elem);
        if (inode->sector == sector) {
            inode_reopen(inode);
            return inode; 
        }
    }

    /* Allocate memory. */
    inode = malloc(sizeof *inode);
    if (inode == NULL)
        return NULL;

    /* Initialize. */
    list_push_front(&open_inodes, &inode->elem);
    inode->sector = sector;
    inode->open_cnt = 1;
    inode->deny_write_cnt = 0;
    inode->removed = false;
    block_read(fs_device, inode->sector, &inode->data);
    return inode;
}

/*! Reopens and returns INODE. */
struct inode * inode_reopen(struct inode *inode) {
    if (inode != NULL)
        inode->open_cnt++;
    return inode;
}

/*! Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode *inode) {
    return inode->sector;
}

/*! Closes INODE and writes it to disk.
    If this was the last reference to INODE, frees its memory.
    If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode *inode) {
    /* Ignore null pointer. */
    if (inode == NULL)
        return;

    /* Release resources if this was the last opener. */
    if (--inode->open_cnt == 0) {
        /* Remove from inode list and release lock. */
        list_remove(&inode->elem);
 
        /* Deallocate blocks if removed. */
        if (inode->removed) {
            free_map_release(inode->sector, 1);
            free_map_release(inode->data.start,
                             bytes_to_sectors(inode->data.length)); 
        }

        free(inode); 
    }
}

/*! Marks INODE to be deleted when it is closed by the last caller who
    has it open. */
void inode_remove(struct inode *inode) {
    ASSERT(inode != NULL);
    inode->removed = true;
}

/*! Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset) {
    uint8_t *buffer = buffer_;
    off_t bytes_read = 0;
    uint8_t *bounce = NULL;

    while (size > 0) {
        /* Disk sector to read, starting byte offset within sector. */
        block_sector_t sector_idx = byte_to_sector (inode, offset);
        int sector_ofs = offset % BLOCK_SECTOR_SIZE;

        /* Bytes left in inode, bytes left in sector, lesser of the two. */
        off_t inode_left = inode_length(inode) - offset;
        int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
        int min_left = inode_left < sector_left ? inode_left : sector_left;

        /* Number of bytes to actually copy out of this sector. */
        int chunk_size = size < min_left ? size : min_left;
        if (chunk_size <= 0)
            break;

        if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
            /* Read full sector directly into caller's buffer. */
            block_read (fs_device, sector_idx, buffer + bytes_read);
        }
        else {
            /* Read sector into bounce buffer, then partially copy
               into caller's buffer. */
            if (bounce == NULL) {
                bounce = malloc(BLOCK_SECTOR_SIZE);
                if (bounce == NULL)
                    break;
            }
            block_read(fs_device, sector_idx, bounce);
            memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_read += chunk_size;
    }
    free(bounce);

    return bytes_read;
}

/*! Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
    Returns the number of bytes actually written, which may be
    less than SIZE if end of file is reached or an error occurs.
    (Normally a write at end of file would extend the inode, but
    growth is not yet implemented.) */
off_t inode_write_at(struct inode *inode, const void *buffer_, off_t size, off_t offset) {
    const uint8_t *buffer = buffer_;
    off_t bytes_written = 0;
    uint8_t *bounce = NULL;

    if (inode->deny_write_cnt)
        return 0;

    while (size > 0) {
        /* Sector to write, starting byte offset within sector. */
        block_sector_t sector_idx = byte_to_sector(inode, offset);
        int sector_ofs = offset % BLOCK_SECTOR_SIZE;

        /* Bytes left in inode, bytes left in sector, lesser of the two. */
        off_t inode_left = inode_length(inode) - offset;
        int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
        int min_left = inode_left < sector_left ? inode_left : sector_left;

        /* Number of bytes to actually write into this sector. */
        int chunk_size = size < min_left ? size : min_left;
        if (chunk_size <= 0)
            break;

        if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
            /* Write full sector directly to disk. */
            block_write(fs_device, sector_idx, buffer + bytes_written);
        }
        else {
            /* We need a bounce buffer. */
            if (bounce == NULL) {
                bounce = malloc(BLOCK_SECTOR_SIZE);
                if (bounce == NULL)
                    break;
            }

            /* If the sector contains data before or after the chunk
               we're writing, then we need to read in the sector
               first.  Otherwise we start with a sector of all zeros. */

            if (sector_ofs > 0 || chunk_size < sector_left) 
                block_read(fs_device, sector_idx, bounce);
            else
                memset (bounce, 0, BLOCK_SECTOR_SIZE);

            memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
            block_write(fs_device, sector_idx, bounce);
        }

        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_written += chunk_size;
    }
    free(bounce);

    return bytes_written;
}

/*! Disables writes to INODE.
    May be called at most once per inode opener. */
void inode_deny_write (struct inode *inode) {
    inode->deny_write_cnt++;
    ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/*! Re-enables writes to INODE.
    Must be called once by each inode opener who has called
    inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write (struct inode *inode) {
    ASSERT(inode->deny_write_cnt > 0);
    ASSERT(inode->deny_write_cnt <= inode->open_cnt);
    inode->deny_write_cnt--;
}

/*! Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode *inode) {
    return inode->data.length;
}

int min(int a, int b) {
    if(a < b)
        return a;
    return b;
}