#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"


/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_BLOCK_SIZE 4
#define INDIRECT_BLOCK_SIZE 10
#define DOUBLE_INDIRECT_BLOCK_SIZE 1

#define PTR_NUMBER_PER_SECTOR 128

// /* On-disk inode.
//    Must be exactly DISK_SECTOR_SIZE bytes long. */
// struct inode_disk
//   {
//     // disk_sector_t start;                /* First data sector. */
//     off_t length;                       /* File size in bytes. */
//     unsigned magic;                     /* Magic number. */
//     // uint32_t unused[125];               /* Not used. */
//     uint32_t unused[110];               /* Not used. */

//     //
//     disk_sector_t direct_index[DIRECT_BLOCK_SIZE];
//     disk_sector_t *indirect_index[INDIRECT_BLOCK_SIZE];
//     disk_sector_t **double_indirect_index;
//     size_t sectors; 
//   };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{ 
  return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

// /* In-memory inode. */
// struct inode 
//   {
//     struct list_elem elem;              /* Element in inode list. */
//     disk_sector_t sector;               /* Sector number of disk location. */
//     int open_cnt;                       /* Number of openers. */
//     bool removed;                       /* True if deleted, false otherwise. */
//     int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
//     struct inode_disk data;             /* Inode content. */

//     //
//     bool isdir;
//     disk_sector_t parent;
  
//   };

/* Returns the disk sector that contains byte offset POS within
   INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  int row, col;
  ASSERT (inode != NULL);
  if (pos >= 0 && pos < inode->data.length)
  {
    if(pos < DIRECT_BLOCK_SIZE * DISK_SECTOR_SIZE)
    {
      return inode->data.direct_index[pos/DISK_SECTOR_SIZE];
    }
    else if(pos < (DIRECT_BLOCK_SIZE * DISK_SECTOR_SIZE) + (INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR * DISK_SECTOR_SIZE))
    {
      pos -= DIRECT_BLOCK_SIZE * DISK_SECTOR_SIZE;
      row = (pos/DISK_SECTOR_SIZE) / PTR_NUMBER_PER_SECTOR;
      col = (pos/DISK_SECTOR_SIZE) % PTR_NUMBER_PER_SECTOR;
      return inode->data.indirect_index[row][col];
    }
    else
    {
      pos -= (DIRECT_BLOCK_SIZE * DISK_SECTOR_SIZE) + (INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR * DISK_SECTOR_SIZE);
      row = (pos/DISK_SECTOR_SIZE) / PTR_NUMBER_PER_SECTOR;
      col = (pos/DISK_SECTOR_SIZE) % PTR_NUMBER_PER_SECTOR;
      return inode->data.double_indirect_index[row][col];
    }
  }
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   disk.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length)
{
  // printf("____DEBUG____length %d \n", length);
  struct inode_disk *disk_inode = NULL;
  bool success = false;
  int i = 0;
  int row, col;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->sectors = sectors;

      // printf("___DEBUG____ secotr %d, sectors %d \n",  sector, disk_inode->sectors);

      disk_sector_t direct_sectors = (sectors > DIRECT_BLOCK_SIZE) ? DIRECT_BLOCK_SIZE : sectors;
      disk_sector_t indirect_sectors = 0;
      disk_sector_t double_indirect_sectors = 0;

      if (sectors > DIRECT_BLOCK_SIZE)      
        indirect_sectors = (sectors > DIRECT_BLOCK_SIZE + INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR) ? INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR : sectors - DIRECT_BLOCK_SIZE;
      
      if (sectors > DIRECT_BLOCK_SIZE + INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR)
        double_indirect_sectors = sectors - DIRECT_BLOCK_SIZE - INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR;

      /////////////////////////////////////////////////////////
      //struct cache_entry *cache_entry = cache_entry_find(sector);
      //hex_dump(cache_entry, cache_entry, 512, 0);
      /////////////////////////////////////////////////////////
      if (sectors > 0)
      {
        for(i=0; i<direct_sectors; i++)
        {
          if(free_map_allocate (1, &disk_inode->direct_index[i]))
          {
            // printf("sector number %d \n", disk_inode->direct_index[i]);
            static char zeros[DISK_SECTOR_SIZE];
            cache_write_from_buffer(disk_inode->direct_index[i], zeros);
          }
          else
            return success; // fail 
        }
      }
      if (sectors > DIRECT_BLOCK_SIZE)
      {
        for(i=0; i<INDIRECT_BLOCK_SIZE; i++)
          disk_inode->indirect_index[i] = calloc(1, PTR_NUMBER_PER_SECTOR * sizeof(disk_sector_t));

        for(i=0; i<indirect_sectors; i++)
        {
          row = i/PTR_NUMBER_PER_SECTOR;
          col = i%PTR_NUMBER_PER_SECTOR;
          if(free_map_allocate (1, &disk_inode->indirect_index[row][col]))
          {
            static char zeros[DISK_SECTOR_SIZE];
            cache_write_from_buffer(disk_inode->indirect_index[row][col], zeros);
          }
          else
            return success; // fail 
        }
      }
      if (sectors > DIRECT_BLOCK_SIZE + PTR_NUMBER_PER_SECTOR)
      {
        // double_indirect_index initialize (2 dim matrix)
        disk_inode->double_indirect_index = (disk_sector_t **) calloc(1, PTR_NUMBER_PER_SECTOR * sizeof(disk_sector_t *));
        for(i=0; i<PTR_NUMBER_PER_SECTOR; i++)
          disk_inode->double_indirect_index[i] = (disk_sector_t *) calloc(1, PTR_NUMBER_PER_SECTOR * sizeof(disk_sector_t));

        for(i=0; i<double_indirect_sectors; i++)
        {
          row = i/PTR_NUMBER_PER_SECTOR;
          col = i%PTR_NUMBER_PER_SECTOR;
          if(free_map_allocate (1, &disk_inode->double_indirect_index[row][col]))
          {
            static char zeros[DISK_SECTOR_SIZE];
            cache_write_from_buffer(disk_inode->double_indirect_index[row][col], zeros);
          }
          else {
            return success; // fail 
          }
        }
      }
      success = true;
      cache_write_from_buffer(sector, disk_inode);
      free (disk_inode);



      // if (free_map_allocate (sectors, &disk_inode->start))
      //   {
      //     // disk_write (filesys_disk, sector, disk_inode);
      //     cache_write_from_buffer(sector, disk_inode);
      //     if (sectors > 0) 
      //       {
      //         static char zeros[DISK_SECTOR_SIZE];
      //         size_t i;
              
      //         for (i = 0; i < sectors; i++) 
      //           // disk_write (filesys_disk, disk_inode->start + i, zeros); 
      //           cache_write_from_buffer(disk_inode->start + i, zeros);
      //       }
      //     success = true; 
      //   } 
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) 
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          // printf("____DEBUG______after inode reopen, inode is %08x sector is %d\n", inode, sector);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL) {
    // printf("____DEBUG______inode is NULL, malloc failed");
    return NULL;
  }
  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  // printf("____DEBUG____ before cache read, sector is %d \n", sector);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  inode->isdir = 0;
  // printf("here?!\n");

  // disk_read (filesys_disk, inode->sector, &inode->data);
  cache_read_to_buffer(inode->sector, &inode->data);
  // printf("++++DEBUG+++++\n");
  // hex_dump(&inode->data, &inode->data, 4, 0);
  // printf("direct data %d\n", inode->data.direct_index[0]);
  // printf("____DEBUG______after cache read to buffer inode is %08x, sector is %d\n", inode, inode->sector);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

struct inode *
inode_get(disk_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          return inode; 
        }
    }

  return NULL;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  int i = 0;
  int row, col;
  size_t sectors = inode->data.sectors;
  disk_sector_t direct_sectors = (sectors > DIRECT_BLOCK_SIZE) ? DIRECT_BLOCK_SIZE : sectors;
  disk_sector_t indirect_sectors = 0;
  disk_sector_t double_indirect_sectors = 0;
  struct cache_entry *temp_cache_entry;

  if (sectors > DIRECT_BLOCK_SIZE)      
    indirect_sectors = (sectors > DIRECT_BLOCK_SIZE + INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR) ? INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR : sectors - DIRECT_BLOCK_SIZE;
  if (sectors > DIRECT_BLOCK_SIZE + INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR)
    double_indirect_sectors = sectors - DIRECT_BLOCK_SIZE - INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          for(i=0; i<direct_sectors; i++)
            free_map_release(inode->data.direct_index[i], 1);

          if( sectors > DIRECT_BLOCK_SIZE)
          {
            for(i=0; i<indirect_sectors; i++)
            {
              row = i / PTR_NUMBER_PER_SECTOR;
              col = i % PTR_NUMBER_PER_SECTOR;
              free_map_release(inode->data.indirect_index[row][col], 1);
            }
            for(i=0; i<INDIRECT_BLOCK_SIZE; i++)
              free(inode->data.indirect_index[i]);
          }
          
          if( sectors > DIRECT_BLOCK_SIZE + PTR_NUMBER_PER_SECTOR)
          {
            for(i=0; i<double_indirect_sectors; i++)
            {
              row = i / PTR_NUMBER_PER_SECTOR;
              col = i % PTR_NUMBER_PER_SECTOR;
              free_map_release(inode->data.double_indirect_index[row][col], 1);
            }
            for(i=0; i<PTR_NUMBER_PER_SECTOR; i++)
              free(inode->data.double_indirect_index[i]);
            free(inode->data.double_indirect_index);
          }
          // free_map_release (inode->data.start, bytes_to_sectors (inode->data.length)); 
          free (inode);
        }
      else
      {
        // remove 하지 않는데 close하는 경우
        cache_write_from_buffer(inode->sector, &inode->data);
      } 
    }
  all_cache_entry_back_to_disk();
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  // printf("____DEBUG_____ start inode_read_at\n");
  // printf("____DEBUG____initial size : %d, offset : %d, inode_length : %d\n", size, offset, inode->data.length);
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  if (offset >= inode->data.length)
  {
    return bytes_read;
  }


  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset); // 그 inode에서 offset이 있는 sector의 인덱스
      int sector_ofs = offset % DISK_SECTOR_SIZE; // 해당 섹터에서 offset

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;

      // printf("===DEBUG=== sector_idx : %d, sector_ofs : %d, inode_left : %d, sector_left : %d, min_left : %d, chunk_size : %d\n", sector_idx, sector_ofs, inode_left, sector_left, min_left, chunk_size);

      if (chunk_size <= 0)
        break;

      // 여기를 cache에서 읽어오는 것으로 수정
      if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) 
        {
          /* Read full sector directly into caller's buffer. */
          // disk_read (filesys_disk, sector_idx, buffer + bytes_read); 
          // printf("___DEBUG_____ cache_read_buffer start in sector_ofs %d chunk_size %d \n", sector_ofs, chunk_size);
          cache_read_to_buffer(sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (DISK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          // disk_read (filesys_disk, sector_idx, bounce);
          // memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
          // printf("___DEBUG_____ cache_read_buffer start in sector_ofs %d chunk_size %d  using bounce \n", sector_ofs, chunk_size);
          cache_read_to_buffer(sector_idx, bounce);
          memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

      // struct cache_entry *get_file = cache_get_file(sector_idx);
      // memcpy(buffer+bytes_read, get_file->data + sector_ofs, chunk_size);
      // disk_read(filesys_disk, sector_idx, buffer+bytes_read);
      /* if (size < DISK_SECTOR_SIZE) {
        memset(buffer+bytes_read+size, 0, DISK_SECTOR_SIZE-size);
      } */
      // printf("size : %d, offset : %d, bytes_read : %d\n", size, offset, bytes_read);
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;
  int i, row, col;

  if (inode->deny_write_cnt)
    return 0;

  size_t add_sectors = bytes_to_sectors(offset + size) > inode->data.sectors ? bytes_to_sectors(offset + size) - inode->data.sectors : 0;

  size_t add_direct_sectors = 0;
  size_t add_indirect_sectors = 0;
  size_t add_double_indirect_sectors = 0;

  // printf("offset %d, size %d\n", offset, size);
  // printf("full sector %d, curr sector %d, add_sectors %d, inode length %d\n", bytes_to_sectors(offset + size), inode->data.sectors, add_sectors, inode->data.length);

  if(add_sectors > 0)
  {
    if(inode->data.sectors <= DIRECT_BLOCK_SIZE)
    {
      // start direct, end direct
      add_direct_sectors = DIRECT_BLOCK_SIZE - inode->data.sectors < add_sectors ? DIRECT_BLOCK_SIZE - inode->data.sectors : add_sectors;
      for(i=0; i<add_direct_sectors; i++)
      {
        if(free_map_allocate (1, &inode->data.direct_index[inode->data.sectors + i]))
        {
          static char zeros[DISK_SECTOR_SIZE];
          cache_write_from_buffer(inode->data.direct_index[inode->data.sectors + i], zeros);
        }
        else
          return 0; // fail
      }
      if(add_sectors > DIRECT_BLOCK_SIZE - inode->data.sectors)
      {
        // start direct, end indirect
        for(i=0;i<INDIRECT_BLOCK_SIZE;i++)
          inode->data.indirect_index[i] = (disk_sector_t *) calloc(1, PTR_NUMBER_PER_SECTOR * sizeof(disk_sector_t));

        add_indirect_sectors = INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR < add_sectors - add_direct_sectors ? INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR : add_sectors - add_direct_sectors;
        for(i=0; i<add_indirect_sectors; i++)
        {
          row = i/PTR_NUMBER_PER_SECTOR;
          col = i%PTR_NUMBER_PER_SECTOR;
          if(free_map_allocate (1, &inode->data.indirect_index[row][col]))
          {
            static char zeros[DISK_SECTOR_SIZE];
            cache_write_from_buffer(inode->data.indirect_index[row][col], zeros);
          }
          else
            return 0; // fail
        }
        if(add_sectors > DIRECT_BLOCK_SIZE + INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR - inode->data.sectors)
        {
          // start direct, end double
          inode->data.double_indirect_index = (disk_sector_t **) calloc(1, PTR_NUMBER_PER_SECTOR * sizeof(disk_sector_t *));
          for(i=0; i<PTR_NUMBER_PER_SECTOR; i++)
            inode->data.double_indirect_index[i] = (disk_sector_t *) calloc(1, PTR_NUMBER_PER_SECTOR * sizeof(disk_sector_t));

          add_double_indirect_sectors = add_sectors - DIRECT_BLOCK_SIZE - INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR + inode->data.sectors;
          
          for(i=0; i<add_double_indirect_sectors; i++)
          {
            row = i/PTR_NUMBER_PER_SECTOR;
            col = i%PTR_NUMBER_PER_SECTOR;
            if(free_map_allocate (1, &inode->data.double_indirect_index[row][col]))
            {
              static char zeros[DISK_SECTOR_SIZE];
              cache_write_from_buffer(inode->data.double_indirect_index[row][col], zeros);
            }
            else
              return 0; // fail 
          }
        }
      }
    }
    else if(inode->data.sectors <= DIRECT_BLOCK_SIZE + INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR)
    {
      // start indirect, end indirect
      add_indirect_sectors = DIRECT_BLOCK_SIZE + INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR - inode->data.sectors < add_sectors ? DIRECT_BLOCK_SIZE + INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR - inode->data.sectors : add_sectors;
      for(i=0; i<add_indirect_sectors; i++)
      {
        row = (inode->data.sectors - DIRECT_BLOCK_SIZE + i)/PTR_NUMBER_PER_SECTOR;
        col = (inode->data.sectors - DIRECT_BLOCK_SIZE + i)%PTR_NUMBER_PER_SECTOR; 
        if(free_map_allocate (1, &inode->data.indirect_index[row][col]))
        {
          static char zeros[DISK_SECTOR_SIZE];
          cache_write_from_buffer(inode->data.indirect_index[row][col], zeros);
        }
        else
          return 0; // fail
      }
      if(DIRECT_BLOCK_SIZE + INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR - inode->data.sectors < add_sectors)
      {
        // start indirect, end double
        inode->data.double_indirect_index = (disk_sector_t **) calloc(1, PTR_NUMBER_PER_SECTOR * sizeof(disk_sector_t *));
        for(i=0; i<PTR_NUMBER_PER_SECTOR; i++)
          inode->data.double_indirect_index[i] = (disk_sector_t *) calloc(1, PTR_NUMBER_PER_SECTOR * sizeof(disk_sector_t));

        add_double_indirect_sectors = add_sectors - DIRECT_BLOCK_SIZE - INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR + inode->data.sectors;

        for(i=0; i<add_double_indirect_sectors; i++)
        {
          row = i/PTR_NUMBER_PER_SECTOR;
          col = i%PTR_NUMBER_PER_SECTOR;
          if(free_map_allocate (1, &inode->data.double_indirect_index[row][col]))
          {
            static char zeros[DISK_SECTOR_SIZE];
            cache_write_from_buffer(inode->data.double_indirect_index[row][col], zeros);
          }
          else
            return 0; // fail 
        }
      }
    }
    else
    {
      add_double_indirect_sectors = add_sectors;
      
      int row = 0;
      int col = 0;
      for(i=0; i<add_double_indirect_sectors; i++)
      {
        row = (i + inode->data.sectors - DIRECT_BLOCK_SIZE - INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR)/PTR_NUMBER_PER_SECTOR;
        col = (i + inode->data.sectors - DIRECT_BLOCK_SIZE - INDIRECT_BLOCK_SIZE * PTR_NUMBER_PER_SECTOR)%PTR_NUMBER_PER_SECTOR;
        if(free_map_allocate (1, &inode->data.double_indirect_index[row][col]))
        {
          static char zeros[DISK_SECTOR_SIZE];
          cache_write_from_buffer(inode->data.double_indirect_index[row][col], zeros);
        }
        else
          return 0; // fail 
      }
    }
    inode->data.sectors += add_sectors;
    inode->data.length = offset + size;
  }


  // printf("offset + size %d, inode length %d, add_sectors %d\n", offset+size, inode->data.length, add_sectors);
  if(offset + size > inode->data.length && add_sectors <= 0)
  {
    inode->data.length = offset + size;
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      // 여기를 cache에 쓰는 것으로 수정
      if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) 
        {
          /* Write full sector directly to disk. */
          // disk_write (filesys_disk, sector_idx, buffer + bytes_written); 
          cache_write_from_buffer(sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (DISK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) {
            // disk_read (filesys_disk, sector_idx, bounce);
            // printf("___DEBUG_____ cache_read_buffer in inode_write_at in sector_ofs %d chunk_size %d \n", sector_ofs, chunk_size);
            cache_read_to_buffer(sector_idx, bounce);
          }
          else
             memset (bounce, 0, DISK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          // disk_write (filesys_disk, sector_idx, bounce); 
          cache_write_from_buffer(sector_idx, bounce);
        }
      // 여기까지 수정

      // struct cache_entry *get_file = cache_get_file(sector_idx);
      // memcpy(get_file->data + sector_ofs, buffer+bytes_written, chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}


disk_sector_t
inode_parent (const struct inode *inode)
{
  return inode->parent;
}


bool
inode_isdir (const struct inode *inode)
{
  return inode->isdir;
}


int
inode_open_cnt(const struct inode *inode)
{
  return inode->open_cnt;
}