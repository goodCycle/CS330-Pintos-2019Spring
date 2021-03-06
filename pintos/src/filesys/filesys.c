#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "devices/disk.h"
#include "threads/thread.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  filesys_disk = disk_get (0, 1);
  if (filesys_disk == NULL)
    PANIC ("hd0:1 (hdb) not present, file system initialization failed");

  inode_init ();
  free_map_init ();
  cache_init();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  all_cache_entry_back_to_disk();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  disk_sector_t inode_sector = 0;
  struct dir *dir = get_dir(name);
  char *file_name = get_name(name);
  char *check_memory;
  // printf("name is %s\n", name);
  // printf("dir sector %d, file_name %s, inode is %08x\n", inode_get_inumber(dir_get_inode(dir)), file_name, dir_get_inode(dir));
  // printf("inode %08x\n", dir_get_inode(dir));
  // printf("name %s\n", file_name);

  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size)
                  && ((check_memory = malloc(8*1024)) != NULL)
                  && dir_add (dir, file_name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);
  
  // printf("dir open cnt %d\n", inode_open_cnt(dir_get_inode(dir)));

  dir_close (dir);
  free(file_name);

  if(check_memory != NULL)
    free(check_memory);

  // if(success)
  //   printf("name is %s\n", name);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  struct dir *dir = get_dir(name);
  char *file_name = get_name(name);
  struct inode *inode = NULL;

  // printf("here?\n");
  // printf("dir %08x, file_name %s\n", dir, file_name);

  // printf("IN FILESYS OPEN\n");
  // printf("dir sector %d, file_name %s\n", inode_get_inumber(dir_get_inode(dir)), file_name);
  // printf("1. inode %08x\n", dir_get_inode(dir));
  
  if (strlen(name) == 0 || (dir == NULL && file_name == NULL)) {
    return NULL;
  }

  if (dir != NULL)
  {
    if(inode_get_inumber(dir_get_inode(dir)) == 1 && strcmp(file_name, "") == 0) // root
    {
      dir_close (dir);
      return file_open(inode_open(ROOT_DIR_SECTOR));
    }

    if(strcmp(file_name, ".") == 0)
    {
      inode = dir_get_inode(dir);
    }
    else if(strcmp(file_name, "..") == 0)
    {
      // inode = inode_open(inode_parent(dir_get_inode(dir)));
    }
    else
    { 
      // printf("lookup?!?!\n");
      if(!dir_lookup (dir, file_name, &inode))
      {
        // printf("lookup fail!\n");
        dir_close (dir);
        free(file_name);
        return NULL;
      }
    }
  }  

  // printf("inode %08x, inode is dir? %d, sector %d\n", inode, inode_isdir(inode), inode_get_inumber(inode));

  dir_close (dir);
  free(file_name);
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  // printf("name is %s\n", name);

  struct dir *dir = get_dir(name);
  char *file_name = get_name(name);

  // printf("dir %08x, file name %s\n", dir, file_name);

  if(dir != NULL && inode_get_inumber(dir_get_inode(dir)) == 1 && strlen(file_name) == 0) // remove root
  {
    // printf("filesysremove!! \n");
    dir_close (dir); 
    return false;
  }

  bool success = dir != NULL && dir_remove (dir, file_name);
  dir_close (dir); 

  free(file_name);
  // printf("remove success!\n");

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
