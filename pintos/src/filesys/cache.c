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
#include "threads/synch.h"

struct list cache_file_list;
struct lock cache_lock;

void file_cache_init()
{
    list_init(&cache_file_list);
    lock_init(&cache_lock);
}

struct cache_file *find_file_in_cache(disk_sector_t sector)
{
    lock_acquire(&cache_lock);
    int find = 0;
    struct list_elem *next, *e;
    if(list_size(&cache_file_list) == 0) {
        lock_release(&cache_lock);
        return NULL;
    }
    
    struct cache_file *c;
    for(e = list_begin(&cache_file_list); e != list_end(&cache_file_list) ; e = next)
    {
        next = list_next(e);
        c = list_entry(e, struct cache_file, elem);

        if(c->sector == sector)
        {
            find = 1;
            break;
        }
    }

    if(find == 0) {
        lock_release(&cache_lock);
        return NULL;
    }
    lock_release(&cache_lock);
    return c;
}

struct cache_file* cache_evicted_file(disk_sector_t sector)
{
    lock_acquire(&cache_lock);
    struct cache_file *evicted_file = list_entry(list_pop_front(&cache_file_list), struct cache_file, elem);

    if (evicted_file->dirty)
    {
        disk_write (filesys_disk, evicted_file->sector, evicted_file->data);
    }

    free(evicted_file);
    struct cache_file *new_file = malloc(sizeof(struct cache_file));
    
    disk_read(filesys_disk, sector, new_file->data);
    new_file->sector = sector;
    new_file->dirty = 0;

    list_push_back(&cache_file_list, &new_file->elem);

    // free(evicted_file);
    lock_release(&cache_lock);
    return new_file;
}

struct cache_file* cache_get_file(disk_sector_t sector)
{
    struct cache_file *get_file = find_file_in_cache(sector);
    lock_acquire(&cache_lock);
    if(get_file != NULL) {
        lock_release(&cache_lock);
        return get_file;
    }
    else if(list_size(&cache_file_list) != MAX_CACHE_SIZE)
    {
        get_file = malloc(sizeof(struct cache_file));
        disk_read(filesys_disk, sector, get_file->data);
        get_file->sector = sector;
        get_file->dirty = 0;
        list_push_back(&cache_file_list, &get_file->elem);
        lock_release(&cache_lock);
        return get_file;
    }
    else
    {
        lock_release(&cache_lock);
        get_file = cache_evicted_file(sector);
        return get_file;
    }
}


void cache_back_to_disk()
{
    lock_acquire(&cache_lock);
    struct list_elem *e, *next;
    if(!list_empty(&cache_file_list))
    {
        for(e = list_begin(&cache_file_list); e != list_end(&cache_file_list); e = next)
        {
            next = list_next(e);
            struct cache_file *cache_file = list_entry(e, struct cache_file, elem);
            if(cache_file->dirty)
            {
                disk_write (filesys_disk, cache_file->sector, cache_file->data);
            }
        }
    }
    lock_release(&cache_lock);
}