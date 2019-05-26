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
#include "threads/malloc.h"

void cache_init()
{
    list_init(&cache_entry_list);
    lock_init(&cache_lock);
}

struct cache_entry *
cache_entry_find(disk_sector_t sector)
{
    struct list_elem *next, *e;
    if(list_size(&cache_entry_list) == 0) {
        return NULL;
    }
    
    struct cache_entry *c = NULL;
    for(e = list_begin(&cache_entry_list); e != list_end(&cache_entry_list) ; e = next)
    {
        next = list_next(e);
        c = list_entry(e, struct cache_entry, elem);
        if(c->sector == sector){
            return c;
        }
    }
    return NULL;
}

void
cache_entry_evict()
{
    ASSERT (lock_held_by_current_thread(&cache_lock));

    struct cache_entry *evict_entry = list_entry(list_pop_front(&cache_entry_list), struct cache_entry, elem);
    if (evict_entry->dirty) {
        cache_entry_back_to_disk(evict_entry);
    }
    free(evict_entry);
    return;
}

struct cache_entry *
cache_entry_add(disk_sector_t sector)
{
    ASSERT (lock_held_by_current_thread(&cache_lock));
    struct cache_entry *cache_entry = malloc(sizeof(struct cache_entry));
    
    disk_read(filesys_disk, sector, cache_entry->data);
    cache_entry->sector = sector;
    cache_entry->dirty = 0;

    list_push_back(&cache_entry_list, &cache_entry->elem);
    return cache_entry;
}

void
cache_read_to_buffer (disk_sector_t sector, void* buffer) 
{
    lock_acquire(&cache_lock);
    struct cache_entry *cache_entry = cache_entry_find(sector);
    if (cache_entry != NULL) {
        // printf("____DEBUG_____cache_read_to_buffer find cache_entry %d \n", cache_entry->sector);
    }
    if (cache_entry == NULL) // no cache entry
    {
        if (list_size(&cache_entry_list) < MAX_CACHE_SIZE) {
            // printf("_____DEBUG_____ just add\n");
            cache_entry = cache_entry_add(sector);
        } else {
            // printf("_____DEBUG_____ evict!\n");
            cache_entry_evict();
            cache_entry = cache_entry_add(sector);
        }
    }
    // printf("____DEBUG_____cache_read_to_buffer cache_entry sector %d \n", cache_entry->sector);
    memcpy(buffer, cache_entry->data, DISK_SECTOR_SIZE);
    lock_release(&cache_lock);
}

void
cache_write_from_buffer (disk_sector_t sector, void *buffer)
{
    // printf("___DEBUG____cache write from buffer %d \n", sector);
    // hex_dump(buffer, buffer, 4, 0);

    lock_acquire(&cache_lock);
    struct cache_entry *cache_entry = cache_entry_find(sector);
    if (cache_entry == NULL) // no cache entry
    {
        if (list_size(&cache_entry_list) < MAX_CACHE_SIZE) {
            cache_entry = cache_entry_add(sector);
        } else {
            cache_entry_evict();
            cache_entry = cache_entry_add(sector);
        }
    }

    memcpy(cache_entry->data, buffer, DISK_SECTOR_SIZE);
    cache_entry->dirty = 1; //
    lock_release(&cache_lock);
}

// struct cache_entry* cache_get_file(disk_sector_t sector)
// {
//     struct cache_entry *get_file = cache_entry_find(sector);
//     lock_acquire(&cache_lock);
//     if(get_file != NULL) {
//         lock_release(&cache_lock);
//         return get_file;
//     }
//     else if(list_size(&cache_entry_list) != MAX_CACHE_SIZE)
//     {
//         get_file = malloc(sizeof(struct cache_entry));
//         disk_read(filesys_disk, sector, get_file->data);
//         get_file->sector = sector;
//         get_file->dirty = 0;
//         list_push_back(&cache_entry_list, &get_file->elem);
//         lock_release(&cache_lock);
//         return get_file;
//     }
//     else
//     {
//         lock_release(&cache_lock);
//         get_file = cache_entry_evict(sector);
//         return get_file;
//     }
// }

void cache_entry_back_to_disk(struct cache_entry *cache_entry)
{
    ASSERT (lock_held_by_current_thread(&cache_lock));
    ASSERT (cache_entry != NULL);

    disk_write (filesys_disk, cache_entry->sector, cache_entry->data);
    cache_entry->dirty = false;
}

void all_cache_entry_back_to_disk()
{
    lock_acquire(&cache_lock);
    struct list_elem *e, *next;
    if(!list_empty(&cache_entry_list))
    {
        for(e = list_begin(&cache_entry_list); e != list_end(&cache_entry_list); e = next)
        {
            next = list_next(e);
            struct cache_entry *cache_entry = list_entry(e, struct cache_entry, elem);
            if (cache_entry->dirty) {
                cache_entry_back_to_disk(cache_entry);
            }
        }
    }
    lock_release(&cache_lock);
}