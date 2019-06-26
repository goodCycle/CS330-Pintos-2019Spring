#include "filesys/off_t.h"
#include "devices/disk.h"
#include "list.h"
#include "threads/synch.h"

#define MAX_CACHE_SIZE 64

extern struct disk *filesys_disk;

struct cache_entry
{
    // bool valid; // true if if is a valid cache entry

    uint8_t data[DISK_SECTOR_SIZE];
    struct list_elem elem;
    disk_sector_t sector;
    
    bool dirty;
};

struct list cache_entry_list;
struct lock cache_lock;

// struct cache_entry *cache_get_file(disk_sector_t sector);
void cache_init();
struct cache_entry *cache_entry_find(disk_sector_t sector);
void cache_entry_evict();
struct cache_entry *cache_entry_add(disk_sector_t sector);
void cache_entry_back_to_disk(struct cache_entry *cache_entry);
void all_cache_entry_back_to_disk();
void cache_read_to_buffer (disk_sector_t sector, void* buffer);
void cache_write_from_buffer (disk_sector_t sector, void *buffer);
