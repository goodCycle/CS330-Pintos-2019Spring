#include "filesys/off_t.h"
#include "devices/disk.h"
#include "list.h"

#define MAX_CACHE_SIZE 64

extern struct disk *filesys_disk;

struct cache_file
{

    uint8_t data[DISK_SECTOR_SIZE];
    struct list_elem elem;
    disk_sector_t sector;
    
    bool dirty;
};

struct cache_file *cache_get_file(disk_sector_t sector);
void cache_back_to_disk();
