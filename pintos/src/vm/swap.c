#include "vm/swap.h"
#include "vm/page.h"
#include "devices/disk.h"
#include "threads/synch.h"
#include <bitmap.h>
#include "vm/frame.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"

/* The swap device */
static struct disk *swap_device;

/* Tracks in-use and free swap slots */
static struct bitmap *swap_table;

/* Protects swap_table */
static struct lock swap_lock;

//
extern struct hash *frame_table;

/* 
 * Initialize swap_device, swap_table, and swap_lock.
 */
void 
swap_init (void)
{
    swap_device = disk_get(1,1);
    if(swap_device == NULL) 
        return;
    disk_sector_t swap_size = disk_size(swap_device);

    swap_table = bitmap_create(swap_size/8);
    if(swap_table == NULL) 
        return;

    lock_init(&swap_lock);
}

/*
 * Reclaim a frame from swap device.
 * 1. Check that the page has been already evicted. 
 * 2. You will want to evict an already existing frame
 * to make space to read from the disk to cache. 
 * 3. Re-link the new frame with the corresponding supplementary
 * page table entry. 
 * 4. Do NOT create a new supplementray page table entry. Use the 
 * already existing one. 
 * 5. Use helper function read_from_disk in order to read the contents
 * of the disk into the frame. 
 */ 
bool 
swap_in (void *addr)
{
    
}

/* 
 * Evict a frame to swap device. 
 * 1. Choose the frame you want to evict. 
 * (Ex. Least Recently Used policy -> Compare the timestamps when each 
 * frame is last accessed)
 * 2. Evict the frame. Unlink the frame from the supplementray page table entry
 * Remove the frame from the frame table after freeing the frame with
 * pagedir_clear_page. 
 * 3. Do NOT delete the supplementary page table entry. The process
 * should have the illusion that they still have the page allocated to
 * them. 
 * 4. Find a free block to write you data. Use swap table to get track
 * of in-use and free swap slots.
 */
bool
swap_out (void)
{
    lock_acquire(&swap_lock);
    
    struct hash_iterator i;

    hash_first (&i, frame_table);
    struct hash_elem *evicted_elem = hash_delete(frame_table, hash_cur (&i));
    struct frame_table_entry *evicted_fte = hash_entry(evicted_elem, struct frame_table_entry, hash_elem);
    
    struct sup_page_table_entry *evicted_spte = evicted_fte->spte;
    pagedir_clear_page(evicted_fte->owner->pagedir, evicted_spte->user_vaddr);
    hash_delete(frame_table, evicted_elem);
    
    size_t bit_index = bitmap_scan(swap_table, 0, 1, 0);
    bitmap_flip(swap_table, bit_index);

	disk_write(swap_device, bit_index, evicted_fte->frame);

    evicted_spte->is_in_frame = 0;
    evicted_spte->is_in_swap = 1;
    evicted_spte->frame = 0;
    evicted_spte->bit_index = bit_index;

    lock_release(&swap_lock);
    return true;
}

/* 
 * Read data from swap device to frame. 
 * Look at device/disk.c
 */
void read_from_disk (uint8_t *frame, int index)
{


}

/* Write data to swap device from frame */
void write_to_disk (uint8_t *frame, int index)
{


}

