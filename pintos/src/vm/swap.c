#include "vm/swap.h"
#include "vm/page.h"
#include "devices/disk.h"
#include "threads/synch.h"
#include <bitmap.h>
#include "vm/frame.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

/* The swap device */
static struct disk *swap_device;

/* Tracks in-use and free swap slots */
static struct bitmap *swap_table;

/* Protects swap_table */
struct lock swap_lock;

//
// extern struct hash frame_table;

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
swap_in (void *addr, void *kpage)
{   
    struct thread *curr = thread_current();
    struct hash_iterator i;
    struct sup_page_table_entry *spte; 
    hash_first (&i, &curr->spt);

    while (hash_next (&i)) //find spte
    {
        spte = hash_entry (hash_cur (&i), struct sup_page_table_entry, hash_elem);
        if(spte->user_vaddr == addr)
            break;
    }

    if(spte == NULL){
        lock_release(&swap_lock);
        return false;
    }
        
    if(spte->is_in_frame){
        lock_release(&swap_lock);
        return false;
    }
        
    if (spte->is_mapped) {
        size_t bit_index = spte->bit_index;
        
        // swap에도 없는 경우
        read_from_disk(kpage, bit_index); //kpage의 정보를 bit_index에 read
        bitmap_flip(swap_table, bit_index); //flip

        spte->frame = kpage;
        spte->is_in_frame = 1;
    }
    else
    {
        file_seek(spte->file, spte->ofs);
        file_read(spte->file, kpage, spte->page_read_bytes);
        memset (kpage + spte->page_read_bytes, 0, spte->page_zero_bytes);
    }
    
    struct frame_table_entry *fte = allocate_frame(kpage, spte);
    if(!fte){
        palloc_free_page(kpage);
        free(fte);
        return false;
    }
    
    if(!install_page(addr, kpage, spte->writable)){
        palloc_free_page(kpage);
        lock_release(&swap_lock);
        return false;
    }
    lock_release(&swap_lock);
    return true;
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
    
    struct hash_elem *evicted_elem = delete_frame_entry(); //hash_delete(&frame_table, hash_cur (&i));
    struct frame_table_entry *evicted_fte = hash_entry(evicted_elem, struct frame_table_entry, hash_elem);
    struct sup_page_table_entry *evicted_spte = evicted_fte->spte;
    
    if(evicted_spte->is_in_swap)
    {
        size_t bit_index = bitmap_scan(swap_table, 0, 1, 0);
        bitmap_flip(swap_table, bit_index);
        write_to_disk(evicted_fte->frame, bit_index);

        evicted_spte->bit_index = bit_index;
    }
    else
    {
        if(evicted_spte->dirty)
        {
            file_seek(evicted_spte->file, evicted_spte->ofs);
            file_write(evicted_spte->file, evicted_spte->frame, evicted_spte->page_read_bytes);
        }
    }
    
    evicted_spte->is_in_frame = 0;

    pagedir_clear_page(evicted_fte->owner->pagedir, evicted_spte->user_vaddr);
    palloc_free_page(evicted_fte->frame);
    free(evicted_fte); //
    return true;
}

/* 
 * Read data from swap device to frame. 
 * Look at device/disk.c
 */
void read_from_disk (uint8_t *frame, int index)
{
    int i=0;
    for(i=0;i<8;i++)
        disk_read(swap_device, (disk_sector_t)(index*8+i), frame+i*512);
}

/* Write data to swap device from frame */
void write_to_disk (uint8_t *frame, int index)
{
    int i=0;
    for(i=0;i<8;i++)
        disk_write(swap_device, (disk_sector_t)(index*8+i), frame+i*512);
}
