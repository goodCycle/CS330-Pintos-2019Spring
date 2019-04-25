#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
/*
 * Initialize frame table
 */
void 
frame_init (void)
{

}


/* 
 * Make a new frame table entry for addr.
 */
bool
allocate_frame (void *addr)
{

}


uint32_t frame_hash_func(struct hash_elem *e)
{
    struct frame_table_entry *fte = hash_entry(e, struct frame_table_entry, hash_elem);
    return ((uint32_t) fte->frame >> PGBITS);
}
bool frame_hash_less_func (const struct hash_elem *elem_a, const struct hash_elem *elem_b, void *aux)
{
    const struct frame_table_entry *a = hash_entry(elem_a, struct frame_table_entry, hash_elem);
    const struct frame_table_entry *b = hash_entry(elem_b, struct frame_table_entry, hash_elem);
    return a->frame < b->frame;
}

