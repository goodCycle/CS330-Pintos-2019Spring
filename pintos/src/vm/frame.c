#include "vm/frame.h"
#include "vm/page.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"

static struct hash frame_table;

/*
 * Initialize frame table
 */
void 
frame_init (void)
{
    hash_init (&frame_table, &frame_hash_func, &frame_hash_less_func, NULL);
}


/* 
 * Make a new frame table entry for addr.
 */
struct frame_table_entry *
allocate_frame (void *frame, struct sup_page_table_entry *spte)
{
    struct frame_table_entry *new_fte = malloc(sizeof(struct frame_table_entry));
    if (new_fte == NULL)
        return NULL;
    new_fte->frame = frame;
    new_fte->owner = thread_current();
    new_fte->spte = spte;
    hash_insert(&frame_table, &new_fte->hash_elem);

    spte->is_mapped = 1; //
    return new_fte;
}

uint8_t
evict_frame(void *addr)
{
    swap_out();
    void* kpage = palloc_get_page(PAL_USER | PAL_ZERO); //need synch? while?!?!?!?!?
    swap_in(addr, kpage);
    return kpage;
}

struct hash_elem *
delete_frame_entry()
{
    struct hash_iterator i;
    hash_first (&i, &frame_table);
    hash_next(&i);
    struct hash_elem *evicted_elem = hash_delete(&frame_table, hash_cur (&i));
    return evicted_elem;
}

struct frame_table_entry *
fte_find(void *kpage)
{
    struct thread *curr = thread_current();
    struct hash_iterator i;
    struct frame_table_entry *fte; 
    hash_first (&i, &frame_table);

    while (hash_next (&i))
    {
        fte = hash_entry (hash_cur (&i), struct frame_table_entry, hash_elem);
        if(fte->frame == kpage){
            break;
        }
        fte = NULL;
    }

    if (fte == NULL) 
        return NULL;
    return fte;
}

void
remove_frame(void *kpage)
{
    struct frame_table_entry *fte = fte_find(kpage);
   
    hash_delete(&frame_table, &fte->hash_elem);
    palloc_free_page(fte->frame);

    hash_delete(&fte->owner->spt, &fte->spte->hash_elem);
    free(fte->spte);
    free(fte);
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

