#include "vm/frame.h"
#include "vm/page.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"

static struct list frame_table;
struct lock frame_lock;
struct lock frame_table_lock;

/*
 * Initialize frame table
 */
void 
frame_init (void)
{
    list_init (&frame_table);
    lock_init(&frame_lock);
    lock_init(&frame_table_lock);
}


/* 
 * Make a new frame table entry for addr.
 */
struct frame_table_entry *
allocate_frame (void *frame, struct sup_page_table_entry *spte)
{
    lock_acquire(&frame_lock);
    struct frame_table_entry *new_fte = malloc(sizeof(struct frame_table_entry));
    if (new_fte == NULL)
        return NULL;
    new_fte->frame = frame;
    new_fte->owner = thread_current();
    new_fte->spte = spte;
    lock_acquire(&frame_table_lock);
    list_push_back(&frame_table, &new_fte->elem);
    lock_release(&frame_table_lock);

    spte->is_mapped = 1; //
    lock_release(&frame_lock);
    return new_fte;
}

uint8_t
evict_frame(void *addr)
{
    swap_out();
    void* kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    while(!kpage)
    {
        swap_out();
        kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    }
    swap_in(addr, kpage);
    return kpage;
}

struct hash_elem *
delete_frame_entry()
{
    lock_acquire(&frame_table_lock);
    struct hash_elem *evicted_elem = list_pop_front(&frame_table);
    lock_release(&frame_table_lock);
    return evicted_elem;
}

struct frame_table_entry *
fte_find(void *kpage)
{
    struct thread *curr = thread_current();
    struct frame_table_entry *fte; 
    struct list_elem *e, *next;
    lock_acquire(&frame_table_lock);
    
    for(e=list_begin(&frame_table);e!=list_end(&frame_table);e=next){
        next = list_next(e);
        fte = list_entry(e, struct frame_table_entry, elem);
        if(fte->frame == kpage)
            break;
        fte = NULL;
    }

    if (fte == NULL) {
        lock_release(&frame_table_lock);
        return NULL;
    }
    lock_release(&frame_table_lock);
    return fte;
}

void
remove_frame(void *kpage)
{
    lock_acquire(&frame_lock);
    struct frame_table_entry *fte = fte_find(kpage);
    if (fte == NULL)
    {
        lock_release(&frame_lock);
        return;
    }
    lock_acquire(&frame_table_lock);
    list_remove(&fte->elem);
    lock_release(&frame_table_lock);

    hash_delete(&fte->owner->spt, &fte->spte->hash_elem);
    free(fte->spte);
    free(fte);
    lock_release(&frame_lock);
}

void
frame_free_mapping_with_curr_thread(struct thread *thread) 
{
    struct list_elem *e, *next;

    for (e=list_begin(&frame_table); e != list_tail(&frame_table); e = next)
    {
        next = list_next(e);
        struct frame_table_entry *fte = list_entry(e, struct frame_table_entry, elem);

        if (fte->owner->tid == thread->tid) {
            remove_frame(fte->frame);
        }
    }
}
