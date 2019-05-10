#include "vm/page.h"
#include "threads/thread.h"
#include "threads/vaddr.h"


/*
 * Initialize supplementary page table
 */
void 
page_init ()
{
    struct thread *curr = thread_current();
    hash_init(&curr->spt, &spt_hash_func, &spt_hash_less_func, NULL);
}

/*
 * Make new supplementary page table entry for addr 
 */
struct sup_page_table_entry *
allocate_page (void *addr, void *frame, bool is_in_frame, bool is_in_swap, struct file *file, off_t ofs, size_t page_read_bytes, size_t page_zero_bytes, bool writable, bool from_load)
{
    struct sup_page_table_entry *spte = malloc(sizeof(struct sup_page_table_entry));
    if (spte == NULL)
        return NULL;

    spte->user_vaddr = addr;
    spte->frame = frame;
    spte->is_in_frame = is_in_frame;
    spte->is_in_swap = is_in_swap;
    spte->is_mapped = 0;

    spte->file = file;
    spte->page_read_bytes = page_read_bytes;
    spte->page_zero_bytes = page_zero_bytes;
    spte->from_load = from_load;
    spte->writable = writable;
    spte->ofs = ofs;
    
    // spte->dirty = 0;
	// spte->accessed = 0
    
    
    hash_insert(&thread_current()->spt, &spte->hash_elem);
    return spte;
}

struct sup_page_table_entry *
spte_find(void *addr)
{
    struct thread *curr = thread_current();
    struct hash_iterator i;
    struct sup_page_table_entry *spte; 
    hash_first (&i, &curr->spt);

    while (hash_next (&i)) //find spte
    {
        spte = hash_entry (hash_cur (&i), struct sup_page_table_entry, hash_elem);
        if(spte->user_vaddr == addr){
            // printf("spte->user_vaddr %08x, addr is %08x\n", spte->user_vaddr, addr);
            break;
        }
        spte = NULL;
    }

    if (spte == NULL) 
        return NULL;
    return spte;
}

uint32_t spt_hash_func(struct hash_elem *e) {
    struct sup_page_table_entry *spte = hash_entry(e, struct sup_page_table_entry, hash_elem);
    return ((uint32_t) spte->user_vaddr >> PGBITS);
}
bool spt_hash_less_func (const struct hash_elem *elem_a, const struct hash_elem *elem_b, void *aux) {
    const struct sup_page_table_entry *a = hash_entry(elem_a, struct sup_page_table_entry, hash_elem);
    const struct sup_page_table_entry *b = hash_entry(elem_b, struct sup_page_table_entry, hash_elem);
    return a->user_vaddr < b->user_vaddr;
}

