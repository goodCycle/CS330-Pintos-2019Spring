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
    hash_init(&curr->spt, spt_hash_func, spt_hash_less_func, NULL);
}

/*
 * Make new supplementary page table entry for addr 
 */
struct sup_page_table_entry *
allocate_page (void *addr)
{

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

