#include "hash.h"
#include <stdlib.h>
#include <stdbool.h>
#include <bitmap.h>

#ifndef VM_FRAME_H
#define VM_FRAME_H

struct frame_table_entry
{
	uint32_t* frame;
	struct thread* owner;
	struct sup_page_table_entry* spte;

	struct hash_elem hash_elem;
};

void frame_init (void);
struct frame_table_entry * allocate_frame (void *frame, struct sup_page_table_entry *spte);


uint32_t frame_hash_func(struct hash_elem *e);
bool frame_hash_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux);

#endif /* vm/frame.h */
