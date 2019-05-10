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

	struct list_elem elem;
};

void frame_init (void);
struct frame_table_entry * allocate_frame (void *frame, struct sup_page_table_entry *spte);


#endif /* vm/frame.h */
