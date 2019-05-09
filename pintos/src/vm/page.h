#include <stdlib.h>
#include <stdbool.h>
#include <bitmap.h>
#include "hash.h"
#include "filesys/off_t.h"

#ifndef VM_PAGE_H
#define VM_PAGE_H

struct sup_page_table_entry 
{
	uint32_t* user_vaddr;
	uint64_t access_time;

	bool dirty;
	bool accessed;

	//
	uint32_t *frame; // physical address of frame to reference frame table
	bool is_in_frame;
	bool is_in_swap; // 1이면 swap에, 0이면 file에
	bool is_mapped; // frame과 mapping 된 적이 있었냐
	size_t bit_index;
	struct hash_elem hash_elem;

	struct file *file;
	off_t ofs;
	size_t page_read_bytes;
	size_t page_zero_bytes;
	bool from_load;
	bool writable;
};

void page_init (void);
struct sup_page_table_entry *allocate_page (void *addr, void *frame, bool is_in_frame, bool is_in_swap, struct file *file, off_t ofs, size_t page_read_bytes, size_t page_zero_bytes, bool writable, bool from_load);
uint32_t spt_hash_func(struct hash_elem *e);
bool spt_hash_less_func (const struct hash_elem *elem_a, const struct hash_elem *elem_b, void *aux);

#endif /* vm/page.h */
