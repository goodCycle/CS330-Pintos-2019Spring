#ifndef USERPROG_EXCEPTION_H
#define USERPROG_EXCEPTION_H

/* Page fault error code bits that describe the cause of the exception.  */
#define PF_P 0x1    /* 0: not-present page. 1: access rights violation. */
#define PF_W 0x2    /* 0: read, 1: write. */
#define PF_U 0x4    /* 0: kernel, 1: user process. */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "vm/page.h"

void exception_init (void);
void exception_print_stats (void);
bool is_valid (void *user_ptr);
bool need_stack_grow (bool user, void *fault_addr, uint32_t esp);
void stack_grow (void *upage, void *kpage);
void free_kpage_and_exit (void *kpage);
void load_file_lazily (void *kpage, struct sup_page_table_entry *spte);

#endif /* userprog/exception.h */
