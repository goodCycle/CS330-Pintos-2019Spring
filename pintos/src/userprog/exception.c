#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/page.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;
 
  // printf("fault addr %08x \n", fault_addr);
  if (!is_valid ((int32_t) fault_addr)){
    printf("is_valid %08x?\n", fault_addr);
    exit (-1);
  }

  // printf("pagedir get page is %08x\n", pagedir_get_page(thread_current()->pagedir, pg_round_down(fault_addr)));

  // pt-write-code 막기 위해 write on read-only page 면 exit
  if (!not_present) {
    exit(-1);
  }

  fault_addr = pg_round_down (fault_addr);

  if (!is_valid_stack(fault_addr)){
    // printf("here %08x \n", fault_addr);
    if (fault_addr > 0x90000000){
      exit(-1);
    }
    uint8_t *kpage;
    void *upage = fault_addr;

    struct sup_page_table_entry *find_spte = spte_find(upage);
    // printf("spte_find user_vaddr %08x, writable %d, upage %08x", find_spte->user_vaddr, find_spte->writable, upage);
    // printf("  file %08x, page_read_bytes %d, page_zero_bytes %d, offset %d\n", find_spte->file, find_spte->page_read_bytes, find_spte->page_zero_bytes, find_spte->ofs);
    
    if(find_spte == NULL){
      exit(-1);
    }

    if(find_spte->page_read_bytes != 0)
      kpage = palloc_get_page (PAL_USER);
    else
      kpage = palloc_get_page (PAL_USER | PAL_ZERO);

    if (kpage != NULL) {
      if (find_spte->from_load && find_spte->page_read_bytes > 0) {
        lock_acquire(&file_lock);
        if (file_read_at (find_spte->file, kpage, find_spte->page_read_bytes, find_spte->ofs) != (int) find_spte->page_read_bytes)
        {
          palloc_free_page (kpage);
          lock_release(&file_lock);
          printf("exit here 3 %08x \n", fault_addr);
          exit(-1);
        }
        memset (kpage + find_spte->page_read_bytes, 0, find_spte->page_zero_bytes);
        lock_release(&file_lock);
      }

      // frame table에 추가
      struct frame_table_entry *new_fte = allocate_frame(kpage, find_spte);
      if (new_fte == NULL)
      {
        palloc_free_page(kpage);
        exit(-1);
      }

      if (!install_page(upage, kpage, find_spte->writable)) {
        palloc_free_page(kpage);
        exit(-1);
      }
      find_spte->frame = kpage;

    }
    else { // frame eviction이 필요
      if (find_spte->from_load) {
        swap_out();
        kpage = palloc_get_page(PAL_USER); //while????
        if (find_spte->from_load) {
          if (file_read_at (find_spte->file, kpage, find_spte->page_read_bytes, find_spte->ofs) != (int) find_spte->page_read_bytes)
          {
            palloc_free_page (kpage);
            exit(-1);
          }
          memset (kpage + find_spte->page_read_bytes, 0, find_spte->page_zero_bytes);
        }
        else{
          palloc_free_page(kpage);
          exit(-1);
        }
      }
      else if (find_spte->is_in_swap) { // 1) frame이 꽉 찼는데 매핑되어야 할 애가 swap에 있음
        kpage = evict_frame(upage);
        // swap에 있으면 이미 initialize 된 거임.
        if (!install_page(upage, kpage, find_spte->writable)){
          exit(-1);
        }
      }
      else { // 2) frame이 꽉 찼는데 매핑되어야 할 애가 file에 있음
        // frame eviction의 return값이 넣을 frame을 리턴 (frame eviction 은 file_in + spte에서 매핑 끊기)
        // spte에서 추가
        // frame table을 새로운 값으로 수정
      }
    }
  }
  else { // stack grow
    uint8_t *kpage = palloc_get_page (PAL_USER);
    void *upage = fault_addr;

    bool writable = true;
    if (kpage != NULL) {
      if(!install_page(upage, kpage, writable)){
        palloc_free_page(kpage);
        exit(-1);
      }
      // spte에 추가
      struct sup_page_table_entry *new_spte = allocate_page(upage, kpage, 1, 1, NULL, 0, 0, 0, 1, 0); // is_in_frame
      if (new_spte == NULL) { 
        palloc_free_page(kpage);
        exit(-1);
      }
      
      // frame table에 추가
      struct frame_table_entry *new_fte = allocate_frame(kpage, new_spte);
      if (new_fte == NULL)
      {
        palloc_free_page(kpage);
        exit(-1);
      }
    }
    else{ // eviction
      swap_out();
      kpage = palloc_get_page(PAL_USER); //while????
      struct sup_page_table_entry *new_spte = allocate_page(upage, kpage, 0, 1, NULL, 0, 0, 0, 1, 0); // frame 꽉 참
      allocate_frame(kpage, new_spte);
      install_page(upage, kpage, writable);
    }
  }
  /* To implement virtual memory, delete the rest of the function
     body, and replace it with code that brings in the page to
     which fault_addr refers. */
  /* printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
  kill (f); */
}

bool is_valid (void *user_ptr)
{
  if(user_ptr == NULL || !is_user_vaddr(user_ptr) || user_ptr < (void *) 0x08048000) {
    return 0;
	}
  return 1;
}

bool is_valid_stack (void *user_ptr)
{
  if(thread_current()->user_esp - PGSIZE <= user_ptr && user_ptr >= 0x90000000){
    return 1;
  }
  return 0;
}
