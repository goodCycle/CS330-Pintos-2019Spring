#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);


/* Starts a new thread running a user program loadedm from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  char file_name_only[256]; // 4KB

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  // If there is no page to be allocated.
  if (fn_copy == NULL) {
    palloc_free_page(fn_copy); 
    return TID_ERROR;
  }
  strlcpy(fn_copy, file_name, PGSIZE);

  // Extract file name only from input file_name
  int i;
  strlcpy(file_name_only, file_name, strlen(file_name)+1);
  for(i=0; file_name_only[i] != '\0' && file_name_only[i] != ' '; i++);
  file_name_only[i] = '\0';

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name_only, PRI_DEFAULT, start_process, fn_copy);
  // If thread_create get failed.
  if(tid == TID_ERROR){
    palloc_free_page(fn_copy);
    return tid;
  }

  struct thread *curr = thread_current();
  struct list_elem *e, *next;
  struct thread *child_thread;
  
  if (!list_empty(&curr->child_list)) {
    for (e = list_begin(&curr->child_list); e != list_end(&curr->child_list); e = next) {
      next = list_next(e);
      child_thread = list_entry(e, struct thread, child_elem);
      if (child_thread->tid == tid) {
        break;
      }
    }
    
    sema_down(&child_thread->child_load_sema); // prevent parent instruct next row before child load
    
    if (child_thread->load_check == 0) {
      tid = TID_ERROR;
      palloc_free_page(fn_copy);
      return process_wait(tid);
    }
  }
  // Need to free page before return.
  palloc_free_page(fn_copy);
  return tid;
}

/* A thread function that loads a user process and makes it start
   running. */
static void
start_process (void *f_name)
{
  //
  char *file_name = palloc_get_page(0);
  if(file_name == NULL){
    palloc_free_page(file_name);
    thread_exit();
  }
  strlcpy(file_name, f_name, PGSIZE);

  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  // Initialize supplement page table of user process
  page_init();
  success = load (file_name, &if_.eip, &if_.esp);

  // 
  if (success) {
    thread_current()->load_check = 1;
  } else {
    thread_current()->load_check = 0;
  }
  sema_up(&thread_current()->child_load_sema); // 자식이 로드되고 부모가 exec 되야함.
  //

  /* If load failed, quit. */
  palloc_free_page (file_name);  //

  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

void push_stack_arguments(char* file_name, char* file_arguments, void **esp){

  // Calculate argc
  int argc = 1;
  if (strlen(file_arguments) != 0) {
    char *argument_ptr = file_arguments;
    while((argument_ptr = strchr(argument_ptr, ' ')) != NULL) {
      argc++;
      argument_ptr++;
      while (argument_ptr[0] == ' ') {
        argument_ptr += 1;
      }
    }
    argc += 1;
  }
  // Store the address of arguments that it's value is stored.
  int i;
  int total_length = 0;
  int cnt = 1;
  uint32_t *arg_address = malloc(sizeof(uint32_t)*argc);
  memset(arg_address, 0, sizeof(arg_address));
  int number_of_arguments = argc - 1;
  if (number_of_arguments > 1) {
    for (i = argc-1; i >= 2; i--) {
      char* last_word = strrchr(file_arguments, ' ');
      cnt = 1;
      while(*last_word == ' '){
        *last_word = '\0';
        cnt += 1;
        last_word -= 1;
      }
      last_word = last_word + cnt;
      *esp -= strlen(last_word)+1;
      arg_address[i] = *esp;
      strlcpy(*esp, last_word, strlen(last_word)+1);
      total_length += strlen(last_word)+1;
    }
  }
  
  // If the number of argument is one
  if (number_of_arguments > 0) {
    *esp -= strlen(file_arguments)+1;
    arg_address[1] = *esp;
    strlcpy(*esp, file_arguments, strlen(file_arguments)+1);
    total_length += strlen(file_arguments)+1;
  }

  // Store address and value of file name in the stack.
  *esp -= strlen(file_name)+1;
  arg_address[0] = *esp;
  strlcpy(*esp, file_name, strlen(file_name)+1);
  total_length += strlen(file_name)+1;

  // Do word align.
  int word_align = (total_length % 4 == 0) ? 0 : 4 - total_length % 4;
  *esp -= word_align;
  memset(*esp, 0, word_align);
 
  // Push 4 byte as 0.
  *esp -= 4;
  memset(*esp, 0, 4);
  
  // Push argment vector.
  for (i=argc-1;i>=0;i--){
    *esp -= 4;
    memcpy(*esp, &arg_address[i], 4);
  }

  // Push the address of the argv
  int argv_zero_address = *esp;
  *esp -= 4;
  memcpy(*esp, &argv_zero_address, 4);

  // Push argc
  *esp -= 4;
  memcpy(*esp, &argc, 4);

  // Push the fake return address.
  *esp -= 4;
  memset(*esp, 0, 4);

  free(arg_address);
}

/* This is 2016 spring cs330 skeleton code */

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  // check child_tid is valid
  int has_child = 0;
  struct thread *curr = thread_current();
  struct thread *t;
  struct list_elem *e, *next;

  if (list_empty(&curr->child_list)) {
    return -1;
  }
  for (e=list_begin(&curr->child_list); e != list_tail(&curr->child_list); e = next)
  {
    next = list_next(e);
    t = list_entry(e, struct thread, child_elem);
    if (t->tid == child_tid) {
      // prevent wait twice
      if (t->is_wait_called) {
        t->exit_status = -1;
        has_child = 1;
        return -1;
      }
      else {
        t->is_wait_called = 1;
        has_child = 1;
        break;
      }
    }
  }
  if (!has_child) {
    return -1;
  }

  sema_down(&t->child_alive_sema); //자식이 죽을 때 까지 기다리는 sema
  int child_exit_status = t->exit_status;

  list_remove(&t->child_elem);
  sema_up(&t->parent_wait_in_sema); //자식이 죽기 전에 wait에 와야하는 parent
  
  return child_exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  // printf("exit call\n");
  struct thread *curr = thread_current ();
  uint32_t *pd;

  struct file_info *t;
  struct list_elem *e, *next;
  struct thread *child;

  if(!list_empty(&curr->fd_list)){
    for(e = list_begin(&curr->fd_list);e != list_end(&curr->fd_list); e = next){
      next = list_next(e);
      t = list_entry(e, struct file_info, elem);
      close(t->fd);
    }
  }

  if(!list_empty(&curr->child_list)){
    for(e = list_begin(&curr->child_list); e != list_end(&curr->child_list); e = next){
      next = list_next(e);
      child = list_entry(e, struct thread, child_elem);
      wait(child->tid);
    }
  }
  

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = curr->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      curr->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  //
  if (curr->load_check) {
    printf("%s: exit(%d)\n", curr->name, curr->exit_status);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (char* file_name, char* file_arguments, void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  // Initialize exit
  t->exit_status = 0;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();
  
  // Split file name
  char *save_ptr;
  char *file_name_only = palloc_get_page(0);
  if(file_name_only == NULL) {
    palloc_free_page (file_name_only); 
    goto done;
  }
  strlcpy(file_name_only, file_name, strlen(file_name)+1);
  file_name_only = strtok_r(file_name_only, " ", &save_ptr);

  // Copy file_name to file_name_only for palloc_free_page at the last.
  if (file_name_only == NULL) {
    strlcpy(file_name_only, file_name, strlen(file_name)+1);
  }
  
  /* Open executable file. */
  file = filesys_open (file_name_only);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (file_name_only, save_ptr, esp)) // change arguments of setup_stack
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  palloc_free_page(file_name_only);
  return success;
}

/* load() helpers. */

bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Do calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      // uint8_t *kpage = palloc_get_page (PAL_USER);
      // if (kpage == NULL)
      //   return false;

      // /* Load this page. */
      // if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
      //   {
      //     palloc_free_page (kpage);
      //     return false; 
      //   }
      // memset (kpage + page_read_bytes, 0, page_zero_bytes);

      // /* Add the page to the process's address space. 여기도 spte에 추가 */
      // if (!install_page (upage, kpage, writable)) 
      // {
      //     palloc_free_page (kpage);
      //     return false; 
      // }

      // printf("upage is %08x, kpage is %08x\n, writable is %08x\n", upage, kpage, writable);
      
      // 여기서 spte만 만들어서 추가만 해줘야 됨......
      // (void *addr, void *frame, bool is_in_frame, bool is_in_swap, struct file *file, off_t ofs, size_t page_read_bytes, size_t page_zero_bytes, bool writable, bool from_load);
      allocate_page(upage, 0, 1, 0, file, ofs, page_read_bytes, page_zero_bytes, writable, 1); // Load하면 frame에 있다. 얘는 file 공간에서 온 애니까..
      //
      // printf("upage is %08x\n", upage);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += page_read_bytes;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (char* file_name, char* file_arguments, void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }

  // Push arguments in the stack
  push_stack_arguments(file_name, file_arguments, esp);

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
