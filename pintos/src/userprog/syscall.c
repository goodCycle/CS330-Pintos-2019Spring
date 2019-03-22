#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);
int sys_write(int fd, const void *buffer, unsigned size);
void* valid_pointer(void *ptr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int *valid_syscall_num = (int *)valid_pointer((int*)(f->esp));
  int syscall_num = *valid_syscall_num;

  switch(syscall_num){
    case SYS_EXIT:
    {
      int *valid_status = (int *)valid_pointer((int*)(f->esp+4));
      exit(*valid_status);
      break;
    }
    case SYS_WRITE:
    {
      int *valid_fd = (int*)valid_pointer((int*)(f->esp+4));
      int *valid_buffer = (int *)valid_pointer((int*)(f->esp+8));
      int *valid_length = (int *)valid_pointer((int*)(f->esp+12));
      f->eax = write(*valid_fd, (const void *)*valid_buffer, (unsigned)*valid_length);
      break;
    }
  }
}

void exit(int status)
{
  struct thread *curr_thread = thread_current();
  curr_thread->exit_status = status;
  thread_exit();
}

int write (int fd, const void *buffer, unsigned length)
{

  if (fd == 1) {
    putbuf(buffer, length);
    return length;
  }
  return -1;
}

void* valid_pointer(void *ptr) {
  if(!is_user_vaddr(ptr) || ptr == NULL || ptr < (void *) 0x08048000)
	{
    exit(-1);
	}
  return ptr;
}
