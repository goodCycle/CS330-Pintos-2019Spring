#include <stdio.h>

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

//
void* valid_pointer(void *ptr);
void exit (int status);
int write (int fd, const void *buffer, unsigned length);

#endif /* userprog/syscall.h */
