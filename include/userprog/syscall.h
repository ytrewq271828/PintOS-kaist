#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#endif /* userprog/syscall.h */

#include <stdbool.h>
#include "threads/thread.h"

#define fdt_limit  3 * (1<<9)

void syscall_init (void);
void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void address_valid(void *vaddr);
void halt(void);
void exit(int status);
tid_t fork(const char *thread_name, struct intr_frame *f);
int exec(char *file_name);
int wait(int pid);
bool create(const char* file, unsigned initial_size);
bool remove(const char *file);
int open(const char* file);
int filesize(int fd);
int read(int fd, void* buffer, unsigned size);
int write(int fd, void* buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
