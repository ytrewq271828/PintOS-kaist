#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <string.h>
#include <list.h>
/*
void syscall_init (void);
void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void address_valid(void *vaddr);
void halt();
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
*/
struct lock filesys_lock;
/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);
}

/* 
Check whether the virtual address is valid
We should check the range of the address and if the mapped physical address exists.
*/
void
address_valid(void *vaddr)
{
	struct thread *current=thread_current();
	//for(;;);
	if(!is_user_vaddr(vaddr) || vaddr==NULL || pml4e_walk(current->pml4, vaddr, 0) == NULL)
	{
		exit(-1);
	}
}
/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	ready_list_iterate();
	struct thread *current=thread_current();
	current->tf.rsp=f->rsp; 		/* Syscall : change the context to the kernel */
	printf("%%%%%%%%%%%%%%\n");
	printf("%d\n", f->R.rax);
	switch(f->R.rax)
	{
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax=fork(f->R.rdi, f);
			break;
		case SYS_EXEC:
			//int exec_result=exec(f->R.rdi);
			if(exec(f->R.rdi)==-1)
			{
				exit(-1);
			}
			break;
		case SYS_WAIT:
			f->R.rax=wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax=create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax=remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax=open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax=filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax=read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax=write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi ,f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax=tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		default:
			//for(;;);
			exit(-1);
			break;
	}
	//thread_exit ();
}

void halt()
{
	power_off();
}

void exit(int status)
{
	struct thread *current=thread_current();
	current->exit_status=status;
	
	printf("%s: exit(%d)\n", current->name, status);
	thread_exit();
	
}

bool create(const char* file, unsigned initial_size)
{
	address_valid(file);
	return filesys_create(file, initial_size);
	
}

bool remove(const char *file)
{
	address_valid(file);
	return filesys_remove(file);
}

int open(const char *file)
{
	//for(;;);
	struct thread *current=thread_current();
	address_valid(file);
	struct file *open_file=filesys_open(file);
	if(open_file==NULL)
	{
		return -1;
	}
	struct file **fdt=current->descriptor_table;
	int idx=2;
	while(fdt[idx]!=NULL)
	{
		idx=idx+1;
		if(idx==fdt_limit)
		{
			idx=-1;
			break;	
		}
	}
	if(idx!=-1)
	{
		current->open_index=idx;
		fdt[idx]=open_file;
	}
	else
	{
		file_close(open_file);
	}
	return idx;
}

int filesize(int fd)
{
	struct thread *current=thread_current();
	if(fd<0)
	{
		return NULL;
	}
	if(fd>fdt_limit)
	{
		return NULL;
	}
	struct file **fdt=current->descriptor_table;
	if(fdt[fd]==NULL)
	{
		return -1;
	}
	return file_length(fdt[fd]);
}

int read(int fd, void *buffer, unsigned size)
{
	struct thread *current=thread_current();
	address_valid(buffer);
	char *buffer_read=NULL;
	unsigned read_len=0;
	if(fd<0)
	{
		return NULL;
	}
	if(fd>fdt_limit)
	{
		return NULL;
	}

	if(fd==0)
	{
		for(read_len=0;read_len<size;read_len++)
		{
			char c=input_getc();
			*buffer_read=c;
			if(c=='\0')
			{
				break;
			}
		}
	}

	if(fd==1)
	{
		return -1;
	}

	if(fd>=2)
	{
		lock_acquire(&filesys_lock);
		struct file *file_to_read=current->descriptor_table[fd];
		if(file_to_read==NULL)
		{
			return -1;
		}
		read_len=file_read(file_to_read, buffer, size);
		lock_release(&filesys_lock);
	}
	return read_len;
}

int write(int fd, void *buffer, unsigned size)
{
	struct thread *current=thread_current();
	printf("%%%%%%%%%%%%%%%%%%%%");
	//for(;;);
	address_valid(buffer);
	int write_len=0;
	struct file *file_to_write=current->descriptor_table[fd];
	if(file_to_write==NULL)
		{
			return -1;
		}
	if(fd<0)
	{
		return NULL;
	}
	if(fd>=fdt_limit)
	{
		return NULL;
	}
	if(fd==1)
	{
		putbuf(buffer, size);
		return size;
	}

	if(fd==0)
	{
		return -1;
	}

	if(fd>=2)
	{
		lock_acquire(&filesys_lock);
		//struct file *file_to_write=current->descriptor_table[fd];
		
		write_len=file_write(file_to_write, buffer, size);
		lock_release(&filesys_lock);
		return write_len;
	}
}
void seek(int fd, unsigned position)
{
	struct thread *current=thread_current();
	if(fd<0)
	{
		return NULL;
	}
	if(fd>fdt_limit)
	{
		return NULL;
	}
	if(fd==0)
	{
		return;
	}
	if(fd==1)
	{
		return;
	}
	if(fd>=2)
	{
		struct file *file_to_seek=current->descriptor_table[fd];
		if(file_to_seek==NULL)
		{
			return;
		}
		address_valid(file_to_seek);
		file_seek(file_to_seek, position);

	}
}

unsigned tell(int fd)
{
	struct thread *current=thread_current();
	if(fd<0)
	{
		return NULL;
	}
	if(fd>fdt_limit)
	{
		return NULL;
	}
	if(fd==0)
	{
		return;
	}
	if(fd==1)
	{
		return;
	}
	if(fd>=2)
	{
		struct file *file_to_tell=current->descriptor_table[fd];
		if(file_to_tell==NULL)
		{
			return;
		}
		address_valid(file_to_tell);
		return file_tell(file_to_tell);
	}
}

void close(int fd)
{
	struct thread *current=thread_current();
	printf("%d", current->exit_status);
	if(fd<0)
	{
		return NULL;
	}
	if(fd>fdt_limit)
	{
		return NULL;
	}
	if(fd==0 || fd==1)
	{
		return;
	}
	
	void * file_to_close=current->descriptor_table[fd];
	ASSERT(file_to_close==NULL);
	//barrier();
	if(file_to_close==NULL)
	{
		return;
	}
	printf("Readhere");
	address_valid(file_to_close);
	current->descriptor_table[fd]=NULL;
	file_close(file_to_close);

}

int exec(char *file_name)
{
	
	address_valid(file_name);
	char *file_name_copy=palloc_get_page(PAL_ZERO);
	if(file_name_copy==NULL)
	{
		exit(-1);
	}
	memcpy(file_name_copy, file_name, strlen(file_name)+1);

	int exec_result=process_exec(file_name_copy);
	if(exec_result==-1)
	{
		return -1;
	}
	return 0;
}

int wait(tid_t pid)
{
	return process_wait(pid);
}

tid_t fork(const char *thread_to_fork, struct intr_frame *f)
{
	return process_fork(thread_to_fork, f);
}