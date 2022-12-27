#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "userprog/syscall.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;
	
	//for(;;);
	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	/* Parsing the file name only - call strtok_r just once */
	char* file_name_token;
	char *save_ptr;
	strtok_r(file_name, " ", &save_ptr);
	
	
	/* Create a new thread to execute FILE_NAME. */
	//tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	//tid=thread_create(fn_copy, PRI_DEFAULT, initd, file_name);
	
	tid=thread_create(file_name, PRI_DEFAULT, initd, fn_copy);
	//tid=thread_create(file_name, PRI_DEFAULT, initd, file_name);
	if (tid == TID_ERROR)
	{
		palloc_free_page (fn_copy);
	}	
	//palloc_free_page(file_name);
	/* tid is not equal to TID_ERROR */
	//ASSERT(tid==-1);
	printf("%d\n", tid);
	//printf("%d\n", thread_current()->exit_status);
	printf("##############\n");
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();
	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	//for(;;);
	/* Clone current thread to new thread.*/
	struct thread *current=thread_current();
	//struct thread *current=thread_current();
	//for(;;);
	memcpy(&current->parent_intr_frame, if_, sizeof(struct intr_frame));
	tid_t pid= thread_create (name,
			PRI_DEFAULT, __do_fork, current);
	if(pid==TID_ERROR)
	{
		//for(;;);
		return TID_ERROR;
	}
	//for(;;);
	//struct list_elem *elem;
	//struct thread *child=NULL;
	//struct thread *currentt=thread_current();
	struct thread *child=find_child(current, pid);
	//if(child!=NULL)
	//{
		//for(;;);
		sema_down(&child->fork_sema);
		if(child->exit_status==-1)
		{
			//for(;;);
			return TID_ERROR;
		}
		return pid;
	//}
	//else
	//{
//		for(;;);
//		return TID_ERROR;
//	}
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
/* pte : page table entry of parent's address sapce*/
/* va : virtual address of the parent's page */
/* */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if(is_kernel_vaddr(va))
	{
		return true;
	}
	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);
	if(parent_page==NULL)
	{
		return false;
	}
	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage=palloc_get_page(PAL_USER);
	if(newpage==NULL)
	{
		return false;
	}
	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	writable=is_writable(pte);
	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if;
	parent_if=&parent->parent_intr_frame;
	bool succ = true;
	//for(;;);
	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	if_.R.rax=0;
	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	
	/* Case of multiple file opened => if the open index is same with limit then TID_ERROR */
	if(parent->open_index==fdt_limit)
	{
		//for(;;);
		current->exit_status=TID_ERROR;
		sema_up(&current->fork_sema);
		exit(TID_ERROR);
	}

	/* Index 0 and 1 of FDT - just copy it */
	current->descriptor_table[0]=parent->descriptor_table[0];
	current->descriptor_table[1]=parent->descriptor_table[1];

	/* Index over 2 of parent's FDT - copy using file_duplicate */
	/* We need to consider the case where the descriptor table points to null file */
	int i=2;
	while(i<fdt_limit)
	{
		struct file *file=parent->descriptor_table[i];
		//for(;;);
		if(file==NULL)
		{
			printf("%d\n", i);
			i=i+1;
			continue;
		}
		current->descriptor_table[i]=file_duplicate(file);
		i=i+1;
	}
	/* Open index : currently opened file's index in FDT */
	current->open_index=parent->open_index;
	/* Return value of child process */
	//if_.R.rax=0;
	sema_up(&current->fork_sema);
	//process_init ();

	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);
error:
	//for(;;);
	current->exit_status=TID_ERROR;
	sema_up(&current->fork_sema);
	exit(TID_ERROR);
	//thread_exit ();
}

/*
2.1. Argument Passing 
This function tokenizes the command line - into command and arguments
*/
void command_tokenize(char **argv, int argc, void* rsp_copy)
{
   //char *len_pointer;					/* Pointer to determine the number of arguments */
   //int space_flag=1; 					/* Flag to check the space in the command line */
   //char *token;							/* Pointer to reference each tokens in command line */
   //char *save_ptr1;						/* Pointer to keep track of the token's position*/
   //char *save_ptr2;
   //void *argv_start; 					/* The starting address of argument values in the memory - not the address value but argument value */
   //char *argv_temp[32];
   char *argv_address_temp[32];
   //char **argv_address_stack;
   //void *stack_start=USER_STACK;		/* The beginning address of the stack*/
   //int argc=0; 							/* The number of arguments*/
   //int arg_index=0;
   //int arg_size=0;
   int argv_len=0;
   //int *current; 						/* Pointer to keep track of currently referenced address */
   //int *argv_last;
   uint8_t word_align_len=0;
   //int argv_flag=0; 					/* Flag to discriminate arguemnts and command */
	
   for(int i=0;i<argc;i++)
   {
		/* Iterating backwards*/
		//char argument=argv[(argc-i-1)];
		int arg_size=strlen(argv[argc-i-1]);
		//memmove(rsp-arg_size, rsp, stack_size);
		rsp_copy=rsp_copy-(arg_size+1);
		//void *rspp=(void *)if_->rsp;
		memcpy(rsp_copy, argv[argc-i-1], (arg_size+1));
		argv_address_temp[(argc-i-1)]=rsp_copy;
		argv_len=argv_len+(arg_size+1);
   }
   //for(;;);
   /* word-align check : increment while stack size is not a multiple of 8 */
   while((uint8_t)rsp_copy%8!=0)
   {
		word_align_len+=1;
		//stack_size+=1;	
		rsp_copy=rsp_copy-1;
		*(uint8_t *)rsp_copy=(uint8_t)0;
		//memset(rsp, 0, 1);
   }
   rsp_copy=rsp_copy-8;
   memset(rsp_copy, 0, 8);

   /* Allocating stack space for address data*/
   for(int i=0;i<argc;i++)
   {
		rsp_copy=rsp_copy-8;
		//char* argument=argv[(argc-i-1)];
		memcpy(rsp_copy, &argv_address_temp[(argc-i-1)], 8);
		//memset(rsp, &argv_address_temp[argc-i-1], 8);
		//stack_size+=8;
   }
   /* Fake return address */
   rsp_copy=rsp_copy-8;
   memset(rsp_copy, 0, 8);
   //free(argv_temp);
   //return argc;
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */

int
process_exec (void *f_name) {
	struct thread *current=thread_current();
	char *file_name=f_name;
	char file_name_copy[128];
	bool success;
	memcpy(file_name_copy, file_name, strlen(file_name)+1); 

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	//memset(&_if,0, sizeof(_if));
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();

	success=load(file_name, &_if);
	
	printf("$$$$$$$$$$$$$$$\n");
	printf("%d\n", success);
	palloc_free_page (file_name);
	/* If load failed, quit. */
	if(!success)
	{
		exit(-1);
	}
	// Maybe &_if can be wrong
	// struct thread *current=thread_current();
	hex_dump(_if.rsp, _if.rsp, USER_STACK-_if.rsp,true);
	printf("%s\n", current->name);
	do_iret (&_if);
	NOT_REACHED ();
}

struct thread* find_child(struct thread *current, tid_t tid)
{
	//struct thread *current=thread_current();
	struct list_elem *e;
	for(e=list_begin(&current->child_list);e!=list_end(&current->child_list);e=list_next(e))
	{
		
		struct thread *child_thread=list_entry(e, struct thread, child_elem);
		
		if(child_thread->tid==tid)
		{
			return child_thread;
		}
	}
	return NULL;
}
/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */


/* Thread of tid 3 : executes userprog thread */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	
	struct thread *current=thread_current();
	printf("%s\n\n", current->name);
	struct list_elem *e;
	//int flag=0;
	//ASSERT(!list_empty(&current->child_list));
	struct thread *child_thread=find_child(current, child_tid);
	if(child_thread==NULL)
	{
		return -1;
	}
	printf("%s**\n", child_thread->name); //args-single
	//if(flag==0)
	//{
	//	return -1;
	//}
	//if(flag==1 && child_thread!=NULL)
	//{
		//
	
	//printf("%d\n", child_thread->exit_status);
	//printf("%d\n", child_thread->tid);
	//ready_list_iterate();
	//printf("----------------------\n");
	sema_down(&child_thread->wait_sema);
	int child_exit_status=child_thread->exit_status;
	//ready_list_iterate();
	printf("%d\n", child_exit_status);
	printf("%d\n", child_thread->tid);
	list_remove(&child_thread->child_elem);
	sema_up(&child_thread->exit_sema);
	//ASSERT(child_exit_status!=-1);
	return child_exit_status;
	//}
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	printf("%d", curr->exit_status);
	printf("%s&&", curr->name);
	printf("@@@@@@@@@@@@\n");
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	for(int i=0;i<fdt_limit;i++)
	{
		//printf("%d\n", i);fail
		//printf("!!!!!!!!");
		close(i);
	}
	//printf("%d\n", curr->exit_status);
	palloc_free_multiple(curr->descriptor_table, 3);
	file_close(curr->running_executable);
	process_cleanup ();
	printf("^^^^^^^^^^^^^^^\n");
	printf("%d\n", curr->exit_status);
	sema_up(&curr->wait_sema);
	sema_down(&curr->exit_sema);
	
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR
static bool setup_stack(struct intr_frame *if_);
//static bool setup_stack (struct intr_frame *if_, int e_phnum);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	char *token;
	char *argv_cut;
	char *save_ptr1;
	int arg_index=0;
	char* argv_temp[32];
	int argc=0;
	int argv_len=0;
	//for(;;);
	token = strtok_r (file_name, " ", &save_ptr1);
    //memcpy(argv_cut, token, strlen(token)+1);
    
	//command_tokenize(argv_temp, argc, if_->rsp, if_);
	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());
	printf("%s\n", t->name);
	file = filesys_open(token);

	if (file == NULL) {
		//lock_release(&t->open_lock);
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}
	t->running_executable=file;
	file_deny_write(file);
	//lock_release(&t->open_lock);

	
	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}
	
	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	//printf("%d\n", ehdr.e_phnum);
	for (i = 0; i < ehdr.e_phnum; i++) {
		
		struct Phdr phdr;
		//printf("%d\n", i);
		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;	
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
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
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					
					
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
									//Fails here
							goto done;
				}
				else
						goto done;
				break;
		}
	}
	
	/* Set up stack. */
	//if (!setup_stack (if_, ehdr.e_phnum))
	if(!setup_stack(if_))	
		goto done;
	
	/* Start address. */
	if_->rip = ehdr.e_entry;
	//for(;;);
	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */
	argv_temp[arg_index]=token;
	arg_index=arg_index+1;
	argv_len=argv_len+(strlen(token)+1);
	ASSERT(strlen(token)!=0);
	//memcpy(argv_cut, token, strlen(token)+1);
	while(token!=NULL) 
    //( token != NULL; token = strtok_r (NULL, " ", &save_ptr1))
    {
		token = strtok_r (NULL, " ", &save_ptr1);
		argv_temp[arg_index]=token;
		arg_index=arg_index+1;
		
    }
    argc=arg_index-1;

	//void **rsp_copy=&if_->rsp;
	command_tokenize(argv_temp, argc, if_->rsp);
	
	if_->R.rdi=argc;
	if_->R.rsi=if_->rsp+8;
	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	file_close (file);
	//for(;;);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
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

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	//uint8_t *upagee;
	//upagee=upage;

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;
		//printf("Load SEgment\n");
		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;
		
		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);
		
		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			//for(;;);
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}
		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		
		upage += PGSIZE;
		
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */

static bool setup_stack(struct intr_frame *if_)
{
	uint8_t *kpage;
	bool success=false;

	kpage=palloc_get_page(PAL_USER | PAL_ZERO);
	if (kpage!=NULL)
	{
		success=install_page (((uint8_t *)USER_STACK)-PGSIZE, kpage, true);	
		if(success)
			if_->rsp=USER_STACK;
		else
			palloc_free_page(kpage);
	}
	return success;
}

/*
static bool
setup_stack (struct intr_frame *if_, int e_phnum) {
	
	uint8_t *kpage;
	bool success = false;
	//kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	for(int i=0;i<e_phnum;i++)
	{
		kpage=palloc_get_page(PAL_USER | PAL_ZERO);
		if (kpage != NULL) {
			success = install_page (((uint8_t *) USER_STACK) - PGSIZE * (i+1), kpage, true);
			if (!success)
			{
				palloc_free_page (kpage);
				return success;
			}
		}
	}
	if_->rsp = USER_STACK;
			
	return success;
}
*/
/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();
	
	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
/*
static int64_t
get_user (const uint8_t *uaddr)
{
	int64_t result;
	__asm __volatile(
		"movabsq $done_get, %0\n"
		"movzbq %1, %0\n"
		"done_get:\n"
		: "=&a" (result) : "m" (*uaddr));
		return result;
}

static bool
put_user(uint8_t *udst, uint8_t byte) {
	int64_t error_code;
	__asm __volatile (
		"movabsq $done_put, %0\n"
		"movb %b2, %1\n"
		"done_put:\n"
		: "=&a" (error_code), "=m" (*udst) : "q" (byte));
		return error_code != -1;
	
}
*/
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
