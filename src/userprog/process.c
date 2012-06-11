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
#include "threads/malloc.h"
#define MAXARGS 30
 
struct command{
	int argc;
	char* argv[MAXARGS];
	};
static bool parsecommand(char * cmd_string,struct command *cmd);	
static void init_process(char * prog_name,struct user_process* parent_process);

	
static thread_func start_process NO_RETURN;
static bool load (struct command* cmd, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  

  struct semaphore load_sema;
  sema_init(&load_sema,0);
  bool load_success;
  
  uint32_t* args[4];
  *args=fn_copy;
  *(args+1)=&load_sema;//parent should wait to see if loading was successeful or not
  *(args+2)=&load_success; 
  *(args+3)=thread_current()->process;//every child has link to its parent in order to signal him when terminated 
  
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, args);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
   sema_down(&load_sema);
  if(!load_success)
  {
	  palloc_free_page (fn_copy); 
	  return -1;
  } 
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *parms)
{
	bool success=false;
	struct intr_frame if_;
	
	char *file_name = *(char **)parms;
	struct semaphore* load_sem=(struct semaphore *)(*((uint32_t*)parms+1));
        bool *load_status=(bool *)(*((uint32_t*)parms+2));
   
   
    struct command cmd;
  if(parsecommand(file_name,&cmd))
  {	  init_process(cmd.argv[0],(struct user_process *)(*((uint32_t*)parms+3)));

  	/* Initialize interrupt frame and load executable. */
  	memset (&if_, 0, sizeof if_);
  	if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  	if_.cs = SEL_UCSEG;
  	if_.eflags = FLAG_IF | FLAG_MBS;
  	success = load (&cmd, &if_.eip, &if_.esp);
   }
   *load_status=success;
   sema_up(load_sem);
  /* If load failed, quit. */
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

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
 	struct user_process * process=thread_current()->process;

	if(process==NULL)//call from kernel thread
	{
	/* i do not handle kernel threads as processes because pintos kernel is multithreaded while user programs are monthreaded (handling every thread as a process is not a great idea), so process operations are valid only for user programs until i add support for multithreaded process, however, there is an adjustment that need to be done, when the initial thread invoke a user program, he need to wait for this process to terminate in order to shutdown pintos.(see init.c:288)*/
	//silly turnarround to solve the problem
		if(thread_current()->tid==1)
		{
			struct thread *t=thread_get_by_tid(child_tid);
			if(t!=NULL && t->process!=NULL)
			{
				sema_down(&t->process->exit_sema);
				t->process->status=PROCESS_DIED;
				int exit_status=t->process->exit_status;
				free(t->process);
				return exit_status;
			}
		}
		return -1;

	}
	struct list_elem *e;
	struct user_process *child_process=NULL;
	for (e = list_begin (&process->children); e != list_end (&process->children);
			e = list_next (e))
	{
		struct user_process *p = list_entry (e, struct user_process, child_elem);
		if(p->pid==child_tid)	
		{
			child_process=p;
			break;
		}
	}

	if(child_process==NULL )
		return -1;
	if(child_process->status==PROCESS_RUNNING)
		sema_down(&child_process->exit_sema);			

	list_remove(&child_process->child_elem);
	child_process->status=PROCESS_DIED;
	int exit_status=child_process->exit_status;		
	free(child_process);
	return exit_status;
}

/* Free the current process's resources. */
	void
process_exit (void)
{
	struct thread *cur = thread_current ();
	uint32_t *pd;

	cur->process->status=PROCESS_ZOMBIE;

	struct list_elem *e;
	for (e = list_begin (&cur->process->children); e != list_end (&cur->process->children);
			e = list_next (e))
	{
		struct user_process *p = list_entry (e, struct user_process, child_elem);
		list_remove(&p->child_elem);
		p->status=PROCESS_ORPHAN;
		//link child process to init
	}	

	e = list_begin (&cur->process->open_descs);

	while (!list_empty (&cur->process->open_descs))
	{
		struct file_desc *file_d = list_entry (e, struct file_desc, elem);
		file_close (file_d->file);
		e = list_remove (e);
		free (file_d);
	}
	struct semaphore * ex_sema=&cur->process->exit_sema;
	sema_up(ex_sema);

	/* Destroy the current process's page directory and switch back
	   to the kernel-only page directory. */
	pd = cur->pagedir;
	if (pd != NULL) 
	{
		/* Correct ordering here is crucial.  We must set
		   cur->pagedir to NULL before switching page directories,
		   so that a timer interrupt can't switch back to the
		   process page directory.  We must activate the base page
		   directory before destroying the process's page
		   directory, or our active page directory will be one
		   that's been freed (and cleared). */
		cur->pagedir = NULL;
		pagedir_activate (NULL);
		pagedir_destroy (pd);
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

static bool setup_stack (void **esp,struct command *cmd);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
	bool
load (struct command* cmd, void (**eip) (void), void **esp) 
{
	struct thread *t = thread_current ();
	struct Elf32_Ehdr ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pagedir = pagedir_create ();
	if (t->pagedir == NULL) 
		goto done;
	process_activate ();

	/* Open executable file. */
	file = filesys_open (cmd->argv[0]);
	if (file == NULL) 
	{
		printf ("load: %s: open failed\n", cmd->argv[0]);
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
		printf ("load: %s: error loading executable\n", cmd->argv[0]);
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
				if(phdr.p_vaddr==0)
					continue; 
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
	if (!setup_stack (esp,cmd))
		goto done;

	/* Start address. */
	*eip = (void (*) (void)) ehdr.e_entry;

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	file_close (file);
	return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

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
		/* Calculate how to fill this page.
		   We will read PAGE_READ_BYTES bytes from FILE
		   and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
		{
			palloc_free_page (kpage);
			return false; 
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) 
		{
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

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
	static bool
setup_stack (void **esp,struct command *cmd) 
{
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) 
	{
		success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
		if (success)
		{  *esp = PHYS_BASE;
			int i=cmd->argc;
			uint32_t * arr[cmd->argc];
			while(--i>=0)
			{
				*esp=*esp-(strlen(cmd->argv[i])+1)*sizeof(char);
				arr[i]=(uint32_t *)*esp;
				memcpy(*esp,cmd->argv[i],strlen(cmd->argv[i])+1);
			}
			*esp=*esp-4;
			(*(int *)(*esp))=0;//sentinel
			i=cmd->argc;
			while(--i>=0)
			{
				*esp=*esp-4;//32bit
				(*(uint32_t **)(*esp))=arr[i];
			}
			*esp=*esp-4;
			(*(uintptr_t  **)(*esp))=(*esp+4);
			*esp=*esp-4;
			*(int *)(*esp)=cmd->argc;
			*esp=*esp-4;
			(*(int *)(*esp))=0;
		}
		else
			palloc_free_page (kpage);
	}
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
	static bool
install_page (void *upage, void *kpage, bool writable)
{
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	   address, then map our page there. */
	return (pagedir_get_page (t->pagedir, upage) == NULL
			&& pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/*
   function to parse the command line
   beware the argument cmd_string will be modified
   return false if there is an error
 */
	static bool
parsecommand(char * cmd_string,struct command *cmd)
{
	ASSERT(cmd_string!=NULL);
	ASSERT(cmd!=NULL);

	cmd->argc=0;

	char *token,*save_ptr;

	token=strtok_r(cmd_string," ",&save_ptr);
	while(token!=NULL)
	{
		cmd->argv[cmd->argc]=token;	
		cmd->argc++;
		if(cmd->argc==MAXARGS)
			return false;
		token=strtok_r(NULL," ",&save_ptr);
	}

	if(cmd->argc==0)//empty string
		return false;


	return true;
}
static void init_process(char * prog_name,struct user_process* parent_process)
{
	struct user_process *process=(struct user_process*)malloc(sizeof(struct user_process));
	strlcpy(process->prog_name,prog_name,strlen(prog_name)+1);
	process->p_thread=thread_current();
	process->pid=thread_current()->tid;
	process->status=PROCESS_RUNNING;
	sema_init(&process->exit_sema,0);
	list_init(&process->children);
	list_init(&process->open_descs);
	thread_current()->process=process;
	if(parent_process!=NULL)
		list_push_back(&parent_process->children,&process->child_elem);
}
