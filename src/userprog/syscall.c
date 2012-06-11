#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"//PHYS_BASE
#include "threads/malloc.h" //malloc
#include "filesys/filesys.h" //filesys_create,filesys_remove
#include "filesys/file.h" //file_read,file_write
#include "devices/shutdown.h"//shutdown
#include "devices/input.h" //input_getc
 
static void syscall_handler (struct intr_frame *);
static void verify_boundary(uint32_t *sp,uint32_t argnum);
static bool valid_string(char * str);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static void halt(void);
int program_exit(int status);
static int exec(const char *cmd_line);
static int wait(pid_t pid);
static bool create (const char *file, unsigned initial_size) ;
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);
struct file_desc * get_file_desc(int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

	static void
syscall_handler (struct intr_frame *f) 
{
	uint32_t *esp=f->esp;
	//make sure esp is below PHYS_BASE

	verify_boundary(esp,1);	
	if (get_user (esp) == -1)
		program_exit(-1);

	uint32_t sysnum=*esp;
	switch(sysnum)
	{
		case SYS_HALT:
			{
				halt();
				break;
			}
		case SYS_EXIT:
			{
				verify_boundary(esp,2);		
				program_exit((int)(*(esp+1)));
				break;
			}
		case SYS_EXEC:
			{
				verify_boundary(esp,2);		
				char *arg1=(char *)(*(esp+1));
				if(valid_string(arg1))
					f->eax = exec(arg1);
				else
					program_exit(-1);
				break;
			}
		case SYS_WAIT:
			{
				verify_boundary(esp,2);		
				pid_t arg1=(pid_t)(*(esp+1));
				f->eax = wait(arg1) ;
				break;
			}
		case SYS_CREATE:
			{
				verify_boundary(esp,3);		
				char *arg1=(char *)(*(esp+1));
				unsigned arg2=(unsigned)(*(esp+2));
				if(!valid_string(arg1))	
				program_exit(-1);
				f->eax = create (arg1, arg2);
				break;
			}
		case SYS_REMOVE:
			{
				verify_boundary(esp,2);		
				char *arg1=(char *)(*(esp+1));
				if(!valid_string(arg1))	
				program_exit(-1);
				f->eax = remove (arg1);
				break;
			}
		case SYS_OPEN:
			{
				verify_boundary(esp,2);		
				char *arg1=(char *)(*(esp+1));
				if(!valid_string(arg1))	
				program_exit(-1);
				f->eax = open (arg1);
				break;
			}
		case SYS_FILESIZE:
			{
				verify_boundary(esp,2);		
				int arg1=(int)(*(esp+1));
				f->eax = filesize(arg1);
				break;
			}
		case SYS_READ:
			{
				verify_boundary(esp,4);		
				int arg1=(int)(*(esp+1));
				void *arg2=(void *)(*(esp+2));
				unsigned arg3=(unsigned)(*(esp+3));
				f->eax = read(arg1, arg2, arg3);
				break;
			}
		case SYS_WRITE:
			{
				verify_boundary(esp,4);		
				int arg1=(int)(*(esp+1));
				void *arg2=(void *)(*(esp+2));
				unsigned arg3=(unsigned)(*(esp+3));
				if(!valid_string(arg2))	
				program_exit(-1);
				f->eax = write (arg1, arg2, arg3);
				break;
			}
		case SYS_SEEK:
			{
				verify_boundary(esp,3);		
				int arg1=(int)(*(esp+1));
				unsigned arg2=(unsigned)(*(esp+2));
				 seek (arg1, arg2);
				break;
			}
		case SYS_TELL:
			{
				verify_boundary(esp,2);		
				int arg1=(int)(*(esp+1));
				f->eax = tell (arg1);
				break;
			}
		case SYS_CLOSE:
			{
				verify_boundary(esp,2);		
				int arg1=(int)(*(esp+1));
				close(arg1);
				break;
			}

	}


}


static void verify_boundary(uint32_t *sp,uint32_t argsize)
{
	if( (sp+argsize) >= (uint32_t *)PHYS_BASE)
		program_exit(-1);	
}
static bool valid_string(char * str)
{
int ch=-1;
while(str<(char*)PHYS_BASE && (ch=get_user((uint8_t*)str++))!='\0' && ch!=-1);
if(ch=='\0')
return true;
else
return false;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
	static int
get_user (const uint8_t *uaddr)
{
	int result;
	asm ("movl $1f, %0; movzbl %1, %0; 1:"
			: "=&a" (result) : "m" (*uaddr));
	return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
	static bool
put_user (uint8_t *udst, uint8_t byte)
{
	int error_code;
	asm ("movl $1f, %0; movb %b2, %1; 1:"
			: "=&a" (error_code), "=m" (*udst) : "q" (byte));
	return error_code != -1;
}


static void halt()
{
   shutdown_power_off();
}

int program_exit(int status)
{
	ASSERT(thread_current()->process!=NULL)
	thread_current()->process->exit_status=status;
	printf ("%s: exit(%d)\n", thread_current()->process->prog_name,status);
	thread_exit();
}
static int exec(const char *cmd_line)
{	
	return process_execute (cmd_line);
}
static int wait(pid_t pid)
{
return process_wait(pid);	
}
static bool create (const char *file, unsigned initial_size) 
{
return filesys_create(file,initial_size);
}
static bool remove (const char *file) 
{
return filesys_remove(file);
}
static int open (const char *filename)
{
	struct file *file = filesys_open (filename);
          if (file == NULL)
             return -1;
	
	struct list *process_fdlist=&thread_current()->process->open_descs;

          struct file_desc *desc= (struct file_desc *)
                                     malloc (sizeof (struct file_desc));

          int fd=2;
	struct list_elem *e=list_begin(process_fdlist);
	while(e!=list_end(process_fdlist))
		{
		if(fd!=(list_entry(e,struct file_desc,elem))->fd)
			break;
		fd++;
		e=list_next(e);
		}	
	desc->fd=fd;
	desc->file=file;	
	list_insert(e,&desc->elem);
	return fd;

}
static int filesize (int fd)
{
	return file_length(get_file_desc(fd)->file);
}
static int read (int fd, void *buffer, unsigned size)
{
	char * ubuffer=(char *)buffer;
	uint32_t count=0;
	if (fd == 0)
	{
		while (count < size)
		{
			uint8_t ch = input_getc ();
			if (ch == '\n')
				break;
			if(!put_user ((uint8_t *)(ubuffer + count), ch))
				break;
			count++;
		}
		return count;
	}
	
	struct file_desc * filedesc=get_file_desc(fd);
	count=file_read(filedesc->file,buffer,size);
	return count;

}
static int write (int fd, const void *buffer, unsigned size)
{
if(size<=0)
return 0;
if(fd==1)
{
 putbuf (buffer, size);
 return size;
}
return file_write(get_file_desc(fd)->file,buffer,size);

}
static void seek (int fd, unsigned position)
{
struct file_desc *desc=get_file_desc(fd);
 file_seek (desc->file, position);
}
static unsigned tell (int fd)
{
                 return file_tell (get_file_desc(fd)->file);

}
static void close (int fd)
{
struct file_desc * desc=get_file_desc(fd);
list_remove(&desc->elem);
}

struct file_desc * get_file_desc(int fd)
{
	struct list *fd_list=&thread_current()->process->open_descs;
 	struct list_elem *e;
          for (e = list_begin (fd_list); e != list_end (fd_list); 
               e = list_next (e))
            {   
              struct file_desc *i_desc = list_entry (e, struct file_desc, elem);
              if ((i_desc->fd == fd)) 
                 return i_desc;
            }
	  program_exit(-1);
	  return NULL;
}
