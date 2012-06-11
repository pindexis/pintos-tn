#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/file.h"
typedef int pid_t;

enum process_status{
PROCESS_RUNNING,
PROCESS_ZOMBIE,
PROCESS_ORPHAN,
PROCESS_DIED,
};
 
struct user_process{ 
	char prog_name[60];
	pid_t pid;//equal to thread tid (non multithread_environment), needed to handle process operation even when the thread is erased from memory(wait for example can be used even when the thread is freed)
	struct thread *p_thread;
	struct list children;
	struct list_elem child_elem;//for children list
	int exit_status;			
	struct semaphore exit_sema;
	enum process_status status;
	struct list open_descs;
};

struct file_desc{
int fd;
struct list_elem elem;
struct file *file;
};
pid_t process_execute (const char *file_name);
int process_wait (pid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
