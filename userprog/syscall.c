#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include <stdbool.h>
typedef int pid_t;
void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	uint64_t *arg1 = (void *)f->R.rdi;
    uint64_t *arg2 = (void *)f->R.rsi;
    uint64_t *arg3 = (void *)f->R.rdx;
    uint64_t *arg4 = (void *)f->R.r10;
    uint64_t *arg5 = (void *)f->R.r8;
    uint64_t *arg6 = (void *)f->R.r9;
	

	switch (f->R.rax){
		if((f->cs & 0x3))

		case SYS_HALT:
			printf("SYS_HALT\n");
			f->R.rax = halt ();
			break;

		case SYS_EXIT:
			printf("SYS_EXIT\n");
			f->R.rax = exit (arg1);
			break;

		case SYS_FORK:
			printf("SYS_FORK\n");
			f->R.rax = fork (arg1);
			break;

		case SYS_EXEC:
			printf("SYS_EXEC\n");
			f->R.rax = exec (arg1);
			break;

		case SYS_WAIT:
			printf("SYS_WAIT\n");
			f->R.rax = wait (arg1);
			break;

		case SYS_CREATE:
			printf("SYS_CREATE\n");
			f->R.rax = create (arg1, arg2);
			break;

		case SYS_REMOVE:
			printf("SYS_REMOVE\n");
			f->R.rax = remove (arg1);
			break;

		case SYS_OPEN:
			printf("SYS_OPEN\n");
			f->R.rax = open (arg1);
			break;

		case SYS_FILESIZE:
			printf("SYS_FILESIZE\n");
			f->R.rax = filesize (arg1);
			break;

		case SYS_READ:
			printf("SYS_READ\n");
			f->R.rax = read (arg1, arg2, arg3);
			break;

		case SYS_WRITE:
			printf("SYS_WRITE\n");
			f->R.rax = write (arg1, arg2, arg3);
			break;

		case SYS_SEEK:
			printf("SYS_SEEK\n");
			f->R.rax = seek (arg1, arg2);
			break;

		case SYS_TELL:
			printf("SYS_TELL\n");
			f->R.rax = tell (arg1);
			break;

		case SYS_CLOSE:
			printf("SYS_CLOSE\n");
			f->R.rax = close (arg1);
			break;

		default:
			
			printf("default\n");
			break;

	}
	printf ("system call!\n");
	thread_exit ();
}

// void user_memory_vaild(uint64_t *r) {
// 	if (r != NULL && is_user_vaddr(r)){
// 		return;
// 	}
// 	return false;
// }

void halt (void){
	powar_off();
	return;
};

void exit (int status){
	thread_exit();
	return status;
};

pid_t fork (const char *thread_name){
	// return thread_create(thread_name, PRI_DEFAULT, dofork, ())
};

int exec (const char *file){

};

int wait (pid_t){

};

bool create (const char *file, unsigned initial_size){
	return filesys_create(file, initial_size);
};

bool remove (const char *file){
	return filesys_remove(file);
};

int open (const char *file){
	struct file *f = filesys_open(file);
	
};

int filesize (int fd){

};

int read (int fd, void *buffer, unsigned length){

};

int write (int fd, const void *buffer, unsigned length){

};

void seek (int fd, unsigned position){

};

unsigned tell (int fd){

};

void close (int fd){

};



