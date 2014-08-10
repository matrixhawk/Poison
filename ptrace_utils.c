/*
 * ptrace_utils.c
 *
 *  Created on: 2013-6-26
 *      Author: boyliang
 */

#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <cutils/sockets.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>

#include "ptrace_utils.h"
#include "log.h"

/**
 * read registers' status
 */
int ptrace_getregs(pid_t pid, struct pt_regs* regs) {
	if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
		perror("ptrace_getregs: Can not get register values");
		return -1;
	}

	return 0;
}

/**
 * set registers' status
 */
int ptrace_setregs(pid_t pid, struct pt_regs* regs) {
	if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
		perror("ptrace_setregs: Can not set register values");
		return -1;
	}

	return 0;
}

static void* connect_to_zygote(void* arg){
	int s, len;
	struct sockaddr_un remote;

	LOGI("[+] wait 2s...");
	sleep(2);

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) != -1) {
		remote.sun_family = AF_UNIX;
		strcpy(remote.sun_path, "/dev/socket/zygote");
		len = strlen(remote.sun_path) + sizeof(remote.sun_family);
		LOGI("[+] start to connect zygote socket");
		connect(s, (struct sockaddr *) &remote, len);
		LOGI("[+] close socket");
		close(s);
	}

	return NULL ;
}

/**
 * attach to target process
 */
int ptrace_attach(pid_t pid, int zygote) {
	if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
		LOGE("ptrace_attach");
		return -1;
	}

	waitpid(pid, NULL, WUNTRACED);

	/*
	 * Restarts  the stopped child as for PTRACE_CONT, but arranges for
	 * the child to be stopped at the next entry to or exit from a sys‐
	 * tem  call,  or  after execution of a single instruction, respec‐
	 * tively.
	 */
	if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) < 0) {
		LOGE("ptrace_syscall");
		return -1;
	}

	waitpid(pid, NULL, WUNTRACED);

	if (zygote) {
		connect_to_zygote(NULL);
	}

	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL ) < 0) {
		LOGE("ptrace_syscall");
		return -1;
	}

	waitpid(pid, NULL, WUNTRACED);

	return 0;
}

/**
 * detach from target process
 */
int ptrace_detach( pid_t pid )
{
    if ( ptrace( PTRACE_DETACH, pid, NULL, 0 ) < 0 )
    {
    	LOGE( "ptrace_detach" );
        return -1;
    }

    return 0;
}
int ptrace_continue(pid_t pid) {
	if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
		LOGE("ptrace_cont");
		return -1;
	}

	return 0;
}

int ptrace_syscall(pid_t pid) {
	return ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
}

/**
 * write data to dest
 */
int ptrace_write(pid_t pid, uint8_t *dest, uint8_t *data, size_t size) {
	uint32_t i, j, remain;
	uint8_t *laddr;

	union u {
		long val;
		char chars[sizeof(long)];
	} d;

	j = size / 4;
	remain = size % 4;

	laddr = data;

	for (i = 0; i < j; i++) {
		memcpy(d.chars, laddr, 4);
		ptrace(PTRACE_POKETEXT, pid, (void *)dest, (void *)d.val);

		dest += 4;
		laddr += 4;
	}

	if (remain > 0) {
		d.val = ptrace(PTRACE_PEEKTEXT, pid, (void *)dest, NULL);
		for (i = 0; i < remain; i++) {
			d.chars[i] = *laddr++;
		}

		ptrace(PTRACE_POKETEXT, pid, (void *)dest, (void *)d.val);

	}

	return 0;
}

int ptrace_read( pid_t pid,  uint8_t *src, uint8_t *buf, size_t size )
{
    uint32_t i, j, remain;
    uint8_t *laddr;

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4;

    laddr = buf;

    for ( i = 0; i < j; i ++ )
    {
        d.val = ptrace( PTRACE_PEEKTEXT, pid, src, 0 );
        memcpy( laddr, d.chars, 4 );
        src += 4;
        laddr += 4;
    }

    if ( remain > 0 )
    {
        d.val = ptrace( PTRACE_PEEKTEXT, pid, src, 0 );
        memcpy( laddr, d.chars, remain );
    }

    return 0;
}

int ptrace_call(pid_t pid, uint32_t addr, long *params, int num_params, struct pt_regs* regs) {
	uint32_t i;

	for (i = 0; i < num_params && i < 4; i++) {
		regs->uregs[i] = params[i];
	}

	if (i < num_params) {
		regs->ARM_sp-= (num_params - i) * sizeof(long);
		ptrace_write(pid, (uint8_t *) regs->ARM_sp, (uint8_t *) &params[i], (num_params - i) * sizeof(long));
	}

	regs->ARM_pc= addr;
	if (regs->ARM_pc& 1) {
		/* thumb */
		regs->ARM_pc &= (~1u);
		regs->ARM_cpsr |= CPSR_T_MASK;
	} else {
		/* arm */
		regs->ARM_cpsr &= ~CPSR_T_MASK;
	}

	regs->ARM_lr= 0;

	if (ptrace_setregs(pid, regs) == -1 || ptrace_continue(pid) == -1) {
		return -1;
	}

	waitpid(pid, NULL, WUNTRACED);
	return 0;
}

//static void* thread_connect_to_zygote(void* arg){
//	int s, len;
//	struct sockaddr_un remote;
//
//	LOGI("[+] wait 2s...");
//	sleep(2);
//
//	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) != -1) {
//		remote.sun_family = AF_UNIX;
//		strcpy(remote.sun_path, "/dev/socket/zygote");
//		len = strlen(remote.sun_path) + sizeof(remote.sun_family);
//		LOGI("[+] start to connect zygote socket");
//		connect(s, (struct sockaddr *) &remote, len);
//		LOGI("[+] close socket");
//		close(s);
//	}
//
//	return NULL ;
//}

static int zygote_special_process(pid_t target_pid){
	LOGI("[+] zygote process should special take care. \n");

	struct pt_regs regs;

	if (ptrace_getregs(target_pid, &regs) == -1)
		return -1;

	void* remote_getpid_addr = get_remote_address(target_pid, getpid);
	LOGI("[+] Remote getpid addr %p.\n", remote_getpid_addr);

	if(remote_getpid_addr == NULL){
		return -1;
	}

	pthread_t tid = 0;
	pthread_create(&tid, NULL, connect_to_zygote, NULL);
	pthread_detach(tid);

	if (ptrace_call(target_pid, remote_getpid_addr, NULL, 0, &regs) == -1) {
		LOGE("[-] Call remote getpid fails");
		return -1;
	}

	if (ptrace_getregs(target_pid, &regs) == -1)
		return -1;

	LOGI("[+] Call remote getpid result r0=%x, r7=%x, pc=%x, \n", regs.ARM_r0, regs.ARM_r7, regs.ARM_pc);
	return 0;
}

void* ptrace_dlopen(pid_t target_pid, void* remote_dlopen_addr, const char*  filename){
	struct pt_regs regs;
	if (ptrace_getregs(target_pid, &regs) == -1)
		return NULL ;

	if (strcmp("zygote", get_process_name(target_pid)) == 0 && zygote_special_process(target_pid) != 0) {
		return NULL ;
	}

	long mmap_params[2];
	size_t filename_len = strlen(filename) + 1;
	void* filename_addr = find_space_by_mmap(target_pid, filename_len);

	if (filename_addr == NULL ) {
		LOGE("[-] Call Remote mmap fails.\n");
		return NULL ;
	}

	ptrace_write(target_pid, (uint8_t *)filename_addr, (uint8_t *)filename, filename_len);

	mmap_params[0] = (long)filename_addr;  //filename pointer
	mmap_params[1] = RTLD_NOW | RTLD_GLOBAL; // flag

	remote_dlopen_addr = (remote_dlopen_addr == NULL) ? get_remote_address(target_pid, (void *)dlopen) : remote_dlopen_addr;

	if (remote_dlopen_addr == NULL) {
		LOGE("[-] Get Remote dlopen address fails.\n");
		return NULL;
	}

	if (ptrace_call(target_pid, (uint32_t) remote_dlopen_addr, mmap_params, 2, &regs) == -1)
		return NULL;

	if (ptrace_getregs(target_pid, &regs) == -1)
		return NULL;

	LOGI("[+] Target process returned from dlopen, return r0=%x, r7=%x, pc=%x, \n", regs.ARM_r0, regs.ARM_r7, regs.ARM_pc);

	return regs.ARM_pc == 0 ? (void *) regs.ARM_r0 : NULL;
}



