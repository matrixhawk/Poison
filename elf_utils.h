/*
 * elf_utils.h
 *
 *  Created on: 2013-6-19
 *      Author: boyliang
 */

#ifndef ELF_UTILS_H_
#define ELF_UTILS_H_

#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <sys/mman.h>

void* get_module_base(pid_t pid, const char* module_name);

void* find_space_by_mmap(int target_pid, int size);

void* find_space_in_maps(int pid, int size);

int find_module_info_by_address(pid_t pid, void* addr, char *module, void** start, void** end);

int find_module_info_by_name(pid_t pid, const char *module, void** start, void** end);

void* get_remote_address(pid_t pid, void *local_addr);

#endif /* ELF_UTILS_H_ */
