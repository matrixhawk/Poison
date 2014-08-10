/*
 * tool.h
 *
 *  Created on: 2013-7-5
 *      Author: boyliang
 */


#include <stdio.h>
#include <dlfcn.h>
#include <stddef.h>


void *get_method_address(const char *soname, const char *methodname) {
	void *handler = dlopen(soname, RTLD_NOW | RTLD_GLOBAL);
	return dlsym(handler, methodname);
}

const char* get_process_name(pid_t pid) {
	static char buffer[255];
	FILE* f;
	char path[255];

	snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
	if ((f = fopen(path, "r")) == NULL) {
		return NULL;
	}

	if (fgets(buffer, sizeof(buffer), f) == NULL) {
		return NULL;
	}

	fclose(f);
	return buffer;
}
