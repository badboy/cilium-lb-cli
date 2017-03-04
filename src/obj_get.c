#define _GNU_SOURCE

#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <strings.h>

static __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

int obj_get(const char *pathname)
{
	union bpf_attr attr;
	bzero(&attr, sizeof(attr));
	attr.pathname = ptr_to_u64((void *)pathname);

	return syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}
