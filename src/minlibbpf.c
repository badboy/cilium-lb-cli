#define _GNU_SOURCE

#include <stdlib.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>

struct lb4_key {
	__be32 address;
	__u16 dport;		/* L4 port filter, if unset, all ports apply */
	__u16 slave;		/* Backend iterator, 0 indicates the master service */
} __attribute__((packed));

struct lb4_key_unpacked {
	__be32 address;
	__u16 dport;		/* L4 port filter, if unset, all ports apply */
	__u16 slave;		/* Backend iterator, 0 indicates the master service */
};

struct lb4_service {
	__be32 target;
	__u16 port;
	__u16 count;
	__u16 rev_nat_index;
	__u16 weight;
} __attribute__((packed));
struct lb4_service_unpacked {
	__be32 target;
	__u16 port;
	__u16 count;
	__u16 rev_nat_index;
	__u16 weight;
};

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

int bpf_lookup_elem(int fd, void *key, void *value)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);

	return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int bpf_update_elem(int fd, void *key, void *value, unsigned long long flags)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = fd;
  attr.key = ptr_to_u64(key);
  attr.value = ptr_to_u64(value);
  attr.flags = flags;

  return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int bpf_delete_elem(int fd, void *key)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = fd;
  attr.key = ptr_to_u64(key);

  return syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

int bpf_get_next_key(int fd, void *key, void *next_key)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.next_key = ptr_to_u64(next_key);

	return syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

int set_service(int fd,
		int daddr, int port, int slave,
		int target, int dport, int count)
{
	struct lb4_key key = {
		/*.address =*/ __bswap_32(daddr),
		/*.dport =*/ port,
		/*.slave =*/ slave,
	};

	struct lb4_service svc = {
		/*.target =*/ __bswap_32(target),
		/*.port   =*/ dport,
		/*.count  =*/ count,
		/*.rev_nat_index =*/ 0,
		/*.weight =*/ 0,
	};

	return bpf_update_elem(fd, &key, &svc, 0);
}

void free_packed(void *in)
{
	free(in);
}

struct lb4_key *to_packed_key(const struct lb4_key_unpacked *in)
{
	struct lb4_key *key = malloc(sizeof(*key));
	if (!key) return NULL;

	key->address = __bswap_32(in->address);
	key->dport = in->dport;
	key->slave = in->slave;

	return key;
}
void from_packed_key(const struct lb4_key *in, struct lb4_key_unpacked *out)
{
	out->address = __bswap_32(in->address);
	out->dport = in->dport;
	out->slave = in->slave;
}

void from_packed_svc(const struct lb4_service *in, struct lb4_service_unpacked *out)
{
	out->target = __bswap_32(in->target);
	out->port = in->port;
	out->count = in->count;
	out->rev_nat_index = in->rev_nat_index;
	out->weight = in->weight;
}
