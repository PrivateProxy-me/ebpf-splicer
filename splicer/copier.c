// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_SOCKHASH);
  __uint(key_size, 12);
  __uint(value_size, 4);
  __uint(max_entries, 1048576);
} sockets SEC(".maps");

#ifdef DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                                                    \
	({                                                                     \
		char ____fmt[] = fmt;                                          \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);     \
	})
#else
#define bpf_debug(fmt, ...){;}
#endif


SEC("sk_skb/stream_parser")
int bpf_redir(struct __sk_buff *skb) {
  return skb->len;
}

SEC("sk_skb/stream_verdict")
int verdict(struct __sk_buff *skb) {
  unsigned char key[12];
  __builtin_memcpy(key, &skb->local_ip4, 4);
  __builtin_memcpy(key + 4, &skb->remote_ip4, 4);
  __builtin_memcpy(key + 8, &skb->local_port, 2);
  __builtin_memcpy(key + 10, (__u8 *)&skb->remote_port + 2, 2);

  void *val = bpf_map_lookup_elem(&sockets, &key);
  if (val != NULL) {
    bpf_sk_release(val);
    return bpf_sk_redirect_hash(skb, &sockets, key, 0);
  }
  return SK_PASS;
}
