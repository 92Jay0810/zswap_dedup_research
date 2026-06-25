// SPDX-License-Identifier: GPL-2.0
// zswap_dedup.bpf.c  — kernel 6.8 相容版本 (v5)
//
// 設計原則：把 instruction count 壓到最低
//   - 移除 BPF 端的 classify_page（改到 userspace 做）
//   - 移除 zero_cb / same_cb / ascii_cb / ptr_cb 四個 bpf_loop callback
//   - BPF 只做：read page、FNV hash、counter、ringbuf event
//   - page_type_stats map 也移到 userspace 維護（讀 ringbuf event 時統計）
//   - 每個 dup event 送 4 × 32 = 128 bytes samples，userspace 分類用

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PAGE_SIZE        4096ULL
#define PAGE_SHIFT       12
#define HASH_MAP_MAX     (1 << 20)
#define STRUCT_PAGE_SIZE 64ULL

#define SAMPLE_SIZE   32
#define SAMPLE_TOTAL  128   // 4 × 32

// ============================================================
// Maps
// ============================================================

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

#define CNT_TOTAL     0
#define CNT_DUPLICATE 1
#define CNT_UNIQUE    2
#define CNT_ERROR     3

struct hash_entry {
    __u64 count;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, HASH_MAP_MAX);
    __type(key, __u64);
    __type(value, struct hash_entry);
} hash_index SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 9);
    __type(key, __u32);
    __type(value, __u64);
} sharing_hist SEC(".maps");

// dup_event：送到 userspace
// samples[0..31]   = page offset 0
// samples[32..63]  = page offset 1024
// samples[64..95]  = page offset 2048
// samples[96..127] = page offset 3072
struct dup_event {
    __u64 hash;
    __u64 count;
    __u64 interval_ns;
    __u64 first_seen_ns;
    __u32 pid;
    __u8  _pad[4];
    char  comm[16];
    __u8  samples[SAMPLE_TOTAL];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 << 20);
} dup_events SEC(".maps");

struct page_content {
    __u8 data[PAGE_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct page_content);
} page_buf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} addr_consts SEC(".maps");

#define AKEY_VMEMMAP_SYM   0
#define AKEY_PGOFFSET_SYM  1
#define AKEY_VMEMMAP_VAL   2
#define AKEY_PGOFFSET_VAL  3

// ============================================================
// FNV-1a：唯一的 bpf_loop callback
// ============================================================

#define FNV_OFFSET 0xcbf29ce484222325ULL
#define FNV_PRIME  0x00000100000001B3ULL

struct hash_ctx {
    struct page_content *pc;
    __u64 h;
};

static int hash_cb(__u32 idx, struct hash_ctx *c)
{
    __u64 word = 0;
    __u32 off  = idx * 8;
    if (off + 8 > PAGE_SIZE) return 1;
    bpf_probe_read_kernel(&word, 8, c->pc->data + off);
    c->h ^= word;
    c->h *= FNV_PRIME;
    return 0;
}

// ============================================================
// 輔助
// ============================================================

static __always_inline void inc_counter(__u32 key)
{
    __u64 *v = bpf_map_lookup_elem(&counters, &key);
    if (v) (*v)++;
}

static __always_inline void update_hist(__u64 count)
{
    __u32 b;
    if      (count == 1)   b = 0;
    else if (count == 2)   b = 1;
    else if (count <= 4)   b = 2;
    else if (count <= 8)   b = 3;
    else if (count <= 16)  b = 4;
    else if (count <= 32)  b = 5;
    else if (count <= 64)  b = 6;
    else if (count <= 128) b = 7;
    else                   b = 8;
    __u64 *v = bpf_map_lookup_elem(&sharing_hist, &b);
    if (v) __sync_fetch_and_add(v, 1);
}

static __always_inline int ensure_consts(__u64 *vm_out, __u64 *pg_out)
{
    __u32 k0=AKEY_VMEMMAP_SYM, k1=AKEY_PGOFFSET_SYM;
    __u32 k2=AKEY_VMEMMAP_VAL, k3=AKEY_PGOFFSET_VAL;

    __u64 *vv = bpf_map_lookup_elem(&addr_consts, &k2);
    __u64 *pv = bpf_map_lookup_elem(&addr_consts, &k3);
    if (!vv || !pv) return -1;
    if (*vv && *pv) { *vm_out = *vv; *pg_out = *pv; return 0; }

    __u64 *vs = bpf_map_lookup_elem(&addr_consts, &k0);
    __u64 *ps = bpf_map_lookup_elem(&addr_consts, &k1);
    if (!vs || !ps || !*vs || !*ps) return -1;

    __u64 vm=0, pg=0;
    if (bpf_probe_read_kernel(&vm, 8, (void *)*vs) < 0) return -1;
    if (bpf_probe_read_kernel(&pg, 8, (void *)*ps) < 0) return -1;
    if (!vm || !pg) return -1;

    bpf_map_update_elem(&addr_consts, &k2, &vm, BPF_ANY);
    bpf_map_update_elem(&addr_consts, &k3, &pg, BPF_ANY);
    *vm_out = vm; *pg_out = pg;
    return 0;
}

static __always_inline __u64 folio_to_virt(void *folio, __u64 vm, __u64 pg)
{
    __u64 addr = (__u64)folio;
    if (addr < vm) return 0;
    __u64 pfn = (addr - vm) / STRUCT_PAGE_SIZE;
    if (pfn > (1ULL << 32)) return 0;
    return pg + (pfn << PAGE_SHIFT);
}

// ============================================================
// kprobe: zswap_store(struct folio *folio)
// ============================================================

SEC("kprobe/zswap_store")
int BPF_KPROBE(zswap_store_entry, struct folio *folio)
{
    __u32 zero = 0;
    __u64 vm = 0, pg = 0;

    inc_counter(CNT_TOTAL);
    if (!folio) { inc_counter(CNT_ERROR); return 0; }
    if (ensure_consts(&vm, &pg) < 0) { inc_counter(CNT_ERROR); return 0; }

    __u64 page_virt = folio_to_virt(folio, vm, pg);
    if (!page_virt) { inc_counter(CNT_ERROR); return 0; }

    struct page_content *pc = bpf_map_lookup_elem(&page_buf, &zero);
    if (!pc) { inc_counter(CNT_ERROR); return 0; }

    if (bpf_probe_read_kernel(pc->data, PAGE_SIZE, (void *)page_virt) < 0) {
        inc_counter(CNT_ERROR); return 0;
    }

    struct hash_ctx hc = { .pc = pc, .h = FNV_OFFSET };
    bpf_loop(512, hash_cb, &hc, 0);
    __u64 hash = hc.h;

    __u64 now = bpf_ktime_get_ns();

    struct hash_entry *ent = bpf_map_lookup_elem(&hash_index, &hash);
    if (ent) {
        __u64 cnt  = __sync_fetch_and_add(&ent->count, 1) + 1;
        __u64 ivns = now - ent->last_seen_ns;
        __u64 fns  = ent->first_seen_ns;
        ent->last_seen_ns = now;

        inc_counter(CNT_DUPLICATE);
        update_hist(cnt);

        if (cnt % 100 == 0 || ivns < 5000000000ULL) {
            struct dup_event *evt = bpf_ringbuf_reserve(
                &dup_events, sizeof(*evt), 0);
            if (evt) {
                evt->hash          = hash;
                evt->count         = cnt;
                evt->interval_ns   = ivns;
                evt->first_seen_ns = fns;
                evt->pid           = bpf_get_current_pid_tgid() >> 32;
                evt->_pad[0] = evt->_pad[1] = evt->_pad[2] = evt->_pad[3] = 0;
                bpf_get_current_comm(evt->comm, sizeof(evt->comm));

                bpf_probe_read_kernel(evt->samples +  0, SAMPLE_SIZE,
                                      (void *)(page_virt));
                bpf_probe_read_kernel(evt->samples + 32, SAMPLE_SIZE,
                                      (void *)(page_virt + 1024));
                bpf_probe_read_kernel(evt->samples + 64, SAMPLE_SIZE,
                                      (void *)(page_virt + 2048));
                bpf_probe_read_kernel(evt->samples + 96, SAMPLE_SIZE,
                                      (void *)(page_virt + 3072));

                bpf_ringbuf_submit(evt, 0);
            }
        }
    } else {
        struct hash_entry ne = {
            .count = 1, .first_seen_ns = now, .last_seen_ns = now
        };
        inc_counter(CNT_UNIQUE);
        update_hist(1);
        bpf_map_update_elem(&hash_index, &hash, &ne, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
