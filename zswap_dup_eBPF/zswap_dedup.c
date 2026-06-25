// zswap_dedup.c  — userspace loader + stats display (v5)
// 分類邏輯從 BPF 移到 userspace，page_type_stats 在 userspace 維護

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "zswap_dedup.skel.h"

#define CNT_TOTAL     0
#define CNT_DUPLICATE 1
#define CNT_UNIQUE    2
#define CNT_ERROR     3

#define ACONST_VMEMMAP_SYM  0
#define ACONST_PGOFFSET_SYM 1

#define SAMPLE_SIZE   32
#define SAMPLE_TOTAL  128

#define PTYPE_ZERO         0
#define PTYPE_SAME_FILLED  1
#define PTYPE_TEXT_ASCII   2
#define PTYPE_CODE_X86     3
#define PTYPE_PTR_HEAVY    4
#define PTYPE_BINARY       5
#define PTYPE_COUNT        6

static const char *ptype_name[PTYPE_COUNT] = {
    "ZERO", "SAME_FILLED", "TEXT/ASCII", "CODE(x86)", "PTR_HEAVY", "BINARY",
};

// 必須和 BPF dup_event 完全對齊
struct dup_event {
    uint64_t hash;
    uint64_t count;
    uint64_t interval_ns;
    uint64_t first_seen_ns;
    uint32_t pid;
    uint8_t  _pad[4];
    char     comm[16];
    uint8_t  samples[SAMPLE_TOTAL];
};

static const char *hist_labels[] = {
    "1 (unique)", "2", "3-4", "5-8", "9-16",
    "17-32", "33-64", "65-128", "129+",
};

static volatile int running = 1;
static void sig_handler(int sig) { (void)sig; running = 0; }

// userspace 維護 page type 統計
static uint64_t page_type_stats[PTYPE_COUNT] = {0};
static uint64_t thrashing_events = 0;

// ============================================================
// kallsyms / percpu
// ============================================================
static uint64_t kallsyms_lookup(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    uint64_t addr = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        uint64_t a; char type[4], sym[256];
        if (sscanf(line, "%lx %3s %255s", &a, type, sym) == 3 &&
            strcmp(sym, name) == 0) { addr = a; break; }
    }
    fclose(f);
    return addr;
}

static uint64_t read_percpu_counter(int map_fd, uint32_t key)
{
    int num_cpus = libbpf_num_possible_cpus();
    uint64_t *values = calloc(num_cpus, sizeof(uint64_t));
    uint64_t sum = 0;
    if (!values) return 0;
    if (bpf_map_lookup_elem(map_fd, &key, values) == 0)
        for (int i = 0; i < num_cpus; i++) sum += values[i];
    free(values);
    return sum;
}

// ============================================================
// Userspace 分類器
// 輸入：samples（4 個位置各 32 bytes）
// 設計：
//   ZERO       = 4 個位置全部都是 0x00
//   SAME_FILLED= 4 個位置全部都是同一個 byte
//   TEXT/ASCII = 位置 0 的前 32 bytes 中，可列印 ASCII ≥ 70%
//   CODE_X86   = 位置 0 前 4 bytes 符合 x86 prologue pattern
//   PTR_HEAVY  = 位置 0 的 4 個 uint64 中，≥ 3 個像 canonical pointer
//   BINARY     = 其他
// ============================================================
static int classify_samples(const uint8_t *samples,
                              uint8_t *zero_confirmed_out)
{
    // 全零檢查：4 個位置各 32 bytes
    int all_zero = 1;
    for (int s = 0; s < 4 && all_zero; s++)
        for (int i = 0; i < SAMPLE_SIZE && all_zero; i++)
            if (samples[s * SAMPLE_SIZE + i] != 0) all_zero = 0;
    *zero_confirmed_out = (uint8_t)all_zero;
    if (all_zero) return PTYPE_ZERO;

    // Same-filled：4 個位置都等於 samples[0]
    uint8_t fb = samples[0];
    int all_same = 1;
    for (int s = 0; s < 4 && all_same; s++)
        for (int i = 0; i < SAMPLE_SIZE && all_same; i++)
            if (samples[s * SAMPLE_SIZE + i] != fb) all_same = 0;
    if (all_same) return PTYPE_SAME_FILLED;

    // ASCII 比例（位置 0）
    int printable = 0;
    for (int i = 0; i < SAMPLE_SIZE; i++) {
        uint8_t b = samples[i];
        if ((b >= 0x20 && b <= 0x7e) || b == 0x09 || b == 0x0a || b == 0x0d)
            printable++;
    }
    if (printable * 100 / SAMPLE_SIZE >= 70) return PTYPE_TEXT_ASCII;

    // x86 prologue（位置 0 前 4 bytes）
    if ((samples[0] == 0x55 && samples[1] == 0x48) ||
        (samples[0] == 0xf3 && samples[1] == 0x0f &&
         samples[2] == 0x1e && samples[3] == 0xfa) ||
        (samples[0] == 0x48 && samples[1] == 0x83))
        return PTYPE_CODE_X86;

    // Pointer-heavy：位置 0 的 4 個 uint64
    int ptr_like = 0;
    for (int i = 0; i + 8 <= SAMPLE_SIZE; i += 8) {
        uint64_t v;
        memcpy(&v, samples + i, 8);
        uint16_t top = (uint16_t)(v >> 48);
        if (top == 0x0000 || top == 0xffff ||
            (top >= 0x7f00 && top <= 0x7fff))
            ptr_like++;
    }
    if (ptr_like >= 3) return PTYPE_PTR_HEAVY;

    return PTYPE_BINARY;
}

// ============================================================
// Hex dump
// ============================================================
static void print_hexdump(const uint8_t *data, int len, uint32_t base_off)
{
    for (int row = 0; row < len; row += 16) {
        int cols = (len - row < 16) ? len - row : 16;
        printf("    %04x: ", base_off + row);
        for (int i = 0; i < 16; i++) {
            if (i < cols) printf("%02x ", data[row + i]);
            else          printf("   ");
            if (i == 7)   printf(" ");
        }
        printf(" |");
        for (int i = 0; i < cols; i++) {
            uint8_t b = data[row + i];
            printf("%c", (b >= 0x20 && b <= 0x7e) ? b : '.');
        }
        printf("|\n");
    }
}

// ============================================================
// Ring buffer callback
// ============================================================
static int handle_dup_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct dup_event)) return 0;
    struct dup_event *e = data;

    // userspace 分類
    uint8_t zero_confirmed = 0;
    int ptype = classify_samples(e->samples, &zero_confirmed);

    // 統計
    if (ptype >= 0 && ptype < PTYPE_COUNT)
        page_type_stats[ptype]++;

    double interval_ms = (double)e->interval_ns / 1e6;
    int is_thrashing   = (e->interval_ns < 5000000000ULL);
    if (is_thrashing) thrashing_events++;

    printf("[%s] hash=0x%016llx count=%-6llu interval=%7.1fms "
           "pid=%-6u comm=%-15s type=%s",
           is_thrashing ? "THRASH" : "HOTDUP",
           (unsigned long long)e->hash,
           (unsigned long long)e->count,
           interval_ms,
           e->pid, e->comm,
           (ptype >= 0 && ptype < PTYPE_COUNT) ? ptype_name[ptype] : "UNKNOWN");

    if (ptype == PTYPE_ZERO)
        printf(" [zero_confirmed=%d]", zero_confirmed);
    printf("\n");

    // ZERO：印出各位置的 hex，確認哪裡有非零
    if (ptype == PTYPE_ZERO) {
        uint32_t offsets[4] = {0, 1024, 2048, 3072};
        int any_nz = 0;
        for (int s = 0; s < 4; s++) {
            const uint8_t *sd = e->samples + s * SAMPLE_SIZE;
            int has_nz = 0;
            for (int i = 0; i < SAMPLE_SIZE; i++)
                if (sd[i]) { has_nz = 1; any_nz = 1; break; }
            if (has_nz) {
                printf("    [offset +%04u: non-zero in sample]\n", offsets[s]);
                print_hexdump(sd, SAMPLE_SIZE, offsets[s]);
            }
        }
        if (!any_nz)
            printf("    [all 4 sample positions are zero, zero_confirmed=%d]\n",
                   zero_confirmed);
    }

    // TEXT/ASCII：印位置 0
    if (ptype == PTYPE_TEXT_ASCII) {
        printf("    [offset +0000]\n");
        print_hexdump(e->samples, SAMPLE_SIZE, 0);
    }

    // SAME_FILLED：印填充值
    if (ptype == PTYPE_SAME_FILLED)
        printf("    [fill byte = 0x%02x]\n", e->samples[0]);

    fflush(stdout);
    return 0;
}

// ============================================================
// print_stats
// ============================================================
static void print_stats(struct zswap_dedup_bpf *skel)
{
    int counters_fd = bpf_map__fd(skel->maps.counters);
    int hist_fd     = bpf_map__fd(skel->maps.sharing_hist);
    int aconst_fd   = bpf_map__fd(skel->maps.addr_consts);

    uint64_t total  = read_percpu_counter(counters_fd, CNT_TOTAL);
    uint64_t dup    = read_percpu_counter(counters_fd, CNT_DUPLICATE);
    uint64_t unique = read_percpu_counter(counters_fd, CNT_UNIQUE);
    uint64_t errors = read_percpu_counter(counters_fd, CNT_ERROR);

    double dedup_ratio = (total > 0) ? (100.0 * dup / total) : 0.0;
    double error_rate  = (total > 0) ? (100.0 * errors / total) : 0.0;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    printf("\n========== zswap Content Dedup Stats [%02d:%02d:%02d] ==========\n",
           t->tm_hour, t->tm_min, t->tm_sec);
    printf("  Total pages into zswap : %10llu\n", (unsigned long long)total);
    printf("  Unique pages           : %10llu\n", (unsigned long long)unique);
    printf("  Duplicate pages        : %10llu\n", (unsigned long long)dup);
    printf("  Read errors            : %10llu  (%.1f%%)\n",
           (unsigned long long)errors, error_rate);
    printf("  Thrashing events (<5s) : %10llu\n",
           (unsigned long long)thrashing_events);

    if (error_rate > 50.0 && total > 100) {
        uint64_t cv = 0, cp = 0;
        uint32_t k2 = 2, k3 = 3;
        bpf_map_lookup_elem(aconst_fd, &k2, &cv);
        bpf_map_lookup_elem(aconst_fd, &k3, &cp);
        printf("\n  [WARN] High error rate!\n");
        printf("         vmemmap=0x%016llx page_offset=0x%016llx\n",
               (unsigned long long)cv, (unsigned long long)cp);
        if (!cv) printf("         BPF has not read constants yet.\n");
        else     printf("         Check struct page size (currently 64 bytes).\n");
    }

    printf("  ----------------------------------------\n");
    printf("  Dedup ratio            : %10.2f%%\n", dedup_ratio);
    printf("  Memory saved (est.)    : %10.2f MB\n",
           (double)dup * 4096.0 / (1024.0 * 1024.0));

    // page type 統計（userspace 累計）
    printf("\n  Page Type Distribution (dup events only):\n");
    printf("  %-14s  %10s  %7s  %s\n", "Type", "Count", "%", "Bar");
    uint64_t type_total = 0;
    for (int i = 0; i < PTYPE_COUNT; i++) type_total += page_type_stats[i];
    for (int i = 0; i < PTYPE_COUNT; i++) {
        double pct = type_total > 0 ? 100.0 * page_type_stats[i] / type_total : 0.0;
        int bar = (int)(pct / 2.0); if (bar > 50) bar = 50;
        char barstr[51]; memset(barstr, '#', bar); barstr[bar] = '\0';
        printf("  %-14s  %10llu  %6.1f%%  %s\n",
               ptype_name[i], (unsigned long long)page_type_stats[i],
               pct, barstr);
    }

    // sharing factor
    printf("\n  Sharing Factor Distribution:\n");
    printf("  %-12s  %10s  %s\n", "Copies/hash", "Count", "Bar");
    for (int i = 0; i < 9; i++) {
        uint32_t key = (uint32_t)i;
        uint64_t val = 0;
        bpf_map_lookup_elem(hist_fd, &key, &val);
        int bar = (int)(val / 100); if (bar > 40) bar = 40;
        char barstr[41]; memset(barstr, '#', bar); barstr[bar] = '\0';
        printf("  %-12s  %10llu  %s\n",
               hist_labels[i], (unsigned long long)val, barstr);
    }
    printf("=============================================================\n");
    fflush(stdout);
}

// ============================================================
// main
// ============================================================
static void usage(const char *prog)
{
    printf("Usage: %s [-i <interval_sec>] [-v]\n", prog);
    printf("  -i  Reporting interval in seconds (default: 5)\n");
    printf("  -v  Verbose: show libbpf debug messages\n");
}

int main(int argc, char **argv)
{
    int interval = 5, verbose = 0;
    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "-i") == 0 && i+1 < argc) interval = atoi(argv[++i]);
        else if (strcmp(argv[i], "-v") == 0) verbose = 1;
        else if (strcmp(argv[i], "-h") == 0) { usage(argv[0]); return 0; }
    }

    if (!verbose) libbpf_set_print(NULL);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    uint64_t vmemmap_sym  = kallsyms_lookup("vmemmap_base");
    uint64_t pgoffset_sym = kallsyms_lookup("page_offset_base");
    if (!vmemmap_sym || !pgoffset_sym) {
        fprintf(stderr, "[ERROR] Cannot find vmemmap_base/page_offset_base. Root?\n");
        return 1;
    }
    printf("[INFO] vmemmap_base     symbol @ 0x%016lx\n", vmemmap_sym);
    printf("[INFO] page_offset_base symbol @ 0x%016lx\n", pgoffset_sym);

    if (!kallsyms_lookup("zswap_store")) {
        fprintf(stderr, "[ERROR] zswap_store not found. Is zswap enabled?\n");
        return 1;
    }
    printf("[INFO] zswap_store      @ 0x%016lx\n\n",
           kallsyms_lookup("zswap_store"));

    struct zswap_dedup_bpf *skel = zswap_dedup_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF: %s\n", strerror(errno));
        return 1;
    }

    int afd = bpf_map__fd(skel->maps.addr_consts);
    uint32_t k0 = ACONST_VMEMMAP_SYM, k1 = ACONST_PGOFFSET_SYM;
    bpf_map_update_elem(afd, &k0, &vmemmap_sym,  BPF_ANY);
    bpf_map_update_elem(afd, &k1, &pgoffset_sym, BPF_ANY);

    int err = zswap_dedup_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach: %d (%s)\n", err, strerror(-err));
        zswap_dedup_bpf__destroy(skel);
        return 1;
    }

    printf("zswap dedup monitor attached (hook: zswap_store).\n");
    printf("Interval: %ds. Press Ctrl+C to stop.\n\n", interval);

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.dup_events), handle_dup_event, NULL, NULL);
    if (!rb) fprintf(stderr, "Warning: failed to create ring buffer\n");

    time_t last_print = time(NULL);
    while (running) {
        if (rb) ring_buffer__poll(rb, 100);
        if (time(NULL) - last_print >= interval) {
            print_stats(skel);
            last_print = time(NULL);
        }
    }

    printf("\n--- Final stats ---\n");
    print_stats(skel);

    ring_buffer__free(rb);
    zswap_dedup_bpf__destroy(skel);
    return 0;
}
