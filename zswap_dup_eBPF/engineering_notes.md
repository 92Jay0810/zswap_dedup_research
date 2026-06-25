# eBPF 工程考量筆記

本工具實作自 Initial Guide 的「階段一：量測 swap 中的內容重複率」。
下文記錄實際實作與 Guide 原始設計的差異，以及每個偏離點的技術原因。
後半部分記錄量測工具在教授回饋後的擴充方向（工作 A：Page Location & Dynamic Tracing），
以及擴充過程中遭遇的 BPF verifier 限制與解法。

---

## 1. Hook 點：從 `fentry/zswap_store_page` 到 `kprobe/zswap_store`

### Guide 的原始設計

Guide 建議掛在 `zswap_store_page()`（mm/zswap.c line ~1402），理由是：
- 這是 page 進入 zswap 的入口，zeromap 已在上層過濾掉全零 page
- 語意上最直覺，每個抵達此處的 page 都是待壓縮的非零內容

### 問題一：`zswap_store_page` 在 kernel 6.8 已不存在

本測試環境為 **kernel 6.8**（Ubuntu 24.04）。kernel 6.8 已完成 folio 遷移，
入口函式重新命名並重構，`zswap_store_page` 不在 kallsyms 中。

存在的入口為 `zswap_store(struct folio *folio)`，BTF 確認：
```
[87082] FUNC 'zswap_store' type_id=33220 linkage=static
[33220] FUNC_PROTO ret_type_id=42 vlen=1
        'folio' type_id=1120   ← struct folio *，非 struct page *
```

### 問題二：`fentry` 對 static linkage 函式受限

BTF 顯示 `zswap_store` 為 `linkage=static`，`fentry` 在部分 kernel 設定下
無法 attach static 函式。改用 `kprobe` 可繞過此限制。

### 問題三：從 folio 取得 page 內容的 virtual address

Guide 設計隱含假設可以直接讀取 page 內容，但在 `zswap_store` 的 kprobe 裡，
拿到的是 `struct folio *`，需要額外推算才能取得 page 內容的 kernel virtual address：

```
pfn  = (folio_addr - vmemmap_base) / sizeof(struct page)   // 64 bytes on x86-64
virt = page_offset_base + pfn * PAGE_SIZE
```

這個推算引出了下一節的 KASLR 問題。

### 最終 Hook：`kprobe/zswap_store`

```c
SEC("kprobe/zswap_store")
int BPF_KPROBE(zswap_store_entry, struct folio *folio)
```

語意等價於 Guide 的目標：每個通過 zeromap、進入 zswap 的非零 page 都會觸發此 hook。

---

## 2. KASLR 動態常數問題（Guide 未提及）

### 問題

Guide 未討論這個問題，但在 kernel 6.8 + KASLR 環境下這是最關鍵的障礙。

`vmemmap_base` 和 `page_offset_base` 在 kernel 6.8 是**執行期動態變數**
（kallsyms 顯示為 `D` 類型），每次開機因 KASLR 偏移不同：

```bash
sudo grep -E 'page_offset_base|vmemmap_base' /proc/kallsyms
# ffffffff90d465e8 D vmemmap_base
# ffffffff90d465f8 D page_offset_base
```

實測值（某次開機）：
```
vmemmap_base     = 0xfffffb03c0000000   ← 非「教科書」預設值 0xffffea0000000000
page_offset_base = 0xffff8d84c0000000   ← 非「教科書」預設值 0xffff888000000000
```

用硬編碼預設值的結果：56 萬個 page 全部 `bpf_probe_read_kernel` 失敗，error rate 100%。

### 嘗試：從 /proc/kcore 讀取

`/proc/kcore` 是 ELF64 core 格式，理論上可解析 program headers 讀取任意
kernel virtual address。實作後發現此 kernel 的 kcore **完全沒有 PT_LOAD segment**：

```
phnum=10, phentsize=56
# 無任何 LOAD 段
```

kcore 路徑不可行。

### 最終設計：讓 BPF 程式自行讀取

BPF 程式本身在 kernel 空間執行，`bpf_probe_read_kernel` 可以讀取任意 kernel 地址
——這正是 bpftrace 能直接寫 `*(uint64*)0xffffffff...` 的原理。

流程：userspace 從 `/proc/kallsyms` 讀取兩個變數的**符號地址**（不是值），
注入 BPF map；BPF 程式在第一次觸發時讀出實際值並 cache：

```
userspace                              BPF (kernel space)
─────────────────────────────────      ──────────────────────────────────
/proc/kallsyms 讀符號地址              第一次 zswap_store 觸發：
addr_consts[0] = 0xffffffff90d465e8    bpf_probe_read_kernel(addr_consts[0])
addr_consts[1] = 0xffffffff90d465f8    → 讀出 vmemmap_base 實際值
                                       → cache 進 addr_consts[2], addr_consts[3]
                                       後續直接用 cache
```

`addr_consts` map 語意：

| key | 內容 | 寫入方 |
|-----|------|--------|
| 0 | `vmemmap_base` 的符號地址 | userspace（kallsyms） |
| 1 | `page_offset_base` 的符號地址 | userspace（kallsyms） |
| 2 | `vmemmap_base` 的實際值 | BPF（首次觸發時讀取） |
| 3 | `page_offset_base` 的實際值 | BPF（首次觸發時讀取） |

完全不依賴硬編碼常數，重開機後自動適應。

---

## 3. Hash 演算法：從 xxHash64 到 FNV-1a

### Guide 的原始設計

Guide 建議使用 `xxHash64`（kernel 內建 `<linux/xxhash.h>`），理由充分：
速度快、kernel 已有實作、碰撞率低。

### 問題一：BPF stack 上限 512 bytes

xxHash64 使用 4 個 accumulator lane（v1–v4）並行處理，需 `#pragma unroll` 展開迴圈。
展開 128 輪後，clang 將每輪中間值留在 stack，瞬間超過 512 bytes 限制：

```
error: Looks like the BPF stack limit is exceeded.
Please move large on stack variables into BPF per-cpu array map.
```

### 問題二：`__noinline` 拆分無效

嘗試拆成兩個 `__noinline` 函式各跑 64 輪，理論上各有獨立 stack frame，
但 clang 在展開 64 輪時仍超出限制。

### 問題三：`BPF_PROG` macro 命名衝突

在 `BPF_PROG` 函式內宣告 `struct hash_ctx ctx`，與 macro 展開的內建參數名
`ctx`（型別 `unsigned long long *`）衝突，產生編譯錯誤。

### 最終設計：FNV-1a 64-bit + `bpf_loop()`

**FNV-1a 適合 BPF 的原因：**
- 每步只有 XOR + multiply 兩個操作，無多個 accumulator，stack 只需一個 `u64`
- 對 dedup 量測（非密碼學用途）碰撞率足夠低

**`bpf_loop()`（kernel 5.17+）取代 `#pragma unroll`：**
- verifier 只需驗證 callback 函式本身，無需展開整個迴圈
- 完全消除 unroll 帶來的 stack 爆炸問題

**page 內容的 4096 bytes 存放在 `BPF_MAP_TYPE_PERCPU_ARRAY`：**
BPF stack 無法容納 4096 bytes，per-CPU map 提供每個 CPU 獨立的 buffer slot，
既繞過 stack 限制，也避免跨 CPU 的 lock contention。

---

## 4. 工作 A 擴充：Thrashing 偵測與 Page 內容分析

初步量測顯示 dedup ratio 超過 10%，教授認為此結果有進一步深挖的價值，
方向是繼續擴充量測工具分析重複 page 的來源與行為，而非直接進入階段二修改 kernel。
擴充目標分為三個方向：

1. **記憶體區段對應**：從 page 內容本身推斷資料類型（Heap / Stack / Text / .rodata）
2. **Memory thrashing 偵測**：同一 page 是否頻繁進出 zswap
3. **GDB 動態追蹤**：找到固定重複的 virtual address 後，attach process 設定 watchpoint

以下記錄各子目標的實作決策與技術限制。

### 4.1 Thrashing 偵測：timestamp + interval_ns

`hash_index` map 的 value 從單純的 `u64 count` 擴充為 `struct hash_entry`：

```c
struct hash_entry {
    __u64 count;
    __u64 first_seen_ns;   // 第一次見到此 hash 的時間
    __u64 last_seen_ns;    // 最近一次見到的時間
};
```

每次 duplicate hit 時計算 `interval_ns = now - last_seen_ns`，
並更新 `last_seen_ns`。interval 小於 5 秒的 event 視為 thrashing，
觸發 ringbuf event 送到 userspace。

原本只有「每 100 次」才送 event 的觸發條件改為：

```c
if (cnt % 100 == 0 || ivns < 5000000000ULL)  // 5 秒門檻
```

這樣 thrashing 窗口不會因為次數門檻而漏掉。userspace 端將
`interval_ns < 5s` 的 event 標記為 `[THRASH]`，其餘為 `[HOTDUP]`，
並另維護 `thrashing_events` 計數器供統計輸出使用。

### 4.2 Page 內容分析：samples + userspace 分類器

**目標：** 在不知道 user virtual address 的前提下，從 page 內容本身推斷資料類型。

每個 dup event 附帶 4 個固定位置的 raw bytes（offset 0 / 1024 / 2048 / 3072，
各 32 bytes，共 128 bytes），送到 userspace 後由分類器分析。

選擇 4 個等距位置而非只取開頭的理由：page 的前 N bytes 可能剛好全零（例如
padding），只看開頭會導致誤分類（詳見下方 ZERO 問題）。4 個位置覆蓋整個
4096 bytes 的分布，在不增加太多 event 大小的前提下提高分類準確度。

分類規則（啟發式，非精確，目的是快速區分大類）：

| 類型 | 判斷條件 |
|------|---------|
| ZERO | 4 個位置全部都是 0x00 |
| SAME_FILLED | 4 個位置全部都是同一個 byte 值（非零） |
| TEXT/ASCII | 位置 0 的 32 bytes 中可列印字元 ≥ 70% |
| CODE(x86) | 位置 0 前 4 bytes 符合 x86 function prologue pattern |
| PTR_HEAVY | 位置 0 的 4 個 uint64 中，≥ 3 個像 canonical 64-bit pointer |
| BINARY | 以上皆不符合 |

**x86 prologue pattern 說明：**

判斷 CODE 類型的依據是 x86-64 ABI 的常見 function prologue：
- `55 48`：`push rbp` + `rex.W prefix`（最常見）
- `f3 0f 1e fa`：`endbr64`（Intel CET 保護，glibc / kernel module 常見）
- `48 83`：`sub rsp, N`（leaf function 直接操作 stack pointer）

**ZERO 誤分類問題與修正：**

初版分類器只看 samples 的位置 0（前 32 bytes），導致「前 32 bytes 剛好全零
但後面有內容」的 page 被誤分類為 ZERO。

修正方式：ZERO 判斷改為「4 個位置全部都是 0x00」才成立。dup event
中另附帶 `is_zero_confirmed` 欄位，供 userspace 輸出時標示確認狀態。

**ZERO（confirmed=1）仍出現在 zswap 的推測原因：**

少數真正全零的 page（4 個 samples 位置全部確認為 0x00）仍進入 zswap，
理論上 zeromap 應在 swap 層攔截。推測原因是 folio 為 large folio（包含
多個 page），其中只有部分 page 全零，但整個 folio 仍進入 zswap 路徑；
zeromap 的過濾邏輯在 single-page 路徑才有效，large folio 路徑未必相同。
此為潛在的後續研究問題，與 page 分類工具本身無關。

### 4.3 Memory Region 對應的根本限制

工作 A 目標一（將重複 page 映射到 `/proc/[pid]/maps` 的 memory region）
在當前 hook 點有根本限制，無法直接完成。

`zswap_store` 的 kprobe context 中，`bpf_get_current_comm()` 拿到的是
**執行 swap 路徑的 process**（通常是 kswapd），而非 page 的實際 owner。
從 folio 計算出的是 kernel virtual address（direct map），與
`/proc/[pid]/maps` 的 user virtual address 沒有直接對應關係。
這個限制和 KSM reverse mapping 貴的原因相同：從 physical page 找回
所有引用它的 user VA 需要 rmap walk，在 BPF 的受限環境下不可行。

要取得 user VA 需在 swap-in 路徑（`do_swap_page()`）另掛 kprobe，
此時 process context 是真正的 page owner，且 VMA 資訊仍然存在，
可用 swap entry（`pte_to_swp_entry()`）作為 key，
與 swap-out 事件在 userspace 端串接對應。

本工具目前不實作此路徑，留作後續擴充。GDB watchpoint（工作 A 目標三）
的前提是取得固定的 user VA，因此也依賴此路徑，目前暫不實施。


---


## 5. BPF Verifier Instruction Count 超限（kernel 6.8）

### 問題

工作 A 擴充後，BPF 程式在 kernel 6.8 載入失敗：

```
BPF program is too large. Processed 1000001 insn
processed 1000001 insns (limit 1000000) max_states_per_insn 5
```

kernel 6.8 的 verifier instruction 上限為 100 萬。擴充後的程式包含：
- 主 kprobe 函式
- FNV-1a hash callback（`bpf_loop`，512 次迭代）
- 分類器的 zero / same-filled / ASCII / pointer 四個 `bpf_loop` callback

五個 callback 在 kernel 6.8 的 verifier 下，每個 callback 的 state 追蹤
cost 遠高於後續版本，合計超過上限。

### 嘗試一：`__always_inline` → `__noinline`

將 `classify_page()` 改為 `__noinline`，理論上 verifier 單獨計算此函式，
主程式只看到一個 `call` instruction。實測仍超限，原因是 kernel 6.8 的
verifier 在遇到 `bpf_loop` callback 時，state 追蹤 cost 本身就很高，
`__noinline` 無法解決 callback 數量過多的問題。

### 最終設計：將分類邏輯完全移到 userspace

BPF 端只保留一個 `bpf_loop` callback（FNV-1a hash），
其餘全部移到 userspace：

- BPF 端：read page → hash → counter → 送 raw samples 到 ringbuf
- Userspace：收到 samples → 分類 → 維護 `page_type_stats[]` 陣列 → 印統計

代價是 page type 統計從「每個 page」退化為「只統計有送 ringbuf event 的
dup page」。對工作 A 的分析目的（了解重複 page 的內容類型）仍然足夠，
因為我們本來就只關心重複 page 的分類結果。

| 元件 | 移動前（BPF 端） | 移動後（userspace 端） |
|------|----------------|----------------------|
| 分類邏輯 | 4 個 bpf_loop callback | C 函式，無限制 |
| page_type_stats | BPF_MAP_TYPE_ARRAY | uint64_t[6] 全域陣列 |
| 統計對象 | 所有 page | 有送 event 的 dup page |
| Verifier insn count | ~1,000,001（超限） | 遠低於上限 |

---

## 設計總結：與 Guide 的差異對照

| 項目 | Guide 設計 | 實際實作 | 原因 |
|------|-----------|---------|------|
| Hook 函式 | `fentry/zswap_store_page` | `kprobe/zswap_store` | kernel 6.8 folio 遷移，原函式不存在；static linkage 限制 fentry |
| 參數型別 | 隱含 `struct page *` | `struct folio *` | kernel 6.8 API 變更 |
| Page VA 取得 | 未討論 | folio → pfn → direct map VA | 需要推算，引出 KASLR 問題 |
| KASLR 常數 | 未討論 | BPF 自行讀取並 cache | kernel 6.8 動態變數，硬編碼無效 |
| Hash 函式 | xxHash64 | FNV-1a 64-bit | BPF stack 512B 限制，unroll 爆炸 |
| 迴圈方式 | `#pragma unroll` | `bpf_loop()` | unroll 導致 stack 超限 |
| Page buffer | 未討論 | `BPF_MAP_TYPE_PERCPU_ARRAY` | BPF stack 無法存放 4096 bytes |
| Thrashing 偵測 | 未討論 | interval_ns + 5s 門檻 | 工作 A 擴充需求 |
| Page 內容分類 | 未討論 | userspace 分類器（4 位置 samples）| BPF verifier 100 萬 insn 上限（kernel 6.8） |
| Memory region 對應 | 未討論 | 未實作（hook 點限制） | swap context ≠ page owner；需 do_swap_page hook |