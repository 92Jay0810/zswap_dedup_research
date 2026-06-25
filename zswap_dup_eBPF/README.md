# zswap Content Dedup eBPF 工具

本工具實作 Initial Guide 的「階段一：量測 swap 中的內容重複率」，
以 eBPF 觀測進入 zswap 的 page 中有多少比例內容重複。

## 環境準備

```bash
make install-deps
make clean && make
```

---

## eBPF 設計說明

### Hook 點：`kprobe/zswap_store`

Guide 建議掛在 `zswap_store_page()`，但本環境為 **kernel 6.8**，此函式已不存在。
kernel 6.8 完成 folio API 遷移後，入口為 `zswap_store(struct folio *folio)`。

語意等價：zeromap 已在 swap 層過濾全零 page，每個觸發 `zswap_store` 的 page
都是待壓縮的非零內容，與 Guide 目標一致。

### KASLR 動態常數（kernel 6.8 特有問題）

從 `struct folio *` 計算 page virtual address 需要 `vmemmap_base` 和 `page_offset_base`。
在 kernel 6.8，這兩個變數是執行期動態值（每次開機因 KASLR 不同），不能硬編碼。

解法：userspace 把兩個變數的**符號地址**（從 `/proc/kallsyms` 讀取）注入 BPF map，
BPF 程式在第一次觸發時用 `bpf_probe_read_kernel` 讀出實際值並 cache，之後直接使用。

### Hash 演算法：FNV-1a（Guide 建議 xxHash64）

Guide 建議的 xxHash64 在 BPF verifier 下因 `#pragma unroll` 展開導致 stack 超過 512 bytes 而無法使用。

改用 **FNV-1a 64-bit**：每步只有 XOR + multiply，stack 只需一個 `u64`。
搭配 **`bpf_loop()`**（kernel 5.17+）做動態迴圈，verifier 只驗證 callback，無需 unroll。

Page 內容（4096 bytes）存放在 **`BPF_MAP_TYPE_PERCPU_ARRAY`**，繞過 BPF stack 限制。

完整的工程考量與失敗嘗試見 `engineering_notes.md`。

---

## 執行前確認 zswap 狀態

```bash
# 確認 zswap 已啟用（每次重開機後需重設）
cat /sys/module/zswap/parameters/enabled

# 若輸出為 N，手動啟用
sudo bash -c 'echo Y > /sys/module/zswap/parameters/enabled'

# 掛載 debugfs
sudo mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true

# 確認 zswap 有在收 page
sudo grep . /sys/kernel/debug/zswap/stored_pages
sudo grep . /sys/kernel/debug/zswap/pool_total_size

# 確認 swap 有啟用
swapon --show
```

---

## 執行 Monitor

**每 60 秒輸出到終端機：**
```bash
sudo ./zswap_dedup -i 60
```

**每 60 秒輸出並同時存到檔案：**
```bash
sudo ./zswap_dedup -i 60 | tee zswap_result_$(date +%Y%m%d_%H%M%S).log
```

---

## Workload

```bash
# 設定 kubectl
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

# 確認 pod 狀態
kubectl get pods
kubectl get pods -w
```

### W1: CloudSuite Media Streaming

```bash
# 啟動
kubectl apply -f media-streaming-limit.yaml

# 停止
kubectl delete job cloudsuite-media-client
kubectl delete job cloudsuite-media-streaming
```

### W2: DeathStarBench Hotel Reserve

```bash
# 重新部署
kubectl delete -f hotel-swap-test.yaml
kubectl apply -f hotel-swap-test.yaml
```

### W3: Python Web Form Image

```bash
# 重新部署
kubectl delete -f python.yaml
kubectl apply -f python.yaml
```

---

## ASLR 對比實驗

```bash
# 查看目前狀態（2 = 完整開啟）
cat /proc/sys/kernel/randomize_va_space

# 關閉 ASLR
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

# 恢復（實驗結束後務必執行）
sudo bash -c 'echo 2 > /proc/sys/kernel/randomize_va_space'
```
