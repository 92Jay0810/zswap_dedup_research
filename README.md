# zswap Dedup Research

This repository contains the final project for **Advanced Storage Systems**, **NTHU - Spring 2026**.

Course website: [Advanced Storage Systems](https://lego.sys-nthu.tw/)

## Project Background

`zswap` is a Linux kernel feature that keeps swapped-out pages in a compressed memory pool before writing them to a swap device. This project studies whether pages entering `zswap` contain repeated content, and whether this duplicate content can be observed under container workloads.

The main goal is not to modify the kernel yet, but to build a measurement pipeline:

1. Generate memory pressure from container workloads.
2. Trace pages entering `zswap`.
3. Hash page contents with eBPF.
4. Estimate duplicate-page ratio, memory-saving potential, and repeated-page behavior.
5. Compare container workloads with and without extra `stress-ng` memory pressure.

## Repository Layout

```text
.
├── container_workload_stress-ng/
│   └── Kubernetes workload scripts with stress-ng memory pressure
├── container_workload_stress-ng_log/
│   └── Logs collected from workloads that include stress-ng
├── container_worklod_only/
│   └── Kubernetes workload scripts for pure application workloads
├── container_worklod_only_log/
│   └── Logs collected from pure workload experiments
├── stress/
│   └── A small custom memory-pressure program
└── zswap_dup_eBPF/
    └── eBPF-based zswap duplicate-page measurement tool
```

Note: the folder name `container_worklod_only` is kept as-is to match the original experiment directory.

## Workload Folders

### `container_workload_stress-ng/`

This folder contains Kubernetes YAML scripts where the application workload is combined with `stress-ng`.

These scripts are used to create stronger and more controlled memory pressure, making it easier to push pages into swap and observe `zswap` behavior.

Included workloads:

- CloudSuite Media Streaming
- DeathStarBench Hotel Reservation
- Python API Farm

### `container_worklod_only/`

This folder contains Kubernetes YAML scripts for pure application workloads, without additional `stress-ng` memory pressure.

These experiments are used as a comparison group to see whether the application workload alone can create enough memory pressure to trigger `zswap` activity.

### Log Folders

The corresponding log folders contain output collected from the eBPF monitor:

- `container_workload_stress-ng_log/`
- `container_worklod_only_log/`

The logs include:

- total pages entering `zswap`
- unique page count
- duplicate page count
- estimated deduplication ratio
- estimated memory saved
- thrashing events
- sampled duplicate-page content types such as `ZERO`, `TEXT/ASCII`, `PTR_HEAVY`, and `BINARY`

## eBPF zswap Dedup Tool

The eBPF tool is in:

```bash
zswap_dup_eBPF/
```

It attaches to:

```text
kprobe/zswap_store
```

The implementation targets Ubuntu 24.04 / Linux kernel 6.8, where the older `zswap_store_page()` function no longer exists because of the kernel folio API migration.

Main implementation notes:

- uses `kprobe/zswap_store` to observe pages entering `zswap`
- reads dynamic kernel constants such as `vmemmap_base` and `page_offset_base` from `/proc/kallsyms`
- uses FNV-1a 64-bit hashing instead of xxHash64 to avoid BPF verifier stack issues
- stores page contents in a per-CPU BPF array buffer
- detects duplicate pages with an LRU hash map
- reports short-interval duplicate hits as possible thrashing events
- sends sampled page bytes to userspace for lightweight content classification

More detailed implementation notes are available in:

```bash
zswap_dup_eBPF/README.md
zswap_dup_eBPF/engineering_notes.md
```

## Environment

Tested environment:

- Ubuntu 24.04
- Linux kernel 6.8
- k3s / Kubernetes-based container workloads
- zswap enabled
- swap enabled
- root permission for eBPF tracing and `/proc/kallsyms`

## Build the eBPF Tool

```bash
cd zswap_dup_eBPF
make install-deps
make clean && make
```

## Check zswap Status

```bash
cat /sys/module/zswap/parameters/enabled
swapon --show
sudo mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
sudo grep . /sys/kernel/debug/zswap/stored_pages
sudo grep . /sys/kernel/debug/zswap/pool_total_size
```

If zswap is disabled:

```bash
sudo bash -c 'echo Y > /sys/module/zswap/parameters/enabled'
```

## Run the Monitor

Print statistics every 60 seconds:

```bash
cd zswap_dup_eBPF
sudo ./zswap_dedup -i 60
```

Save output to a log file:

```bash
sudo ./zswap_dedup -i 60 | tee zswap_result_$(date +%Y%m%d_%H%M%S).log
```

## Run Container Workloads

Set the kubeconfig first:

```bash
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
```

Apply one workload YAML:

```bash
kubectl apply -f container_workload_stress-ng/media-streaming-30pods.yaml
```

Watch pod status:

```bash
kubectl get pods -w
```

For pure workload experiments:

```bash
kubectl apply -f container_worklod_only/media_streaming_onlyworkload_30pods.yaml
```

## Custom Stress Program

The `stress/` folder contains a small C program that allocates memory and fills pages with random content. It can be used for simpler non-container memory-pressure tests.

Example:

```bash
cd stress
gcc stress.c -o stress
./stress 1500M 300
```

## Experiment Notes

The collected logs show that workloads with explicit `stress-ng` memory pressure are more likely to produce enough swapping activity for `zswap` measurement. Pure workload experiments may produce fewer `zswap` events if the workload alone does not create sufficient memory pressure.

The eBPF logs can be used to compare:

- duplicate-page ratio
- memory-saving potential
- page type distribution
- short-interval duplicate hits
- behavior under ASLR enabled or disabled

## References

- [Advanced Storage Systems](https://lego.sys-nthu.tw/)
- Linux `zswap`
- eBPF / libbpf
- Kubernetes workloads for containerized memory-pressure experiments
