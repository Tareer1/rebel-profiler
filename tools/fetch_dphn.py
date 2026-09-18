#!/usr/bin/env python3
"""Parallel resumable range downloader for the dphn GGUF checkpoint.

Splits the file into N parts; each part downloads to dphn/.part-XX with
retries. A part is complete when its size matches the expected range size.
Re-running skips complete parts, so the download survives timeouts.
Finally: verify all parts, concatenate into the .gguf, verify size.
"""
import os
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

URL = ("https://huggingface.co/bartowski/Qwen2.5-Coder-7B-Instruct-abliterated-GGUF"
       "/resolve/main/Qwen2.5-Coder-7B-Instruct-abliterated-Q4_K_M.gguf")
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "dphn", "Qwen2.5-Coder-7B-Instruct-abliterated-Q4_K_M.gguf")
PART_DIR = os.path.join(os.path.dirname(OUT), ".parts-dphn")
PARTS = 16
UA = "Mozilla/5.0 (X11; Linux x86_64) rebel-profiler-setup/1.0"


def head_size():
    req = urllib.request.Request(URL, method="HEAD", headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return int(r.headers["Content-Length"])


def fetch_range(start, end, path, tries=12):
    want = end - start + 1
    if os.path.exists(path) and os.path.getsize(path) == want:
        return path, 0
    for attempt in range(1, tries + 1):
        have = os.path.getsize(path) if os.path.exists(path) else 0
        if have >= want:
            return path, 0
        req = urllib.request.Request(
            URL, headers={"User-Agent": UA, "Range": f"bytes={start + have}-{end}"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r, open(path, "ab") as f:
                while True:
                    chunk = r.read(1 << 20)
                    if not chunk:
                        break
                    f.write(chunk)
        except Exception as exc:
            time.sleep(min(2 * attempt, 10))
            continue
        if os.path.getsize(path) == want:
            return path, 1
    raise RuntimeError(f"part {os.path.basename(path)} incomplete after {tries} tries")


def main():
    os.makedirs(PART_DIR, exist_ok=True)
    total = head_size()
    print(f"total size: {total/1e9:.2f} GB in {PARTS} parts", flush=True)
    edges = [(i * total // PARTS, (i + 1) * total // PARTS - 1) for i in range(PARTS)]
    jobs = []
    for i, (s, e) in enumerate(edges):
        part = os.path.join(PART_DIR, f"part-{i:02d}")
        if os.path.exists(part) and os.path.getsize(part) == e - s + 1:
            print(f"part {i:02d}: already complete", flush=True)
            continue
        jobs.append((i, s, e, part))
    if not jobs:
        print("all parts complete", flush=True)
    else:
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=PARTS) as pool:
            futs = [pool.submit(fetch_range, s, e, p) for _i, s, e, p in jobs]
            for fut, (i, _s, e, p) in zip(futs, jobs):
                try:
                    _path, status = fut.result()
                    done = os.path.getsize(p)
                    rate = (done / 1e6) / max(time.time() - t0, 1)
                    print(f"part {i:02d}: ok {done/1e9:.2f}GB ({rate:.1f} MB/s agg)",
                          flush=True)
                except Exception as exc:
                    print(f"part {i:02d}: FAILED: {exc}", flush=True)
                    sys.exit(3)
    # concatenate
    missing = [i for i, (s, e) in enumerate(edges)
               if os.path.getsize(os.path.join(PART_DIR, f"part-{i:02d}")) != e - s + 1]
    if missing:
        print(f"incomplete parts: {missing}", flush=True)
        sys.exit(3)
    print("assembling...", flush=True)
    tmp = OUT + ".tmp"
    with open(tmp, "wb") as out:
        for i in range(PARTS):
            with open(os.path.join(PART_DIR, f"part-{i:02d}"), "rb") as f:
                while True:
                    chunk = f.read(1 << 22)
                    if not chunk:
                        break
                    out.write(chunk)
    got = os.path.getsize(tmp)
    if got != total:
        print(f"size mismatch: {got} != {total}", flush=True)
        sys.exit(4)
    os.replace(tmp, OUT)
    print(f"DONE: {OUT} ({got/1e9:.2f} GB)", flush=True)


if __name__ == "__main__":
    main()
