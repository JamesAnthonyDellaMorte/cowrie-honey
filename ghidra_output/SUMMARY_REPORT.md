# Cowrie Honeypot Malware Analysis Report

**Date:** 2026-02-16
**Tool:** Ghidra 12.0.3 Headless Analyzer
**Samples:** 17 ELF binaries (15 successfully analyzed, 2 failed import)

---

## Overview

Three distinct malware families were identified across 17 samples captured by the Cowrie SSH honeypot:

| Family | Arch | Samples | Type |
|--------|------|---------|------|
| ELF Infector/Worm | x86-64 | 11 | File infector virus with propagation |
| XMRig Cryptominer | AARCH64 | 2 | Cryptocurrency miner (Monero) |
| Go-based Botnet | AARCH64 | 4 (2 failed) | Statically linked bot/RAT |

---

## Family 1: ELF File Infector (x86-64) — "bongripz4jezuz"

**Samples (11):** All `.16` suffix x86-64 files
- 4e6745cb7-.16 (2.5MB), 558ee07e7-.16 (4.5MB), 57055de03-.16 (328KB)
- 62dd195aa-.16 (1.1MB), 8099e4410-.16 (3.6MB), 8f2d4fed1-.16 (3.2MB)
- 9a2c429ae-.16 (3.4MB), a6dec4020-.16 (5.5MB), ab7187d0f-.16 (3.7MB)
- ad5a30ec9-.16 (4.0MB), ad68f4f4f-.16 (5.3MB)

**All share the same BuildID:** `a5bdb209387e06cba305d4d5db76c52b7cb6ea26`

### Characteristics
- **Format:** ELF 64-bit LSB PIE, x86-64, dynamically linked (glibc 2.2.5+)
- **Section headers stripped** — anti-analysis technique
- **Identical code across all samples** — different file sizes due to parasitic infection payload appended to varying host binaries
- **63 functions** total (small, focused malware)

### Behavior (from decompiled code)

1. **String Obfuscation:** Uses a custom character substitution cipher with two lookup tables:
   - Encoding table: `0123456789abcdefghijklmnopqrstuvzywxABCDEFGHIJKLMNOPQRSTUVZYWX|:. !#-/;&*'"`
   - Decoding table: `>@o$:,.l+*^?=)(|AB&%;D{!wkUxzvutsrqp_nm-ihgfFCcba~K23456789eyd1XSNQWTZMIRHGVOYLjPJE/][`
   - Obfuscated strings include file paths and C2 configuration

2. **Embedded Marker:** Base64 string `Ym9uZ3JpcHo0amV6dXoK` decodes to **"bongripz4jezuz"** — used as an infection marker to avoid re-infecting already-compromised binaries

3. **File Infection / Propagation:**
   - Gets current working directory (`getcwd`)
   - Opens directory and enumerates files (`opendir`/`readdir`)
   - Reads first 5 bytes of each file to check for ELF magic: `\x7fELF\x02` (64-bit ELF)
   - Checks infection marker (`bongripz4jezuz`) to skip already-infected files
   - Infects clean ELF binaries via `FUN_00101460` — prepends/appends parasitic code
   - Uses `ftruncate`, `lseek`, `read`, `write` for binary manipulation

4. **Process Management:**
   - Forks child processes (`fork`/`waitpid`)
   - Executes payloads (`execve`)
   - Uses temporary files (`tmpnam`)

5. **Persistence:**
   - Opens a socket (obfuscated via `FUN_00100e70` → `open`)
   - Connects with `fchmod` (0xbff = mode 05777 — setuid sticky)
   - Sets up ioctl with terminal control (0x40086602 — TIOCSWINSZ)

### Key Imports
`execve`, `fork`, `waitpid`, `opendir`, `readdir`, `memmem`, `ftruncate`, `ioctl`, `tmpnam`, `access`, `unlink`

---

## Family 2: XMRig Cryptominer (AARCH64)

**Samples (2):**
- 7412c5d4b-.b0s (3.0MB) — SHA256: `2b9bedfe...`
- efb006f1d-.16 (3.4MB) — SHA256: `298b05a5...` (AARCH64 despite .16 extension)

### Characteristics
- **Format:** ELF 64-bit LSB executable, AARCH64, dynamically linked
- **7,292 functions** — massive codebase
- **16MB decompiled output** per sample
- **Linked against:** libpthread, libc, libdl

### Identification as XMRig
The dependency chain in the hardcoded RPATH is a definitive XMRig fingerprint:
```
/root/aarch64-libs/curl/lib
/usr/local/aarch64/krb5-1.20.1/src/lib/krb5
/usr/local/aarch64/krb5-1.20.1/src/lib/crypto
/root/keyutils-1.4
/usr/local/aarch64/libuv/lib      <-- event loop (XMRig core)
/usr/local/aarch64/hwloc/lib      <-- CPU topology (XMRig thread pinning)
/usr/aarch64-linux-gnu/lib
```

**libuv** (async I/O event loop) + **hwloc** (hardware locality/CPU pinning) + **curl** + **OpenSSL** + **Kerberos** is the exact dependency set of XMRig compiled with TLS and proxy support.

### Crypto Capabilities (from symbols)
- Full OpenSSL suite: AES-128/256 (ARMv8 NEON accelerated), ChaCha20, RSA, ECDSA
- ARMv8 hardware AES: `aes_v8_encrypt`, `aes_v8_ctr32_encrypt_blocks`, `NEON_aese`/`NEON_aesmc`
- CRYPTOGAMS optimized assembly for GHASH, Montgomery multiplication
- C++ standard library (STL) — compiled with g++

### Network Capabilities
- Full socket API: `socket`, `connect`, `bind`, `listen`, `sendto`, `recvfrom`
- DNS resolution: `getaddrinfo`, `getnameinfo`, `gethostbyname`
- IPv4/IPv6: `inet_pton`, `inet_ntop`
- TLS via OpenSSL (`SSL_*`, `ossl_statem_*`)
- Epoll-based event loop: `epoll_create1`, `epoll_ctl`, `epoll_pwait`

### Persistence
- `daemon()`, `setsid()`, `setuid()` — daemonize and drop privileges
- `inotify_init1`, `inotify_add_watch`, `inotify_rm_watch` — file monitoring
- `sched_setaffinity`, `pthread_setaffinity_np` — CPU pinning for mining

### Notes
- Mining pool configuration and wallet addresses are likely encrypted/obfuscated (no cleartext strings found)
- Cross-compiled on x86 host for AARCH64 target (visible from build paths: `/root/aarch64-libs/`)

---

## Family 3: Go-based Botnet (AARCH64, statically linked)

**Samples successfully analyzed (2):**
- 7f689ea10-aarch64 (1.7MB) — 913 functions
- a154cf15b-aarch64 (2.2MB) — 919 functions

**Samples that failed Ghidra import (2):**
- 75ce450a7-aarch64 (2.7MB) — corrupted ELF section headers
- 8288f8ec6-aarch64 (3.2MB) — corrupted ELF section headers

### Characteristics
- **Format:** ELF 64-bit LSB executable, AARCH64, **statically linked**
- **Completely stripped** — no imports, no exported strings, no symbols
- **Go runtime confirmed** — 669 occurrences of the goroutine stack-growth check pattern (`FUN_00075390`)
- Go's `unaff_x28` register (g pointer) and stack-split prologue present in every function

### Behavior Indicators
- Jump tables at `0x3229c0` — type switch dispatch (Go interface method resolution)
- Large data sections at `0x4e2xxx`–`0x517xxx` — Go runtime data, likely contains encrypted C2 config
- Memory management: `0x4000000` (64MB) page allocations — Go heap
- Complex control flow with many goroutine synchronization points

### Classification
Based on the characteristics (Go-compiled, statically linked, stripped, AARCH64, deployed via SSH honeypot), these are consistent with **Mirai-derivative** or similar IoT botnet agents written in Go. The fully stripped and statically linked nature makes detailed behavioral analysis difficult without dynamic execution.

---

## Failed Imports

| Sample | Reason |
|--------|--------|
| 75ce450a7-aarch64 | `MemorySectionResolver` error — corrupted/manipulated ELF section headers |
| 8288f8ec6-aarch64 | Same error — likely same malware family with anti-analysis section header corruption |

---

## IOCs Summary

### Infection Markers
- Base64 marker: `Ym9uZ3JpcHo0amV6dXoK` → `bongripz4jezuz`
- BuildID (ELF Infector): `a5bdb209387e06cba305d4d5db76c52b7cb6ea26`

### Build Environment (XMRig)
- `/root/aarch64-libs/curl/lib`
- `/usr/local/aarch64/krb5-1.20.1/`
- `/root/keyutils-1.4`
- `/usr/local/aarch64/libuv/lib`
- `/usr/local/aarch64/hwloc/lib`

### Obfuscation Techniques
- Custom character substitution cipher (ELF Infector)
- Stripped section headers (all families)
- Encrypted/obfuscated config (XMRig pool/wallet not in cleartext)
- Statically compiled Go binaries with all symbols stripped (Botnet)
- Anti-analysis ELF header corruption (2 samples)

---

## SHA256 Hashes

### ELF Infector (x86-64)
```
75d1dc15537c7f72cf410173ed5f94c449fd90155b65cabb0172f7388db9e80c  4e6745cb7-.16
1fb50d473c9f0c039a393aeb61da27192105735324e8833645cb843a1bd0a571  558ee07e7-.16
57055de03ab6a71b021eae323e170bc18a6ee3202ac2947e3d07a54611067242  57055de03-.16
a0fd742259fd49aec9811fc01aff601c660b8cd58b0dc6fa2492757418277f18  62dd195aa-.16
8231005cbd8ab104efaaee5b3e31f2be5eb45fae113c5006968fc09f72b3aa5e  8099e4410-.16
12978ba9937e6d2c882687666d9cfbe4d0e5161ddad9c2d44ddc3a2c46b8612b  8f2d4fed1-.16
676d611d48941d5715e8244b844edcd3bffaaf74bac157984a10e8bbc8b153ba  9a2c429ae-.16
a6dec4020dd2cb4dadbf4f7d0e78a2c735f9e64cc70047d6979101d3890fd233  a6dec4020-.16
3f6f4ea89975b3c6f86db599eb3fcc146e646b46ad1dcb74884642032b83a23e  ab7187d0f-.16
0b1f5dcbbe0e86e1962fdbea01aa32e982b5be9ce3781f507c10f381ef63d8f3  ad5a30ec9-.16
e727005480525cc70c71efa2690c8287f66d85d953e2053925e7cf93c542eaa0  ad68f4f4f-.16
```

### XMRig Cryptominer (AARCH64)
```
2b9bedfe9d519d0d21fa2b2198bbc8c1b403652bcd76b44a0bee61df318dcdc0  7412c5d4b-.b0s
298b05a598ebc33dd12a245669c45a4905faf07934d4b1db5f38b6018b43f72b  efb006f1d-.16
```

### Go Botnet (AARCH64)
```
18aa86c3604e2ef84862863af4ca9ee00fd53de9b1c8339476f59a8d6e0c5613  7f689ea10-aarch64
581e8603f4fc343fa4676b06189cabbae48fcdf49efc241aa882a76fe04d0264  a154cf15b-aarch64
29c42e9595bf3a2628d0e3804dea1c465321b96a313ede1aebbaf0d443c730da  75ce450a7-aarch64
62839dda44bdbc3bfcbbb4e6c03209f321fd5924e927ec9eb3711100d119668c  8288f8ec6-aarch64
```
