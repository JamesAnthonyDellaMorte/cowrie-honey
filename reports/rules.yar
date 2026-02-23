/*
 * Custom YARA rules for honeypot malware classification
 * Built from real samples captured by Cowrie SSH honeypot
 * Signatures derived from r2 + Ghidra analysis of captured binaries
 * Author: James
 */


// ============================================================
// REDTAIL CRYPTOMINER FAMILY
// UPX-packed (standard + modified header), multi-arch
// Statically linked, stripped section headers, LZMA compressed
// Unique UPX block signature: 3f 91 45 84
// ============================================================

rule Redtail_Miner_UPX
{
    meta:
        author      = "James"
        family      = "Redtail"
        description = "Redtail cryptominer — UPX packed ELF with unique block signature"
        severity    = "high"

    strings:
        // UPX header (standard or #-modified) followed by LZMA method (0x0e),
        // l_info, p_info, and the Redtail-unique compressed block magic 3f914584.
        // This 38-byte pattern spans UPX! magic through the block header and
        // matches ALL Redtail architectures (x86_64, i686, arm7, arm8).
        // Confirmed: 141/141 Redtail, 0/57 non-Redtail in sample corpus.
        $upx_block = {
            55 50 58 21           // "UPX!" magic
            ?? ??                 // version, format
            0e                    // method = LZMA
            ??                    // level
            00 00 00 00           // l_checksum (always zero)
            ?? ?? ?? 00           // compressed size
            ?? ?? ?? 00           // uncompressed size
            ?? ?? 00 00           // file offset
            ?? 00 00 00           // filter id
            0e 00 00 00           // block header type (0x0e = ELF)
            ?? ?? 00              // block header padding
            3f 91 45 84           // Redtail-unique compressed block signature
        }

    condition:
        uint32(0) == 0x464C457F  // ELF magic
        and filesize < 2MB
        and $upx_block
}

rule Redtail_Dropper_Script
{
    meta:
        author      = "James"
        family      = "Redtail"
        description = "Redtail setup/dropper shell script"
        severity    = "high"

    strings:
        $arch1 = "redtail.x86_64" ascii
        $arch2 = "redtail.i686" ascii
        $arch3 = "redtail.arm7" ascii
        $arch4 = "redtail.arm8" ascii
        $arch5 = "redtail.$ARCH" ascii
        $arch6 = "redtail.$a" ascii
        $name1 = "rm -rf redtail" ascii
        $name2 = "echo \"redtail\"" ascii
        $name3 = ".redtail" ascii

    condition:
        filesize < 10KB
        and (2 of ($arch1, $arch2, $arch3, $arch4) or 2 of ($arch5, $arch6, $name1, $name2, $name3))
}

rule Redtail_Clean_Script
{
    meta:
        author      = "James"
        family      = "Redtail"
        description = "Redtail competitor-cleaning script — kills other miners, scrubs crontabs"
        severity    = "medium"

    strings:
        $func    = "clean_crontab" ascii
        $chattr  = "chattr -ia" ascii
        $c3pool  = "c3pool_miner" ascii
        $spool   = "/var/spool/cron" ascii
        $grep    = /grep -vE ['"].*wget.*curl.*\/tmp/ ascii
        $tmpwipe = /rm -rf \/tmp\/\*/ ascii

    condition:
        filesize < 5KB
        and $func
        and 2 of ($chattr, $c3pool, $spool, $grep, $tmpwipe)
}


// ============================================================
// TROJAN SSHD (Go-based SSH backdoor + credential stealer)
// Compiled Go binary with CGO, PAM integration, SFTP support
// Dual miner (XMRig + NBMiner), credential-stuffing attack queue
// Persistence via systemd-worker.service
// r2 analysis: all 26 samples share 4,896 common strings
// ============================================================

rule Trojan_SSHD_Go_Backdoor
{
    meta:
        author      = "James"
        family      = "TrojanSSHD"
        description = "Go-based SSH trojan with credential theft, PAM hooks, dual miner config, and systemd persistence"
        severity    = "critical"

    strings:
        // CGO build hashes — consistent across sample variants
        $cgo1        = "_cgo_6cc2654a8ed3" ascii
        $cgo2        = "_cgo_eba3282b571c" ascii
        $cgo3        = "_cgo_129d52bb6bd3" ascii

        // Go package imports revealing intent
        $pam         = "github.com/msteinert/pam" ascii
        $sftp        = "github.com/pkg/sftp" ascii
        $gopsutil_p  = "github.com/shirou/gopsutil/process" ascii
        $gopsutil_c  = "github.com/shirou/gopsutil/cpu" ascii

        // Dual miner configuration (XMRig + NBMiner)
        $xmrig       = "Xmrig_enabled" ascii
        $nbminer     = "Nbminer_enabled" ascii

        // Attack/credential structures
        $attackqueue = "attackqueue" ascii
        $credential  = "main.credential" ascii
        $rig_config  = "main._rig_config" ascii

        // Persistence
        $systemd     = "systemd-worker.service" ascii

    condition:
        uint32(0) == 0x464C457F  // ELF
        and filesize > 200KB
        and any of ($cgo1, $cgo2, $cgo3)
        and 2 of ($pam, $sftp, $gopsutil_p, $gopsutil_c)
        and 2 of ($attackqueue, $credential, $rig_config, $xmrig, $nbminer, $systemd)
}

rule Trojan_SSHD_Go_PAM
{
    meta:
        author      = "James"
        family      = "TrojanSSHD"
        description = "Go-based SSH trojan with PAM hooks — variant CGO builds"
        severity    = "high"

    strings:
        $libpam     = "libpam.so" ascii
        $pam_conv   = "Cfunc_init_pam_conv" ascii
        $pam_auth   = "Cfunc_pam_chauthtok" ascii
        $pam_start  = "Cfunc_pam_start" ascii
        $pam_cb     = "cbPAMConv" ascii
        $cgo        = "_cgo_" ascii
        $getpwnam   = "Cfunc_mygetpwnam_r" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize > 200KB
        and $libpam
        and 2 of ($pam_conv, $pam_auth, $pam_start, $pam_cb, $getpwnam)
        and $cgo
}


// ============================================================
// DOT16 / B0S FAMILY
// ARM64 dynamically linked binaries from same actor toolkit
// Includes libcurl-build variants and processhider/sshd variants
// ============================================================

rule Dot16_B0s_Aarch64_Bot
{
    meta:
        author      = "James"
        family      = "Dot16_B0s"
        description = "Aarch64 Dot16/B0s toolkit binary (miner/backdoor variants)"
        severity    = "high"

    strings:
        $build_path = "/root/aarch64-libs/curl/lib" ascii
        $krb5_path  = "/usr/local/aarch64/krb5-1.20.1" ascii
        $hider_path = "/f/aarch64/libprocesshider.so" ascii
        $preload    = "/etc/ld.so.preload" ascii
        $ssh_guard  = "SSH_ORIGINAL_COMMAND" ascii
        $ipcheck    = "http://api.ipify.org" ascii

    condition:
        uint32(0) == 0x464C457F
        and uint16(0x12) == 0x00B7  // ARM64
        and filesize > 100KB
        and (
            any of ($build_path, $krb5_path)
            or ($hider_path and $preload and 1 of ($ssh_guard, $ipcheck))
        )
}

rule Aarch64_Go_Packed_Bot
{
    meta:
        author      = "James"
        family      = "Aarch64GoBot"
        description = "Statically linked ARM64 Go binary — packed bot with known build ID"
        severity    = "high"

    strings:
        // Go build ID seen across all known samples of this family
        $gobuildid   = "kSkyaQnBpMWHzhzftUbB/3Ikfs90WHFlfPTOw24GH" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize > 500KB
        // ARM64 ELF: e_machine at offset 0x12 == 0xB7
        and uint16(0x12) == 0x00B7
        and $gobuildid
}


// ============================================================
// UPX-PACKED GO SSH SCANNER (i386)
// UPX 4.01 packed ELF with consistent pack-header block signature
// Unpacked samples expose Go SSH brute/scanner functions
// ============================================================

rule Go_SSH_Scanner_UPX
{
    meta:
        author      = "James"
        family      = "GoSSHScanner"
        description = "UPX-packed i386 Go SSH scanner/bruter payload"
        severity    = "high"

    strings:
        // Stable UPX block header observed in this payload lineage
        $upx_block = {
            55 50 58 21 f8 08 0e 0c
            00 00 00 00
            00 70 33 00
            00 70 33 00
            f4 00 00 00
            86 00 00 00
            08 00 00 00
            77 1f a4 f9
        }
        $ssh1    = "SSH-," ascii
        $ssh2    = ":ssh-" ascii
        $xmr     = "\"XMR" ascii
        $upx_ver = "UPX 4.01 Copyright (C) 1996-2022 the UPX Team." ascii
        $selfexe = "/proc/self/exe" ascii

    condition:
        uint32(0) == 0x464C457F
        and uint16(0x12) == 0x0003  // i386
        and filesize > 900KB
        and filesize < 2MB
        and $upx_block
        and $ssh1 and $ssh2
        and $upx_ver
        and 1 of ($xmr, $selfexe)
}


// ============================================================
// OBFUSCATED UPX SSH/XMR BOT (x86-64)
// Large static ELF64 payloads with repeated embedded UPX stubs.
// Current corpus: 43/43 hits on unmatched set, 0 hits on known families.
// ============================================================

rule Obf_UPX_SSH_XMR_x64
{
    meta:
        author      = "James"
        family      = "ObfUPX_SSHXMR"
        description = "Obfuscated UPX-packed x86-64 payload with SSH/XMR indicators"
        severity    = "high"

    strings:
        // Actor-specific UPX block signature observed at the first "/UPX!" stub.
        $upx_actor_sig = {
            2f 55 50 58 21 f8 0a 0e
            16 00 00 00
            00 87 50 42
            01 60 31 c1
            00 58 01 00
            00 7b 00 00
            00 08 00 00
            00 bb fb 20 ff 7f 45 4c
        }

    condition:
        uint32(0) == 0x464C457F
        and uint16(0x12) == 0x003E  // x86-64
        // Include 96KB truncated pulls that share the same actor UPX stub.
        and filesize >= 96KB
        and $upx_actor_sig
}

// ============================================================
// GO SSH SCANNER / DROPPER (x86-64 cache variant, often partial)
// Shares a stable UPX header block and entrypoint across cache samples.
// ============================================================

rule Go_SSH_Scanner_UPX_x64_Cache
{
    meta:
        author      = "James"
        family      = "GoSSHScanner"
        description = "UPX-packed x86-64 cache variant with ftp/ssh/tcp markers"
        severity    = "high"

    strings:
        $upx_cache_sig = {
            2f 55 50 58 21 fc 0a 0e
            16 00 00 00
            00 87 b0 2b
            00 b5 e4 18
            00 58 01 00
            00 7c 00 00
            00 08 00 00
        }
        $proto_mix = "dLdpftpssh::)" ascii
        $tcp_fmt   = "tcp%s" ascii
        $selfexe   = "/proc/self/exe" ascii
        $upx_ver   = "UPX 4.23 Copyright (C) 1996-2024 the UPX Team." ascii

    condition:
        uint32(0) == 0x464C457F
        and uint16(0x12) == 0x003E  // x86-64
        and uint32(0x18) == 0x00814E90
        and uint32(0x1C) == 0x00000000
        and $upx_cache_sig
        and (
            filesize < 200KB
            or any of ($proto_mix, $tcp_fmt, $selfexe, $upx_ver)
        )
}


// ============================================================
// XORDDOS FAMILY
// Statically linked i386 with init.d persistence
// ============================================================

rule XorDDoS_ELF
{
    meta:
        author      = "James"
        family      = "XorDDoS"
        description = "XorDDoS bot — statically linked i386 with init.d persistence and /proc/self/exe"
        severity    = "critical"

    strings:
        $histfile  = "HISTFILE=/dev/null" ascii
        $mysql     = "MYSQL_HISTFILE=/dev/null" ascii
        $procself  = "/proc/self/exe" ascii
        $procpid   = "/proc/%d/exe" ascii
        $chkconfig = "# chkconfig:" ascii
        $initinfo  = "### BEGIN INIT INFO" ascii

    condition:
        uint32(0) == 0x464C457F
        // i386 ELF (XorDDoS lineage in this corpus)
        and uint16(0x12) == 0x0003
        and filesize < 1MB
        and $procself
        and $histfile
        and any of ($chkconfig, $initinfo, $procpid, $mysql)
}


// ============================================================
// SSH KEY INJECTION
// ============================================================

rule SSH_Key_Injection
{
    meta:
        author      = "James"
        family      = "SSHKeyInjection"
        description = "Script/payload that injects attacker SSH keys into authorized_keys"
        severity    = "medium"

    strings:
        $key1 = "ssh-rsa AAAA" ascii
        $key2 = "ssh-ed25519 AAAA" ascii
        $key3 = "ssh-dss AAAA" ascii
        $auth = "authorized_keys" ascii
        $mkdir = "mkdir -p ~/.ssh" ascii
        $chmod1 = "chmod 700 ~/.ssh" ascii
        $chmod2 = "chmod 600 ~/.ssh/authorized_keys" ascii
        $append = ">> ~/.ssh/authorized_keys" ascii
        $echo = "echo \"" ascii

    condition:
        filesize < 20KB
        and filesize > 80
        and any of ($key1, $key2, $key3)
        and $auth
        and 2 of ($mkdir, $chmod1, $chmod2, $append, $echo)
}


// ============================================================
// DOT16 XMRIG MINER FAMILY (x86-64)
// Bundled XMRig with RandomX JIT, libcurl, and persistence
// Deployed as .16 and .b0s on x86-64 (aarch64 covered by Dot16_B0s)
// Multiple wallets/operators sharing same build
// ============================================================

rule Dot16_XMRig_Miner
{
    meta:
        author      = "James"
        family      = "Dot16_XMRig"
        description = "XMRig miner with RandomX JIT — deployed as .16/.b0s/.X0-lock by Dot16 actor"
        severity    = "high"

    strings:
        // C++ mangled XMRig RandomX JIT symbols — survive even in 98KB partial downloads
        $jit     = "randomx14JitCompilerX86" ascii
        $threads = "xmrig7Threads" ascii
        // Dot16 actor deployment markers
        $dot16_cfg = ".16.json" ascii
        $b0s_cfg   = ".b0s.json" ascii
        $x0lock    = ".X0-lock" ascii
        // Dot16 x86_64 build-toolchain fingerprint observed in both dl and unanalyzed sets
        $curl_static = "/root/curl-static/lib64" ascii
        $krb5_src    = "/usr/local/src/krb5-1.20.1/src/lib/krb5" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize > 50KB
        and $jit
        and $threads
        and (
            any of ($dot16_cfg, $b0s_cfg, $x0lock)
            or ($curl_static and $krb5_src)
        )
}


// ============================================================
// DOT16 DROPPER (.X0-lock)
// Downloads and deploys .16 XMRig miners + snapd persistence
// Uses libcurl, copyAndExecute pattern
// ============================================================

rule Dot16_Dropper
{
    meta:
        author      = "James"
        family      = "Dot16_Dropper"
        description = "Dot16 dropper — downloads .16 miners and snapd, copyAndExecute deployment"
        severity    = "high"

    strings:
        $copy_exec = "copyAndExecute" ascii
        $dl_from   = "Downloading from:" ascii
        $miner_run = "Miner running:" ascii
        $snapd_chk = "snapd doesn't exist or is invalid" ascii
        $dot16_path = "/f/x86_64/.16" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize > 100KB
        // Require actor-specific path/marker plus one behavioral string
        and (
            ($dot16_path and 1 of ($copy_exec, $dl_from, $miner_run, $snapd_chk))
            or ($copy_exec and 1 of ($dl_from, $miner_run, $snapd_chk))
        )
}


// ============================================================
// BILLGATES DDOS BOT (kswpad variant)
// C++ DDoS bot with full attack class hierarchy
// Statically linked i386, not stripped
// ============================================================

rule BillGates_DDoS
{
    meta:
        author      = "James"
        family      = "BillGates"
        description = "BillGates DDoS bot — C++ class hierarchy with multi-vector attack capability"
        severity    = "critical"

    strings:
        $bill_status = "CBillStatus" ascii
        $update_bill = "CUpdateBill" ascii
        $update_gates = "CUpdateGates" ascii
        $mon_gates   = "CThreadMonGates" ascii
        $task_gates  = "CThreadTaskGates" ascii
        $attack_syn  = "CAttackSyn" ascii
        $attack_dns  = "CAttackDns" ascii
        $attack_udp  = "CAttackUdp" ascii

    condition:
        uint32(0) == 0x464C457F
        // BillGates family samples here are i386 static ELF
        and uint16(0x12) == 0x0003
        and filesize > 100KB
        and any of ($bill_status, $update_bill, $update_gates, $mon_gates, $task_gates)
        and 2 of ($attack_syn, $attack_dns, $attack_udp)
}


// ============================================================
// GO DDOS BOT (amd64)
// Go-compiled multi-vector DDoS bot with spoofing, proxy, encryption
// Statically linked x86-64
// ============================================================

rule Go_DDoS_Bot
{
    meta:
        author      = "James"
        family      = "GoDDoS"
        description = "Go-compiled DDoS bot with multi-vector attacks, IP spoofing, and XOR encryption"
        severity    = "critical"

    strings:
        // Full function names (unstripped builds)
        $attack_run = "main.Attack_Run" ascii
        $spoof      = "main.Spoof" ascii
        $xor_enc    = "main.XorEnc" ascii
        $xor_dec    = "main.XorDec" ascii
        $allowlist  = "main.(*Allowlist)" ascii
        $watchdog   = "main.Watchdog" ascii
        $plain_udp  = "main.Plain_Udp" ascii
        $socks5     = "main.Socks5Connect" ascii
        $initsh     = "main.initsh" ascii
        $rclocal    = "main.rclocal" ascii
        // Go type descriptors (survive stripping)
        $type_allow = "*main.Allowlist" ascii
        $type_proxy = "*main.Proxy" ascii
        $type_tcp   = "*main.TCP" ascii
        $type_rng   = "*main.RNG" ascii
        $type_ini   = "*main.ini" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize > 500KB
        and (
            ($attack_run and 2 of ($spoof, $xor_enc, $xor_dec, $allowlist, $watchdog, $plain_udp, $socks5, $initsh, $rclocal))
            or (3 of ($type_allow, $type_proxy, $type_tcp, $type_rng, $type_ini))
        )
}

rule Go_DDoS_Bot_Partial_amd64
{
    meta:
        author      = "James"
        family      = "GoDDoS"
        description = "amd64 Go DDoS build-ID variant (matches partial and larger stripped builds)"
        severity    = "high"

    strings:
        $build_id = "9aweAb3NxvdjkKSF5j5z/-6qEjXc-SfQjEyoBRUWa/M_49j5sTTJLMK3MMdr3g/OVx2LvkSFU1AaVRWkhzu" ascii

    condition:
        uint32(0) == 0x464C457F
        and uint16(0x12) == 0x003E
        and filesize > 150KB
        and filesize < 2MB
        and uint32(0x18) == 0x00467E20
        and uint32(0x1C) == 0x00000000
        and $build_id
}


// ============================================================
// KAITEN WEB3 DROPPER (kal64)
// Go dropper that embeds and releases a "web3server" binary
// Kills competing processes, cleans up after deployment
// ============================================================

rule Kaiten_Web3Dropper
{
    meta:
        author      = "James"
        family      = "KaitenDropper"
        description = "Go-based dropper that releases embedded web3server binary"
        severity    = "high"

    strings:
        $web3_release = "main.releaseAndRunWeb3Server" ascii
        $clean_file   = "main.cleanFileAndProcess" ascii
        $kill_proc    = "main.killProcessByName" ascii
        $delete_file  = "main.deleteFile" ascii
        $web3_str     = "web3server" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize > 500KB
        and $web3_release
        and any of ($clean_file, $kill_proc, $delete_file, $web3_str)
}


// ============================================================
// PROCESS HIDER (LD_PRELOAD rootkit)
// Hooks readdir/readdir64 to hide processes from ps/top
// Loaded via /etc/ld.so.preload
// ============================================================

rule ProcessHider_LDPreload
{
    meta:
        author      = "James"
        family      = "ProcessHider"
        description = "LD_PRELOAD rootkit that hooks readdir to hide processes from ps/top"
        severity    = "critical"

    strings:
        // Unstripped builds
        $src             = "processhider.c" ascii
        $filter          = "process_to_filter" ascii
        $orig_readdir    = "original_readdir" ascii
        $orig_readdir64  = "original_readdir64" ascii
        $get_proc_name   = "get_process_name" ascii
        $get_dir_name    = "get_dir_name" ascii
        // Behavioral strings (survive stripping)
        $proc_stat       = "/proc/%s/stat" ascii
        $proc_fd         = "/proc/self/fd/%d" ascii
        $dlsym_err       = "Error in dlsym: %s" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize < 100KB
        and (
            ($src and any of ($filter, $orig_readdir, $orig_readdir64, $get_proc_name, $get_dir_name, $proc_stat))
            or ($proc_stat and $proc_fd and $dlsym_err)
        )
}


// ============================================================
// DOT16 SSHD BACKDOOR
// Packed/encrypted network backdoor deployed as /tmp/sshd
// Uses zlib decompression, dlopen for runtime loading,
// implements accept/fork daemon with STARTTLS/SASL auth
// ============================================================

rule Dot16_SSHD_Backdoor
{
    meta:
        author      = "James"
        family      = "Dot16_Backdoor"
        description = "Packed network backdoor deployed as sshd — zlib-compressed, STARTTLS/SASL auth, command execution"
        severity    = "critical"

    strings:
        // Linked libraries (specific combination)
        $libz       = "libz.so.1" ascii
        $libpthread = "libpthread.so.0" ascii
        $libdl      = "libdl.so.2" ascii
        // Protocol strings embedded in packed binary
        $starttls   = "STARTTLS" ascii
        $sasl       = "SASL" ascii
        // Runtime behavior
        $daemon     = "daemon" ascii
        $syslog     = "syslog" ascii
        $prctl      = "prctl" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize > 50KB
        and filesize < 10MB
        and $libz and $libpthread and $libdl
        and $starttls
        and 2 of ($sasl, $daemon, $syslog, $prctl)
}


// ============================================================
// DHPCD XMRIG MINER (UPX-packed, different actor from Redtail/Dot16)
// Wallet: 82WBefqugLBf... — survives UPX compression
// Disguised as dhpcd (DHCP daemon)
// ============================================================

rule DHPCD_XMRig_Miner
{
    meta:
        author      = "James"
        family      = "DHPCD_XMRig"
        description = "UPX-packed XMRig miner disguised as dhpcd — unique wallet survives packing"
        severity    = "high"

    strings:
        $wallet = "82WBefqugLBfZQg" ascii
        $upx    = "UPX!" ascii
        $upx_ver = "UPX 4.24" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize > 100KB
        and $wallet
        and ($upx or $upx_ver)
}


// ============================================================
// COMPETITOR KILLER / CLEANER
// Scans /proc for known malware paths and kills them
// Checks for libprocesshider.so, validates ELF binaries,
// monitors CPU usage of suspicious processes
// Built with crosstool-NG 1.23.0 / GCC 6.3.0
// ============================================================

rule CompetitorKiller_Scanner
{
    meta:
        author      = "James"
        family      = "CompetitorKiller"
        description = "Process scanner that detects and kills competing malware by path and CPU usage"
        severity    = "medium"

    strings:
        $deleted    = "deleted binary %s" ascii
        $whitelist  = "whitelisted" ascii
        $highcpu    = "high CPU usage" ascii
        $elf_check  = "File %s is not ELF" ascii
        $hider1     = "/lib/libprocesshider.so" ascii
        $hider2     = "/lib64/libprocesshider.so" ascii
        $crosstool  = "crosstool-ng-1.23.0" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize > 50KB
        and $deleted
        and any of ($whitelist, $highcpu, $elf_check, $hider1, $hider2, $crosstool)
}


// ============================================================
// DHPCD DROPPER (minimal network component)
// Same crosstool-NG toolchain as CompetitorKiller
// Tiny static binary, likely downloads/deploys the XMRig miner
// ============================================================

rule DHPCD_Dropper
{
    meta:
        author      = "James"
        family      = "DHPCD_Dropper"
        description = "Minimal static dropper from DHPCD toolkit — crosstool-NG compiled"
        severity    = "medium"

    strings:
        $crosstool = "crosstool-ng-1.23.0" ascii
        $gcc       = "GCC: (crosstool-NG" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize > 10KB
        and filesize < 100KB
        and $crosstool
        and $gcc
}
