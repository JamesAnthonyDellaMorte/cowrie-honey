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
// ARM64 dynamically linked, custom libcurl build path
// Cross-compiled with specific aarch64 toolchain
// ============================================================

rule Dot16_B0s_Aarch64_Bot
{
    meta:
        author      = "James"
        family      = "Dot16_B0s"
        description = "Aarch64 bot with custom libcurl cross-compilation toolchain"
        severity    = "high"

    strings:
        $build_path = "/root/aarch64-libs/curl/lib" ascii
        $krb5_path  = "/usr/local/aarch64/krb5-1.20.1" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize > 100KB
        and any of ($build_path, $krb5_path)
}

rule Aarch64_Go_Packed_Bot
{
    meta:
        author      = "James"
        family      = "Aarch64GoBot"
        description = "Statically linked ARM64 Go binary — packed bot with known build ID"
        severity    = "high"

    strings:
        // Go runtime pool structures (present in less-stripped variants)
        $sync_pool   = "*sync.Pool" ascii
        $deferpool   = "deferpool" ascii
        $framepool   = "framePool" ascii
        $writepool   = "writePool" ascii
        $buildonce   = "buildOnce" ascii
        // Go build ID seen across all known samples of this family
        $gobuildid   = "kSkyaQnBpMWHzhzftUbB/3Ikfs90WHFlfPTOw24GH" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize > 500KB
        // ARM64 ELF: e_machine at offset 0x12 == 0xB7
        and uint16(0x12) == 0x00B7
        and (
            3 of ($sync_pool, $deferpool, $framepool, $writepool, $buildonce)
            or $gobuildid
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
        description = "Injected SSH authorized_keys file"
        severity    = "medium"

    strings:
        $key1 = "ssh-rsa AAAA" ascii
        $key2 = "ssh-ed25519 AAAA" ascii
        $key3 = "ssh-dss AAAA" ascii

    condition:
        filesize < 10KB
        and filesize > 50
        and any of ($key1, $key2, $key3)
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

    condition:
        uint32(0) == 0x464C457F
        and filesize > 50KB
        and $jit
        and $threads
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
        and 2 of them
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

    condition:
        uint32(0) == 0x464C457F
        and filesize > 500KB
        and $attack_run
        and 2 of ($spoof, $xor_enc, $xor_dec, $allowlist, $watchdog, $plain_udp, $socks5, $initsh, $rclocal)
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
        $src             = "processhider.c" ascii
        $filter          = "process_to_filter" ascii
        $orig_readdir    = "original_readdir" ascii
        $orig_readdir64  = "original_readdir64" ascii
        $get_proc_name   = "get_process_name" ascii
        $get_dir_name    = "get_dir_name" ascii
        $proc_stat       = "/proc/%s/stat" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize < 100KB
        and $src
        and any of ($filter, $orig_readdir, $orig_readdir64, $get_proc_name, $get_dir_name, $proc_stat)
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
