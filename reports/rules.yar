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
