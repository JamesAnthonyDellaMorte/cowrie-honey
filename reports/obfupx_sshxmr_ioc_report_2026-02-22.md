# ObfUPX_SSHXMR IOC Report
Generated: 2026-02-22
Scope: Newly captured `ObfUPX_SSHXMR` cluster in `/root/cowrie/dl`

## Dataset Summary
- Files matched by YARA family `ObfUPX_SSHXMR`: `43`
- Unique SHA256 samples: `38`
- Hash inventory file: `reports/obfupx_sshxmr_hashes.txt`

## Campaign Telemetry (Cowrie Logs)
- Matching command events tied to this drop set: `92`
- Time window:
  - First seen: `2026-02-22T01:25:05.568962Z`
  - Last seen: `2026-02-22T06:01:03.150906Z`
- Unique sessions: `78`
- Source IPs observed for this campaign subset: `165.245.136.10` only

## Binary Triage (r2/rabin2)
Representative unpacked sample: `dl/094b46a9f-ozVKRtln` (unpacked to `/tmp/newtriage/sample1`)

`rabin2 -I /tmp/newtriage/sample1`:
- `ELF64`, `x86-64`, static, stripped, language = `go`

`r2 izz` highlights:
- Network/client behavior markers:
  - `http2clientConnPool`
  - `yvo6rOL.(*http2clientConnPool).GetClientConn`
  - `yvo6rOL.(*http2clientConnPool).MarkDead`
- Auth/crypto markers:
  - `B7KwKMdoi.(*MJc4BaJd).Password`
  - `...XORKeyStream`
  - `RC4(`
- Family markers seen repeatedly:
  - `SSH-A` (rendered as `SSH-A\``)
  - `?xMR`
  - `t passhr`
  - `/proc/self/exe`

### C2/Network IOC Result
- No reliable cleartext C2 URL/domain/IP recovered from this family’s binaries.
- Recovered URL-like string is UPX metadata only: `http://upx.sf.net`.
- Practical conclusion: config/C2 is likely encoded/decrypted at runtime.

## Host-Behavior IOCs (Command Telemetry)
Observed delivery and execution templates:
- `scp -qt "/var/tmp/<PAYLOAD>"` (41 events)
- `scp -qt "/tmp/<PAYLOAD>"` (14 events)
- `cd /var/tmp && chmod 777 <PAYLOAD> && ./<PAYLOAD> </dev/null &>/dev/null & disown` (23 events)
- `cd /tmp && chmod 777 <PAYLOAD> && ./<PAYLOAD> </dev/null &>/dev/null & disown` (14 events)

`<PAYLOAD>` is typically an 8-character mixed-case token (example: `ozVKRtln`).

### Cleanup / Competitive Kill / Anti-Forensics Markers
- `crontab -r`
- `chattr -iae ~/.ssh/authorized_keys`
- `pkill/killall` targets: `java`, `xmrig`, `cnrig`, `Opera`
- File/path wipes:
  - `/dev/shm/.x`
  - `/dev/shm/rete*`
  - `/var/tmp/payload`
  - `/tmp/.diicot`
  - `/tmp/kuak`
  - `/var/tmp/.update-logs`
  - `/var/tmp/Documents`
  - `.black`
  - `xmrig.1`
- History cleanup:
  - `history -c`
  - `rm -rf .bash_history ~/.bash_history`

## Detection and Hunting Guidance
- YARA:
  - Rule: `Obf_UPX_SSH_XMR_x64` in `reports/rules.yar`
  - Family label: `ObfUPX_SSHXMR`
- Command-line detections:
  - `scp -qt "/(var/tmp|tmp)/[A-Za-z0-9]{8}"`
  - `chmod 777 [A-Za-z0-9]{8} && \\./[A-Za-z0-9]{8}.*disown`
  - `crontab -r` combined with `pkill xmrig|killall xmrig|pkill cnrig`
- Filesystem detections:
  - Creation and execution of random 8-char binaries under `/tmp` or `/var/tmp`
  - Presence of cleanup artifacts under `/var/tmp/.update-logs` and `/tmp/.diicot`

## Open Items
- Dynamic run in controlled sandbox is required to recover decrypted runtime config and potential live C2 endpoints.
