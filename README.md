# SRTunnel

Minimal Debian/Ubuntu installer for **SRTunnel** (srapi + websocket + stunnel + helpers).

---
## Quick Install
As `root`:
```bash
curl -sSL https://raw.githubusercontent.com/kunshakolime/srtunnel/main/scripts/debinstall.sh | bash
```
## CLI

```bash
srtunnel                      # same as `srtunnel status`
srtunnel status [--json]      # units, ports, users, config drift
srtunnel reconcile --dry-run  # show what would change on this box
srtunnel reconcile            # render units/nginx/sshd/sysctl/stunnel
srtunnel reconcile --check    # dry-run; exit 1 if anything is out of sync
srtunnel bin                  # list the installed release binaries
srtunnel exec hysteria2       # run one of them (they are not on PATH)
srtunnel run                  # run srapi in the foreground
```

`reconcile` never overwrites a live file it did not write. If you customize a
deployed file on purpose, pin it:

```bash
srtunnel reconcile --adopt nginx-ws
```

## Binaries

Third-party executables are GitHub release assets, not repository files:

| | |
|---|---|
| Installed to | `/usr/local/libexec/srtunnel` (not on `PATH`) |
| Pinned in | `binaries.lock` (release tag + per-arch SHA-256) |
| arm64 bundle | `badvpn-udpgw`, `udp-zivpn` |
| amd64 bundle | `badvpn-udpgw`, `dropbear*`, `dnstt-server`, `hysteria2`, `udp-custom`, `udp-zivpn` |

`scripts/debinstall.sh` downloads only the bundle for the machine's
architecture, verifies it against `binaries.lock`, and extracts it. Use
`srtunnel bin` to see what is installed and `srtunnel exec NAME [args]` to run
one. The eBPF meter (`traffic_meter_user`, `traffic_meter.bpf.o`) and
`ipmask_tool` are built from this repo and copied there on install.

Publishing a new bundle: build `srtunnel-bins-{arm64,amd64}.tar.gz` plus
`SHA256SUMS`, create a release with that tag, then bump `TAG` and the hashes in
`binaries.lock`.

## Uninstall
```bash
./scripts/uninstall.sh
```
