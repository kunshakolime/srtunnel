# SRTunnel

Minimal Debian/Ubuntu installer for **SRTunnel** (srapi + websocket + stunnel + helpers).

---
## Quick Install
As `root`:
```bash
curl -sSL https://raw.githubusercontent.com/kunshakolime/srtunnel/main/scripts/debinstall.sh | bash
```
Add `-d <domain>` to request a Let's Encrypt certificate (certbot standalone):
```bash
curl -sSL https://raw.githubusercontent.com/kunshakolime/srtunnel/main/scripts/debinstall.sh | bash -s -- -d tunnel.example.com
```
Without `-d`, a self-signed certificate is generated so TLS services can start.
## CLI

```bash
srtunnel                      # same as `srtunnel status`
srtunnel status [--json]      # units, ports, users, config drift
srtunnel reconcile --dry-run  # show what would change on this box
srtunnel reconcile            # render units/nginx/sshd/sysctl/stunnel
srtunnel reconcile --check    # dry-run; exit 1 if anything is out of sync
srtunnel bin                  # list the installed release binaries
srtunnel exec hysteria2       # run one of them (they are not on PATH)
srtunnel cert                 # show the current TLS certificate
srtunnel cert -d example.com  # obtain/renew a Let's Encrypt certificate
srtunnel cert --selfsigned    # generate a self-signed pair if missing
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

## Certificates

Every TLS consumer reads the same two files at the repo root — no per-service
paths:

| file | mode |
|---|---|
| `fullchain.pem` | certificate + chain |
| `privkey.pem` | private key |

`srtunnel cert` owns both flows, so they are available long after the install:

```bash
srtunnel cert                              # paths, subject, issuer, expiry
srtunnel cert -d example.com               # Let's Encrypt (certbot standalone)
srtunnel cert -d example.com --force       # reissue even if not near expiry
srtunnel cert --selfsigned                 # self-signed (10 years) if missing
```

`srtunnel cert -d` stops nginx for the HTTP-01 challenge and starts it again
afterwards; the same pre/post hooks are stored in the certbot renewal config, so
`certbot.timer` renews unattended. A `--force` issue or a renewal also restarts
stunnel, which only reads the certificate at startup. If certbot fails, the
previous certificate stays in place.

`debinstall.sh -d DOMAIN` simply calls `srtunnel cert -d DOMAIN`; without `-d`
it calls `srtunnel cert --selfsigned` so TLS services can start.

## Uninstall
```bash
./scripts/uninstall.sh
```
