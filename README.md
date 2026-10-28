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
srtunnel run                  # run srapi in the foreground
```

`reconcile` never overwrites a live file it did not write. If you customize a
deployed file on purpose, pin it:

```bash
srtunnel reconcile --adopt nginx-ws
```

## Uninstall
```bash
./scripts/uninstall.sh
```
