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

## Uninstall
```bash
./scripts/uninstall.sh
```
