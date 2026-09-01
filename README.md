# SRTunnel

Minimal Debian/Ubuntu installer for **SRTunnel** (srapi + websocket + stunnel + helpers).

---

## What `debinstall.sh` does (minimal)

* Distro check (`debian`/`ubuntu`), `apt update` + base deps (`git openssh-server stunnel4 nginx libnginx-mod-stream nftables iptables openssl` + `python3` + `python3-certbot`)
* Python deps via **apt** (`python3-fastapi` `python3-uvicorn` `python3-requests` `python3-httpx` `python3-ruamel.yaml` `python3-psutil` `python3-yaml` `python3-pam` `python3-cryptography` `python3-jwcrypto` `python3-python-multipart` `python3-websockets` `python3-pip`; `python-jose[cryptography]` via `pip --break-system-packages` — no `venv`, systemd uses `/usr/bin/python3`)
* Clones to `/opt/srtunnel` (or uses current repo if `config.template.yaml`+`srapi.py` present), installs `bin/deb13amd64/*`, `geoip.dat`/`geosite.dat`
* SSH tweak (`KexAlgorithms`, `Banner`, `UsePAM`)
* Renders config **hardwired** (`cp config.template.yaml → config.yaml`, `cp xray.template.json → xray.json`) — no `envsubst` vars
* Generates **only** SlowDNS key (`dnstt-server -gen-key` → `slowdns.key`/`slowdns.pub`); no self-signed/certbot certs
* Installs `srtunnel` → `/usr/sbin/srtunnel`, `srapi.service` (`/usr/bin/python3 /opt/srtunnel/srapi.py`, `WorkingDirectory=/opt/srtunnel`), `srtadmin` group, `daemon-reload` + `enable --now srapi`

No nginx vhost/stream setup, no iptables rules, no services auto-started (`manager.keep: []`, `manager.enable: []` in `config.template.yaml`).

> Nginx is kept as a **dependency** but configured separately.

---

## Quick Install

As `root`:

```bash
curl -sSL https://raw.githubusercontent.com/kunshakolime/srtunnel/main/debinstall.sh | bash
# or: . <(curl -sSL https://raw.githubusercontent.com/kunshakolime/srtunnel/main/debinstall.sh)
```

No required env vars. The installer copies the hardwired example:

* `config.template.yaml` → `config.yaml` (`example.com`, `sd.example.com`, `eth0`, `22`, `1000:2999`/`3000:5999`/`6000:19999`/`20000:30000`, `[80, 8080, 8000, 8880]`/`[8446]`, `keep: []`/`enable: []`, iptables commented)
* `xray.template.json` → `xray.json` (`example.com`)

Edit after install:

```bash
nano /opt/srtunnel/config.yaml   # set telegram_bot.token, domain, cf_* , interface etc.
nano /opt/srtunnel/xray.json     # set serverName/host if you use xray
systemctl restart srapi
```

Enable services manually (API or edit `config.yaml` → `manager.keep`/`manager.enable`, e.g. `keep: [websocket, stunnel]`).

---

## Dashboard & srapi

* **srapi** listens on `0.0.0.0:57000` (`srapi.py:186` `uvicorn.run(..., port=57000)`, `telegram_bot.primary_url: http://127.0.0.1:57000`).
* Dashboard/static files are mounted at `/` from `static/`:
  ```
  http://<server-ip>:57000/
  ```
  (no nginx needed for direct access).

* **Nginx reverse-proxy** (optional, hardwired `example.com`):
  ```bash
  sudo ./setup-nginx.sh   # from /opt/srtunnel
  # edits: /etc/nginx/stream-enabled/srtdash (SNI 443 → 127.0.0.1:8443/8444/8445/8446)
  #        /etc/nginx/sites-available/srtdash (8444 ssl, proxy_pass → 127.0.0.1:57000)
  #        includes stream in nginx.conf, removes default site, nginx -t && restart
  ```
  Then:
  ```
  https://example.com:8444/   (srtdash vhost)
  https://example.com/        (stream 443 SNI → 8444)
  ```
  Edit the generated files for a real domain and `nginx -t && systemctl reload nginx`.

* **3x-ui** (if installed) remains on `http://127.0.0.1:57001/3x-ui/` (`config.template.yaml:xui_panel.url`), proxied by `srtdash.nginx` at `/3x-ui/`.

---

## Other scripts

* `./setup-nginx.sh` — nginx setup extracted from `debinstall.sh` (run later, idempotent).
* `./startsrapi.sh` — dev runner (`cp config.template.yaml → config.yaml` if missing, `exec python3 srapi.py`, no `venv`).
* All Python entrypoints now use `#!/usr/bin/env python3` (`srtunnel`, `websocket`, `pystunnel`, `telegram_bot`, `srapi.py`).

---

## Uninstall

```bash
./uninstall.sh
```
