# SRTunnel

Minimal Debian/Ubuntu installer for **SRTunnel** (srapi + websocket + stunnel + helpers).

---

## Quick Install

As `root`:

```bash
curl -sSL https://raw.githubusercontent.com/kunshakolime/srtunnel/main/scripts/debinstall.sh | bash
# or: bash <(curl -sSL https://raw.githubusercontent.com/kunshakolime/srtunnel/main/scripts/debinstall.sh)
```

No required env vars. The installer copies the hardwired example:

* `configs/config.template.yaml` → `configs/config.yaml` (`example.com`, `sd.example.com`, `eth0`, `22`, `1000:2999`/`3000:5999`/`6000:19999`/`20000:30000`, `[80, 8080, 8000, 8880]`/`[8446]`, `keep: []`/`enable: []`, iptables commented)
* `configs/xray.template.json` → `configs/xray.json` (`example.com`)

Edit after install:

```bash
nano /opt/srtunnel/configs/config.yaml   # set telegram_bot.token, domain, cf_* , interface etc.
nano /opt/srtunnel/configs/xray.json     # set serverName/host if you use xray
systemctl restart srapi
```

Enable services manually (API or edit `configs/config.yaml` → `manager.keep`/`manager.enable`, e.g. `keep: [websocket, stunnel]`).

---

## Dashboard & srapi

* **srapi** listens on `0.0.0.0:57000` (`app/srapi.py:186` `uvicorn.run(..., port=57000)`, `telegram_bot.primary_url: http://127.0.0.1:57000`).
* Dashboard/static files are mounted at `/` from `static/`:
  ```
  http://<server-ip>:57000/
  ```
  (no nginx needed for direct access).

* **Nginx reverse-proxy** (optional, hardwired `example.com`):
  ```bash
  sudo ./scripts/setup-nginx.sh   # from /opt/srtunnel
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

* **3x-ui** (if installed) remains on `http://127.0.0.1:57001/3x-ui/` (`configs/config.template.yaml:xui_panel.url`), proxied by `configs/srtdash.nginx` at `/3x-ui/`.

---

## Uninstall

```bash
./scripts/uninstall.sh
```
