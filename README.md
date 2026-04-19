# SRTunnel Installer

This repository provides a quick way to install **SRTunnel** on your system.

---

## Quick Install

You can install SRTunnel directly on your system with a single command, as long as you have a domain or subdomain already linked to your ip and a telegram bot token.

AS THE ROOT USER:

 set up your desired variables (you can leave most of them empty and they'll default.)

```bash
export HTTP="" \
       HTTPS="" \
       IFACE="" \
       TOKEN="your_telegram_token_here" \
       DOMAIN="your_domain_or_subdomain.com" \
       RUN_SPEEDTEST="" \
       SSH="" \
       H1_PR="" \
       H2_PR="" \
       ZU_PR="" \
       UC_PR="" \
```
```bash
apt update -qq && apt install -y -qq curl && . <(curl -sSL https://raw.githubusercontent.com/kunshakolime/srtunnel/main/debinstall.sh)
```

