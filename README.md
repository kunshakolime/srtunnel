# SRTunnel Installer

This repository provides a quick way to install **SRTunnel** on your system.

---

## Quick Install

You can install SRTunnel directly on your system with a single command.
AS THE ROOT USER:

```bash
apt update -qq && apt install -y -qq curl bash && . <(curl -sSL https://raw.githubusercontent.com/kunshakolime/srtunnel/main/debinstall.sh)
```

Optional: Run Inside Podman

If you prefer a clean environment or want to avoid modifying your host system while tesing, you can run the installer inside a Debian container using Podman:

```bash
podman run -it --privileged --rm debian:trixie-slim bash -c "apt update -qq && apt install -y -qq curl bash && . <(curl -sSL https://raw.githubusercontent.com/kunshakolime/srtunnel/main/debinstall.sh) && bash"
```
Or Ubuntu

```bash
podman run -it --privileged --rm ubuntu:24.04 bash -c "apt update -qq && apt install -y -qq curl bash && . <(curl -sSL https://raw.githubusercontent.com/kunshakolime/srtunnel/main/debinstall.sh) && bash"
```
