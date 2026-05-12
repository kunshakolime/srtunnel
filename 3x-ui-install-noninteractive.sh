#!/bin/bash

# ============================================================================
# NON-INTERACTIVE X-UI INSTALLATION SCRIPT
# ============================================================================
# All interactive prompts have been replaced with variables.
# Set these variables before running the script or pass them as environment variables.
# ============================================================================

# Configuration Variables (set these before running)
# ----------------------------------------------------------------------------

# SSL Configuration
# SKIP_SSL=y        → HTTP mode, no SSL at all (overrides SSL_MODE)
# SSL_MODE=3        → Custom cert paths (only supported mode)
# SSL_MODE=anything else with SKIP_SSL unset → treated as no-SSL (safe fallback)
XRAY_SKIP_SSL="${SKIP_SSL:-n}"                         # y=HTTP mode (no SSL), n=use SSL_MODE
SSL_MODE="${SSL_MODE:-3}"                          # Only mode 3 (custom paths) is supported
SSL_CUSTOM_CERT="${SSL_CUSTOM_CERT:-/root/srtunnel/server.crt}"  # Custom cert path (mode 3)
SSL_CUSTOM_KEY="${SSL_CUSTOM_KEY:-/root/srtunnel/server.key}"    # Custom key path (mode 3)
SSL_CUSTOM_DOMAIN="${DOMAIN:-}"                    # Domain for custom cert (mode 3)

# Panel Configuration
WEBPATH="${WEBPATH:-3x-ui}"
USER="${USER:-root}"
PASS="${XRAY_PASS:-}"
CUSTOMIZE_PORT="${CUSTOMIZE_PORT:-y}"              # Customize panel port (y/n)
PANEL_PORT="${PANEL_PORT:-51701}"                 # Panel port

# Output Variables (script will set these)
OUTPUT_USERNAME=""
OUTPUT_PASSWORD=""
OUTPUT_PORT=""
OUTPUT_WEBBASEPATH=""
OUTPUT_ACCESS_URL=""
OUTPUT_SSL_HOST=""
OUTPUT_INSTALL_STATUS=""

# ----------------------------------------------------------------------------

red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

xui_folder="${XUI_MAIN_FOLDER:=/usr/local/x-ui}"
xui_service="${XUI_SERVICE:=/etc/systemd/system}"

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}Fatal error: ${plain} Please run this script with root privilege \n " && exit 1

# Check OS and set release variable
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
elif [[ -f /usr/lib/os-release ]]; then
    source /usr/lib/os-release
    release=$ID
else
    echo "Failed to check the system OS, please contact the author!" >&2
    exit 1
fi
echo "The OS release is: $release"

arch() {
    case "$(uname -m)" in
        x86_64 | x64 | amd64) echo 'amd64' ;;
        i*86 | x86) echo '386' ;;
        armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
        armv7* | armv7 | arm) echo 'armv7' ;;
        armv6* | armv6) echo 'armv6' ;;
        armv5* | armv5) echo 'armv5' ;;
        s390x) echo 's390x' ;;
        *) echo -e "${green}Unsupported CPU architecture! ${plain}" && rm -f install.sh && exit 1 ;;
    esac
}

echo "Arch: $(arch)"

# Simple helpers
is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && return 0 || return 1
}
is_ipv6() {
    [[ "$1" =~ : ]] && return 0 || return 1
}
is_ip() {
    is_ipv4 "$1" || is_ipv6 "$1"
}
is_domain() {
    [[ "$1" =~ ^([A-Za-z0-9](-*[A-Za-z0-9])*\.)+(xn--[a-z0-9]{2,}|[A-Za-z]{2,})$ ]] && return 0 || return 1
}

# Port helpers
is_port_in_use() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | awk -v p=":${port}$" '$4 ~ p {exit 0} END {exit 1}'
        return
    fi
    if command -v netstat >/dev/null 2>&1; then
        netstat -lnt 2>/dev/null | awk -v p=":${port} " '$4 ~ p {exit 0} END {exit 1}'
        return
    fi
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:${port} -sTCP:LISTEN >/dev/null 2>&1 && return 0
    fi
    return 1
}

install_base() {
    case "${release}" in
        ubuntu | debian | armbian)
            apt-get update && apt-get install -y -q cron curl tar tzdata socat ca-certificates openssl
            ;;
        fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
            dnf -y update && dnf install -y -q cronie curl tar tzdata socat ca-certificates openssl
            ;;
        centos)
            if [[ "${VERSION_ID}" =~ ^7 ]]; then
                yum -y update && yum install -y cronie curl tar tzdata socat ca-certificates openssl
            else
                dnf -y update && dnf install -y -q cronie curl tar tzdata socat ca-certificates openssl
            fi
            ;;
        arch | manjaro | parch)
            pacman -Syu && pacman -Syu --noconfirm cronie curl tar tzdata socat ca-certificates openssl
            ;;
        opensuse-tumbleweed | opensuse-leap)
            zypper refresh && zypper -q install -y cron curl tar timezone socat ca-certificates openssl
            ;;
        alpine)
            apk update && apk add dcron curl tar tzdata socat ca-certificates openssl
            ;;
        *)
            apt-get update && apt-get install -y -q cron curl tar tzdata socat ca-certificates openssl
            ;;
    esac
}

gen_random_string() {
    local length="$1"
    openssl rand -base64 $(( length * 2 )) \
        | tr -dc 'a-zA-Z0-9' \
        | head -c "$length"
}

# ============================================================================
# SSL SETUP — custom cert only (mode 3)
# Called after x-ui is installed and running.
# Sets cert/key paths directly in the panel config; no certificate issuance.
# ============================================================================
setup_custom_ssl() {
    local cert_file="${SSL_CUSTOM_CERT}"
    local key_file="${SSL_CUSTOM_KEY}"

    echo -e "${green}Configuring custom SSL certificate...${plain}"

    if [[ -z "$cert_file" || -z "$key_file" ]]; then
        echo -e "${red}SSL_CUSTOM_CERT and SSL_CUSTOM_KEY must both be set for custom SSL mode.${plain}"
        return 1
    fi

    if [[ ! -f "$cert_file" ]]; then
        echo -e "${red}Certificate file not found: ${cert_file}${plain}"
        return 1
    fi

    if [[ ! -f "$key_file" ]]; then
        echo -e "${red}Key file not found: ${key_file}${plain}"
        return 1
    fi

    # Secure permissions
    chmod 600 "$key_file"  2>/dev/null
    chmod 644 "$cert_file" 2>/dev/null

    # Register paths with the panel
    ${xui_folder}/x-ui cert -webCert "$cert_file" -webCertKey "$key_file"
    if [[ $? -ne 0 ]]; then
        echo -e "${red}Failed to set certificate paths in panel config.${plain}"
        return 1
    fi

    echo -e "${green}Custom SSL certificate configured successfully.${plain}"
    echo -e "  Cert : ${cert_file}"
    echo -e "  Key  : ${key_file}"
    return 0
}

# ============================================================================
# DETERMINE SSL MODE AND BUILD ACCESS URL
# ============================================================================
configure_ssl() {
    local port="$1"
    local webpath="$2"

    # SKIP_SSL=y → plain HTTP, nothing to configure
    if [[ "$SKIP_SSL" == "y" || "$SKIP_SSL" == "Y" ]]; then
        echo -e "${yellow}SKIP_SSL=y: running in HTTP mode, skipping SSL configuration.${plain}"
        OUTPUT_ACCESS_URL="http://<server-ip>:${port}/${webpath}"
        OUTPUT_SSL_HOST=""
        return 0
    fi

    # Only mode 3 (custom cert) is supported
    if [[ "$SSL_MODE" != "3" ]]; then
        echo -e "${yellow}SSL_MODE=${SSL_MODE} is not supported in this script. Only mode 3 (custom cert) is available.${plain}"
        echo -e "${yellow}Falling back to HTTP mode. Set SKIP_SSL=y to silence this warning.${plain}"
        OUTPUT_ACCESS_URL="http://<server-ip>:${port}/${webpath}"
        OUTPUT_SSL_HOST=""
        return 0
    fi

    # Mode 3: custom cert
    setup_custom_ssl
    if [[ $? -eq 0 ]]; then
        local host="${SSL_CUSTOM_DOMAIN:-<server-ip>}"
        OUTPUT_SSL_HOST="$host"
        OUTPUT_ACCESS_URL="https://${host}:${port}/${webpath}"

        echo -e "${green}Restarting panel to apply SSL certificate...${plain}"
        systemctl restart x-ui 2>/dev/null || rc-service x-ui restart 2>/dev/null
    else
        echo -e "${yellow}Custom SSL setup failed; panel will run over HTTP.${plain}"
        OUTPUT_ACCESS_URL="http://<server-ip>:${port}/${webpath}"
        OUTPUT_SSL_HOST=""
    fi
}

# ============================================================================
# MAIN INSTALL
# ============================================================================
install_x-ui() {
    install_base

    # ------------------------------------------------------------------
    # Download and install x-ui binary
    # ------------------------------------------------------------------
    local ARCH
    ARCH=$(arch)
    local last_version
    last_version=$(curl -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" \
        | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

    if [[ -z "$last_version" ]]; then
        echo -e "${red}Failed to fetch latest x-ui version.${plain}"
        exit 1
    fi

    echo -e "${green}Installing x-ui version: ${last_version}${plain}"

    cd /usr/local/ || exit 1
    curl -Lo /usr/local/x-ui-linux-${ARCH}.tar.gz \
        "https://github.com/MHSanaei/3x-ui/releases/download/${last_version}/x-ui-linux-${ARCH}.tar.gz"
    tar -xzf x-ui-linux-${ARCH}.tar.gz
    rm -f x-ui-linux-${ARCH}.tar.gz
    chmod +x x-ui/x-ui x-ui/bin/xray-linux-* x-ui/x-ui.sh 2>/dev/null

    # ------------------------------------------------------------------
    # Install systemd service
    # ------------------------------------------------------------------
    curl -Lo /etc/systemd/system/x-ui.service \
        "https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.service"
    systemctl daemon-reload
    systemctl enable x-ui

    # ------------------------------------------------------------------
    # Panel settings: port, web base path, credentials
    # ------------------------------------------------------------------
    local panel_port="${PANEL_PORT}"
    if [[ "$CUSTOMIZE_PORT" == "y" || "$CUSTOMIZE_PORT" == "Y" ]]; then
        if [[ -z "$panel_port" ]]; then
            panel_port=$(shuf -i 10000-65535 -n 1)
            echo -e "${yellow}PANEL_PORT not set, using random port: ${panel_port}${plain}"
        fi
    else
        panel_port=$(shuf -i 10000-65535 -n 1)
        echo -e "${yellow}Using random panel port: ${panel_port}${plain}"
    fi

    local webpath="${WEBPATH:-$(gen_random_string 8)}"
    local username="${USER:-$(gen_random_string 8)}"
    local password="${PASS:-$(gen_random_string 16)}"

    ${xui_folder}/x-ui setting -port "${panel_port}" >/dev/null 2>&1
    ${xui_folder}/x-ui setting -webBasePath "${webpath}" >/dev/null 2>&1
    ${xui_folder}/x-ui setting -username "${username}" >/dev/null 2>&1
    ${xui_folder}/x-ui setting -password "${password}" >/dev/null 2>&1

    # ------------------------------------------------------------------
    # Start panel
    # ------------------------------------------------------------------
    systemctl start x-ui
    sleep 2

    # ------------------------------------------------------------------
    # SSL / HTTP
    # ------------------------------------------------------------------
    configure_ssl "${panel_port}" "${webpath}"

    # ------------------------------------------------------------------
    # Store outputs
    # ------------------------------------------------------------------
    OUTPUT_USERNAME="$username"
    OUTPUT_PASSWORD="$password"
    OUTPUT_PORT="$panel_port"
    OUTPUT_WEBBASEPATH="$webpath"
    OUTPUT_INSTALL_STATUS="success"

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    echo ""
    echo -e "${green}============================================================${plain}"
    echo -e "${green} x-ui installation complete${plain}"
    echo -e "${green}============================================================${plain}"
    echo -e "  Username   : ${OUTPUT_USERNAME}"
    echo -e "  Password   : ${OUTPUT_PASSWORD}"
    echo -e "  Port       : ${OUTPUT_PORT}"
    echo -e "  Web path   : ${OUTPUT_WEBBASEPATH}"
    echo -e "  Access URL : ${OUTPUT_ACCESS_URL}"
    echo -e "${green}============================================================${plain}"
}

install_x-ui
