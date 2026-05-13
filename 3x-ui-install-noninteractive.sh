#!/bin/bash

# ============================================================================
# NON-INTERACTIVE X-UI INSTALLATION SCRIPT
# ============================================================================

# SSL Configuration
# SKIP_SSL=y  -> HTTP mode, no SSL at all (overrides SSL_MODE)
# SSL_MODE=3  -> Custom cert paths (only supported mode)
XRAY_SKIP_SSL="${SKIP_SSL:-y}"
SSL_MODE="${SSL_MODE:-3}"
SSL_CUSTOM_CERT="${SSL_CUSTOM_CERT:-/root/srtunnel/server.crt}"
SSL_CUSTOM_KEY="${SSL_CUSTOM_KEY:-/root/srtunnel/server.key}"
SSL_CUSTOM_DOMAIN="${DOMAIN:-}"

# Panel Configuration
WEBPATH="${WEBPATH:-3x-ui}"
USER="${USER:-root}"
PASS="${XRAY_PASS:-}"
CUSTOMIZE_PORT="${CUSTOMIZE_PORT:-y}"
PANEL_PORT="${PANEL_PORT:-51701}"

# Output Variables
OUTPUT_USERNAME=""
OUTPUT_PASSWORD=""
OUTPUT_PORT=""
OUTPUT_WEBBASEPATH=""
OUTPUT_ACCESS_URL=""
OUTPUT_SSL_HOST=""
OUTPUT_INSTALL_STATUS=""

# ----------------------------------------------------------------------------

cur_dir=$(pwd)

xui_folder="${XUI_MAIN_FOLDER:=/usr/local/x-ui}"
xui_service="${XUI_SERVICE:=/etc/systemd/system}"

[[ $EUID -ne 0 ]] && echo "Fatal error: please run this script with root privilege" && exit 1

if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
elif [[ -f /usr/lib/os-release ]]; then
    source /usr/lib/os-release
    release=$ID
else
    echo "Failed to check the system OS" >&2
    exit 1
fi
echo "OS release: $release"

arch() {
    case "$(uname -m)" in
        x86_64 | x64 | amd64) echo 'amd64' ;;
        i*86 | x86) echo '386' ;;
        armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
        armv7* | armv7 | arm) echo 'armv7' ;;
        armv6* | armv6) echo 'armv6' ;;
        armv5* | armv5) echo 'armv5' ;;
        s390x) echo 's390x' ;;
        *) echo "Unsupported CPU architecture" && rm -f install.sh && exit 1 ;;
    esac
}

echo "Arch: $(arch)"

is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
is_ipv6() { [[ "$1" =~ : ]]; }
is_domain() { [[ "$1" =~ ^([A-Za-z0-9](-*[A-Za-z0-9])*\.)+(xn--[a-z0-9]{2,}|[A-Za-z]{2,})$ ]]; }

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

setup_custom_ssl() {
    local cert_file="${SSL_CUSTOM_CERT}"
    local key_file="${SSL_CUSTOM_KEY}"

    if [[ -z "$cert_file" || -z "$key_file" ]]; then
        echo "ERROR: SSL_CUSTOM_CERT and SSL_CUSTOM_KEY must both be set for custom SSL mode"
        return 1
    fi
    if [[ ! -f "$cert_file" ]]; then
        echo "ERROR: Certificate file not found: ${cert_file}"
        return 1
    fi
    if [[ ! -f "$key_file" ]]; then
        echo "ERROR: Key file not found: ${key_file}"
        return 1
    fi

    chmod 600 "$key_file"  2>/dev/null
    chmod 644 "$cert_file" 2>/dev/null

    ${xui_folder}/x-ui cert -webCert "$cert_file" -webCertKey "$key_file"
    if [[ $? -ne 0 ]]; then
        echo "ERROR: Failed to set certificate paths in panel config"
        return 1
    fi

    echo "Custom SSL configured: cert=${cert_file} key=${key_file}"
    return 0
}

configure_ssl() {
    local port="$1"
    local webpath="$2"

    if [[ "$SKIP_SSL" == "y" || "$SKIP_SSL" == "Y" ]]; then
        echo "SKIP_SSL=y: running in HTTP mode"
        OUTPUT_ACCESS_URL="http://<server-ip>:${port}/${webpath}"
        OUTPUT_SSL_HOST=""
        return 0
    fi

    if [[ "$SSL_MODE" != "3" ]]; then
        echo "WARNING: SSL_MODE=${SSL_MODE} is not supported; only mode 3 (custom cert) is available. Falling back to HTTP."
        OUTPUT_ACCESS_URL="http://<server-ip>:${port}/${webpath}"
        OUTPUT_SSL_HOST=""
        return 0
    fi

    setup_custom_ssl
    if [[ $? -eq 0 ]]; then
        local host="${SSL_CUSTOM_DOMAIN:-<server-ip>}"
        OUTPUT_SSL_HOST="$host"
        OUTPUT_ACCESS_URL="https://${host}:${port}/${webpath}"
        systemctl restart x-ui 2>/dev/null || rc-service x-ui restart 2>/dev/null
    else
        echo "WARNING: Custom SSL setup failed; panel will run over HTTP"
        OUTPUT_ACCESS_URL="http://<server-ip>:${port}/${webpath}"
        OUTPUT_SSL_HOST=""
    fi
}

install_x-ui() {
    install_base

    local ARCH
    ARCH=$(arch)
    local last_version
    last_version=$(curl -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" \
        | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

    if [[ -z "$last_version" ]]; then
        echo "ERROR: Failed to fetch latest x-ui version"
        exit 1
    fi

    echo "Installing x-ui version: ${last_version}"

    cd /usr/local/ || exit 1
    curl -Lo /usr/local/x-ui-linux-${ARCH}.tar.gz \
        "https://github.com/MHSanaei/3x-ui/releases/download/${last_version}/x-ui-linux-${ARCH}.tar.gz"
    tar -xzf x-ui-linux-${ARCH}.tar.gz
    rm -f x-ui-linux-${ARCH}.tar.gz
    chmod +x x-ui/x-ui x-ui/bin/xray-linux-* x-ui/x-ui.sh 2>/dev/null

    curl -Lo /etc/systemd/system/x-ui.service \
        "https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.service"
    systemctl daemon-reload
    systemctl enable x-ui

    local panel_port="${PANEL_PORT}"
    if [[ "$CUSTOMIZE_PORT" == "y" || "$CUSTOMIZE_PORT" == "Y" ]]; then
        if [[ -z "$panel_port" ]]; then
            panel_port=$(shuf -i 10000-65535 -n 1)
            echo "PANEL_PORT not set, using random port: ${panel_port}"
        fi
    else
        panel_port=$(shuf -i 10000-65535 -n 1)
        echo "Using random panel port: ${panel_port}"
    fi

    local webpath="${WEBPATH:-$(gen_random_string 8)}"
    local username="${USER:-$(gen_random_string 8)}"
    local password="${PASS:-$(gen_random_string 16)}"

    ${xui_folder}/x-ui setting -port "${panel_port}" >/dev/null 2>&1
    ${xui_folder}/x-ui setting -webBasePath "${webpath}" >/dev/null 2>&1
    ${xui_folder}/x-ui setting -username "${username}" >/dev/null 2>&1
    ${xui_folder}/x-ui setting -password "${password}" >/dev/null 2>&1
    if [[ "$SKIP_SSL" == "y" || "$SKIP_SSL" == "Y" ]]; then
        echo "setting listen port to 127.0.0.1"
        /usr/local/x-ui/x-ui setting -listenIP "127.0.0.1"
    fi

    systemctl start x-ui
    sleep 2

    configure_ssl "${panel_port}" "${webpath}"

    OUTPUT_USERNAME="$username"
    OUTPUT_PASSWORD="$password"
    OUTPUT_PORT="$panel_port"
    OUTPUT_WEBBASEPATH="$webpath"
    OUTPUT_INSTALL_STATUS="success"

    echo "------------------------------------------------------------"
    echo "x-ui installation complete"
    echo "  Username   : ${OUTPUT_USERNAME}"
    echo "  Password   : ${OUTPUT_PASSWORD}"
    echo "  Port       : ${OUTPUT_PORT}"
    echo "  Web path   : ${OUTPUT_WEBBASEPATH}"
    echo "  Access URL : ${OUTPUT_ACCESS_URL}"
    echo "------------------------------------------------------------"
}

install_x-ui
