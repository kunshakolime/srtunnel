#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
yellow='\033[0;33m'
plain='\033[0m'

xui_folder="${XUI_MAIN_FOLDER:=/usr/local/x-ui}"
xui_service="${XUI_SERVICE:=/etc/systemd/system}"

OUTPUT_USERNAME=""
OUTPUT_PASSWORD=""
OUTPUT_PORT=""
OUTPUT_WEBBASEPATH=""
OUTPUT_ACCESS_URL=""
OUTPUT_SSL_HOST=""
OUTPUT_SSL_SCHEME=""
OUTPUT_INSTALL_STATUS=""

[[ $EUID -ne 0 ]] && echo -e "${red}Fatal error: ${plain} Please run this script with root privilege \n " && exit 1

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

arch() {
    case "$(uname -m)" in
        x86_64 | x64 | amd64) echo 'amd64' ;;
        i*86 | x86) echo '386' ;;
        armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
        armv7* | armv7 | arm) echo 'armv7' ;;
        armv6* | armv6) echo 'armv6' ;;
        armv5* | armv5) echo 'armv5' ;;
        s390x) echo 's390x' ;;
        *) echo -e "${green}Unsupported CPU architecture! ${plain}" && exit 1 ;;
    esac
}

install_base() {
    command -v curl &>/dev/null && command -v tar &>/dev/null && command -v openssl &>/dev/null && return
    case "${release}" in
        ubuntu | debian | armbian)
            apt-get update -qq && apt-get install -y -q cron curl tar tzdata socat ca-certificates openssl
        ;;
        fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
            dnf install -y -q cronie curl tar tzdata socat ca-certificates openssl
        ;;
        centos)
            if [[ "${VERSION_ID}" =~ ^7 ]]; then
                yum install -y cronie curl tar tzdata socat ca-certificates openssl
            else
                dnf install -y -q cronie curl tar tzdata socat ca-certificates openssl
            fi
        ;;
        arch | manjaro | parch)
            pacman -Syu --noconfirm cronie curl tar tzdata socat ca-certificates openssl
        ;;
        opensuse-tumbleweed | opensuse-leap)
            zypper -q install -y cron curl tar timezone socat ca-certificates openssl
        ;;
        alpine)
            apk add dcron curl tar tzdata socat ca-certificates openssl
        ;;
        *)
            apt-get update -qq && apt-get install -y -q cron curl tar tzdata socat ca-certificates openssl
        ;;
    esac
}

gen_random_string() {
    local length="$1"
    openssl rand -base64 $(( length * 2 )) \
        | tr -dc 'a-zA-Z0-9' \
        | head -c "$length"
}

config_after_install() {
    local existing_hasDefaultCredential=$(${xui_folder}/x-ui setting -show true | grep -Eo 'hasDefaultCredential: .+' | awk '{print $2}')
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep -Eo 'webBasePath: .+' | awk '{print $2}' | sed 's#^/##')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}')

    local server_ip=""
    for ip_address in "https://api4.ipify.org" "https://ipv4.icanhazip.com" "https://v4.api.ipinfo.io/ip" "https://ipv4.myexternalip.com/raw" "https://4.ident.me" "https://check-host.net/ip"; do
        local response=$(curl -s -w "\n%{http_code}" --max-time 3 "${ip_address}" 2>/dev/null)
        local http_code=$(echo "$response" | tail -n1)
        local ip_result=$(echo "$response" | head -n-1 | tr -d '[:space:]')
        if [[ "${http_code}" == "200" && -n "${ip_result}" ]]; then
            server_ip="${ip_result}"
            break
        fi
    done

    if [[ ${#existing_webBasePath} -lt 4 ]]; then
        if [[ "$existing_hasDefaultCredential" == "true" ]]; then
            local config_webBasePath="${WEBPATH:-3x-ui}"
            local config_username="${USER:-root}"
            local config_password="${PASS:-}"

            if [[ "${CUSTOMIZE_PORT:-y}" == "y" || "${CUSTOMIZE_PORT:-y}" == "Y" ]]; then
                if [[ -n "${PANEL_PORT}" ]]; then
                    local config_port="${PANEL_PORT}"
                else
                    local config_port=$(shuf -i 1024-62000 -n 1)
                fi
            else
                local config_port=$(shuf -i 1024-62000 -n 1)
            fi

            ${xui_folder}/x-ui setting -username "${config_username}" -password "${config_password}" -port "${config_port}" -webBasePath "${config_webBasePath}"
            ${xui_folder}/x-ui cert -reset

            OUTPUT_USERNAME="${config_username}"
            OUTPUT_PASSWORD="${config_password}"
            OUTPUT_PORT="${config_port}"
            OUTPUT_WEBBASEPATH="${config_webBasePath}"
            OUTPUT_SSL_HOST="${server_ip}"
            OUTPUT_SSL_SCHEME="http"
            OUTPUT_ACCESS_URL="http://${server_ip}:${config_port}/${config_webBasePath}"

            echo ""
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}     Panel Installation Complete!         ${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}Username:    ${config_username}${plain}"
            echo -e "${green}Password:    ${config_password}${plain}"
            echo -e "${green}Port:        ${config_port}${plain}"
            echo -e "${green}WebBasePath: ${config_webBasePath}${plain}"
            echo -e "${green}Access URL:  ${OUTPUT_ACCESS_URL}${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"
        else
            local config_webBasePath=$(gen_random_string 18)
            ${xui_folder}/x-ui setting -webBasePath "${config_webBasePath}"
            OUTPUT_WEBBASEPATH="${config_webBasePath}"
            OUTPUT_ACCESS_URL="http://${server_ip}:${existing_port}/${config_webBasePath}"
        fi
    else
        if [[ "$existing_hasDefaultCredential" == "true" ]]; then
            local config_username=$(gen_random_string 10)
            local config_password=$(gen_random_string 10)
            ${xui_folder}/x-ui setting -username "${config_username}" -password "${config_password}"
            OUTPUT_USERNAME="${config_username}"
            OUTPUT_PASSWORD="${config_password}"
        fi
        OUTPUT_ACCESS_URL="http://${server_ip}:${existing_port}/${existing_webBasePath}"
    fi

    ${xui_folder}/x-ui cert -reset >/dev/null 2>&1
    ${xui_folder}/x-ui migrate
}

install_x-ui() {
    cd ${xui_folder%/x-ui}/

    if [ $# == 0 ]; then
        tag_version=$(curl -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$tag_version" ]]; then
            tag_version=$(curl -4 -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
            if [[ ! -n "$tag_version" ]]; then
                echo -e "${red}Failed to fetch x-ui version, it may be due to GitHub API restrictions, please try it later${plain}"
                OUTPUT_INSTALL_STATUS="failed_version_fetch"
                exit 1
            fi
        fi
        curl -4fLRo ${xui_folder}-linux-$(arch).tar.gz https://github.com/MHSanaei/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Downloading x-ui failed, please be sure that your server can access GitHub ${plain}"
            OUTPUT_INSTALL_STATUS="failed_download"
            exit 1
        fi
    else
        tag_version=$1
        tag_version_numeric=${tag_version#v}
        min_version="2.3.5"
        if [[ "$(printf '%s\n' "$min_version" "$tag_version_numeric" | sort -V | head -n1)" != "$min_version" ]]; then
            echo -e "${red}Please use a newer version (at least v2.3.5). Exiting installation.${plain}"
            OUTPUT_INSTALL_STATUS="failed_version_check"
            exit 1
        fi
        curl -4fLRo ${xui_folder}-linux-$(arch).tar.gz https://github.com/MHSanaei/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Download x-ui $1 failed, please check if the version exists ${plain}"
            OUTPUT_INSTALL_STATUS="failed_download"
            exit 1
        fi
    fi

    curl -4fLRo /usr/bin/x-ui-temp https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.sh
    if [[ $? -ne 0 ]]; then
        echo -e "${red}Failed to download x-ui.sh${plain}"
        OUTPUT_INSTALL_STATUS="failed_script_download"
        exit 1
    fi

    if [[ -e ${xui_folder}/ ]]; then
        if [[ $release == "alpine" ]]; then
            rc-service x-ui stop 2>/dev/null
        else
            systemctl stop x-ui 2>/dev/null
        fi
        rm ${xui_folder}/ -rf
    fi

    tar zxvf x-ui-linux-$(arch).tar.gz
    rm x-ui-linux-$(arch).tar.gz -f

    cd x-ui
    chmod +x x-ui x-ui.sh

    if [[ $(arch) == "armv5" || $(arch) == "armv6" || $(arch) == "armv7" ]]; then
        mv bin/xray-linux-$(arch) bin/xray-linux-arm
        chmod +x bin/xray-linux-arm
    fi
    chmod +x x-ui bin/xray-linux-$(arch)

    mv -f /usr/bin/x-ui-temp /usr/bin/x-ui
    chmod +x /usr/bin/x-ui
    mkdir -p /var/log/x-ui
    config_after_install

    if [[ $release == "alpine" ]]; then
        curl -4fLRo /etc/init.d/x-ui https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.rc
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Failed to download x-ui.rc${plain}"
            OUTPUT_INSTALL_STATUS="failed_service_download"
            exit 1
        fi
        chmod +x /etc/init.d/x-ui
        rc-update add x-ui
        rc-service x-ui start
    else
        service_installed=false

        if [ -f "x-ui.service" ]; then
            cp -f x-ui.service ${xui_service}/ >/dev/null 2>&1 && service_installed=true
        fi

        if [ "$service_installed" = false ]; then
            case "${release}" in
                ubuntu | debian | armbian)
                    [ -f "x-ui.service.debian" ] && cp -f x-ui.service.debian ${xui_service}/x-ui.service >/dev/null 2>&1 && service_installed=true
                ;;
                arch | manjaro | parch)
                    [ -f "x-ui.service.arch" ] && cp -f x-ui.service.arch ${xui_service}/x-ui.service >/dev/null 2>&1 && service_installed=true
                ;;
                *)
                    [ -f "x-ui.service.rhel" ] && cp -f x-ui.service.rhel ${xui_service}/x-ui.service >/dev/null 2>&1 && service_installed=true
                ;;
            esac
        fi

        if [ "$service_installed" = false ]; then
            case "${release}" in
                ubuntu | debian | armbian)
                    curl -4fLRo ${xui_service}/x-ui.service https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.service.debian >/dev/null 2>&1
                ;;
                arch | manjaro | parch)
                    curl -4fLRo ${xui_service}/x-ui.service https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.service.arch >/dev/null 2>&1
                ;;
                *)
                    curl -4fLRo ${xui_service}/x-ui.service https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.service.rhel >/dev/null 2>&1
                ;;
            esac

            if [[ $? -ne 0 ]]; then
                echo -e "${red}Failed to install x-ui.service from GitHub${plain}"
                OUTPUT_INSTALL_STATUS="failed_service_download"
                exit 1
            fi
            service_installed=true
        fi

        if [ "$service_installed" = true ]; then
            chown root:root ${xui_service}/x-ui.service >/dev/null 2>&1
            chmod 644 ${xui_service}/x-ui.service >/dev/null 2>&1
            systemctl daemon-reload
            systemctl enable x-ui
            systemctl start x-ui
        else
            echo -e "${red}Failed to install x-ui.service file${plain}"
            OUTPUT_INSTALL_STATUS="failed_service_install"
            exit 1
        fi
    fi

    OUTPUT_INSTALL_STATUS="success"
    echo -e "${green}x-ui ${tag_version}${plain} installation finished, it is running now..."
}

export_results() {
    local u="${OUTPUT_USERNAME:-root}" p="${OUTPUT_PASSWORD:-${PASS:-}}"
    local scheme="https" host="${DOMAIN:-server}"
    echo ""
    echo "============================================"
    echo "  3x-ui Panel"
    echo "    URL:  https://srtnl.${host}/3x-ui/"
    echo "    User: $u"
    echo "    Pass: ${p:-<not set>}"
    echo ""
    echo "  Dashboard"
    echo "    URL:  https://srtnl.${host}/dashboard/"
    echo "============================================"
}

install_base
install_x-ui $1
export_results
