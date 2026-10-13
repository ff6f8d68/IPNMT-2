#!/bin/bash
# IPNMT 3 - Installation Script
# IP Network Management Tool v3.0.0
# This script installs IPNMT 3 on your system

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/usr/local"
BIN_DIR="$INSTALL_DIR/bin"
LIB_DIR="$INSTALL_DIR/lib/ipnmt3"
SHARE_DIR="$INSTALL_DIR/share/ipnmt3"
MAN_DIR="$INSTALL_DIR/share/man/man1"

# Script directory (where this install.sh is located)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Logging
LOG_FILE="/tmp/ipnmt3_install_$(date +%Y%m%d_%H%M%S).log"
log() {
    local level=$1
    local message=$2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" | tee -a "$LOG_FILE"
}

echo_success() {
    echo -e "${GREEN}[OK]${NC} $1"
    log "INFO" "$1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    log "ERROR" "$1"
}

echo_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    log "WARNING" "$1"
}

echo_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    log "INFO" "$1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo_error "This installation script must be run as root. Please use sudo."
        exit 1
    fi
}

# Check system compatibility
check_system() {
    echo_info "Checking system compatibility..."
    
    if ! command -v bash &>/dev/null; then
        echo_error "Bash is required but not found"
        exit 1
    fi
    
    local arch=$(uname -m)
    echo_info "System architecture: $arch"
    
    if ! command -v ip &>/dev/null; then
        echo_warning "ip command not found. Some features may not work properly."
    fi
    
    echo_success "System compatibility check passed"
}

# Create man page
create_man_page() {
    local man_content="\
.TH IPNMT 1 "$(date +%Y-%m-%d)" "3.0.0" "IP Network Management Tool"
.SH NAME
ipnmt \- IP Network Management Tool for kernel-level debugging and WiFi controller access
.SH SYNOPSIS
.B ipnmt
[\fIOPTIONS\fP] \fICOMMAND\fP [\fIARGS\fP...]
.SH DESCRIPTION
.B ipnmt
is a comprehensive tool for performing kernel-level network debugging and direct access to WiFi controllers.
.SH OPTIONS
.TP
.B \-h, \-\-help
Show help message
.TP
.B \-v, \-\-version
Show version
.TP
.B \-d, \-\-debug
Enable debug mode
.SH COMMANDS
.SS Network Information
.TP
.B ifaces
List interfaces
.TP
.B iface <name>
Show interface details
.TP
.B ip
Show IP addresses
.TP
.B routes
Show routing table
.TP
.B arp
Show ARP cache
.TP
.B netstat
Show connections
.SS Network Debugging
.TP
.B ping <host>
Ping host
.TP
.B traceroute <host>
Trace route
.TP
.B iperf <host>
Iperf test
.TP
.B tcpdump
Packet capture
.TP
.B sniff
Packet sniffing
.SS Kernel Tools
.TP
.B kernel-info
Kernel config
.TP
.B sysctl [key]
Sysctl parameters
.TP
.B iptables
Iptables rules
.TP
.B nftables
Nftables rules
.TP
.B ethtool <iface>
Ethtool info
.SS WiFi Controller
.TP
.B wifi-scan
Scan WiFi
.TP
.B wifi-connect <ssid> [password]
Connect to WiFi
.TP
.B wifi-disconnect
Disconnect WiFi
.TP
.B wifi-info
WiFi info
.TP
.B wifi-list
List WiFi interfaces
.SS Advanced
.TP
.B socket
Raw socket ops
.TP
.B bpfilter
BPF filters
.TP
.B netns
Network namespaces
.SS Utilities
.TP
.B speedtest
Speed test
.TP
.B dns <domain>
DNS query
.TP
.B whois <domain>
WHOIS lookup
.SH EXAMPLES
.TP
.B ipnmt ifaces
.TP
.B ipnmt ping google.com
.TP
.B ipnmt wifi-scan
.SH FILES
.TP
.I /usr/local/bin/ipnmt
Main executable
.SH AUTHOR
IPNMT Team
"
    
    echo "$man_content" > "$SHARE_DIR/ipnmt.1"
    gzip -f "$SHARE_DIR/ipnmt.1" 2>/dev/null || true
}

install_dependencies() {
    echo_info "Checking dependencies..."
    local required=("ip" "ping" "traceroute" "arp" "ss" "ethtool" "iw")
    local optional=("tcpdump" "iperf3" "nft" "speedtest-cli" "dig" "whois" "nmcli" "wpa_supplicant" "bpftool")
    
    local missing_req=()
    for cmd in "${required[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_req+=("$cmd")
        fi
    done
    
    if [ ${#missing_req[@]} -gt 0 ]; then
        echo_warning "Missing required: ${missing_req[*]}"
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq "${missing_req[@]}" 2>&1 | grep -v "^Selecting\|^Preparing\|^Unpacking\|^Setting"
        elif command -v yum &>/dev/null; then
            yum install -y "${missing_req[@]}"
        elif command -v dnf &>/dev/null; then
            dnf install -y "${missing_req[@]}"
        elif command -v pacman &>/dev/null; then
            pacman -Sy --noconfirm "${missing_req[@]}"
        else
            echo_warning "Please install manually: ${missing_req[*]}"
        fi
    fi
    
    echo_success "Dependencies checked"
}

install_binary() {
    echo_info "Installing binary..."
    mkdir -p "$BIN_DIR" "$LIB_DIR" "$SHARE_DIR" "$MAN_DIR"
    cp "$SCRIPT_DIR/bin/ipnmt" "$BIN_DIR/ipnmt"
    chmod +x "$BIN_DIR/ipnmt"
    ln -sf "$BIN_DIR/ipnmt" /usr/bin/ipnmt 2>/dev/null || true
    echo_success "Binary installed to $BIN_DIR/ipnmt"
}

install_man_page() {
    echo_info "Installing man page..."
    create_man_page
    if [ -f "$SHARE_DIR/ipnmt.1.gz" ]; then
        cp "$SHARE_DIR/ipnmt.1.gz" "$MAN_DIR/ipnmt.1.gz"
        chmod 644 "$MAN_DIR/ipnmt.1.gz"
    fi
    if command -v mandb &>/dev/null; then
        mandb 2>/dev/null || true
    fi
    echo_success "Man page installed"
}

install_completion() {
    echo_info "Installing completion..."
    local completion_script="$SHARE_DIR/completion/bash/ipnmt"
    mkdir -p "$SHARE_DIR/completion/bash"
    
    cat > "$completion_script" << 'COMPEOF'
_ipnmt_completion() {
    local cur prev commands
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="ifaces iface ip routes arp netstat ping traceroute iperf tcpdump sniff kernel-info sysctl iptables nftables ethtool wifi-scan wifi-connect wifi-disconnect wifi-info wifi-list socket bpfilter netns speedtest dns whois help version"
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands} -h --help -v --version -d --debug" -- "${cur}") )
    elif [[ " $commands " == *" $prev "* ]]; then
        case $prev in
            iface|ethtool|ping|traceroute|iperf|dns|whois)
                COMPREPLY=( $(compgen -W "$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}')" -- "${cur}") );;
            wifi-connect) COMPREPLY=( $(compgen -W "$(iw dev 2>/dev/null | grep Interface | awk '{print $2}')" -- "${cur}") );;
            sysctl) COMPREPLY=( $(compgen -W "$(sysctl -a 2>/dev/null | grep '^net\.' | cut -d'=' -f1 | tr '.' ' ')" -- "${cur}") );;
            *) COMPREPLY=();;
        esac
    else
        COMPREPLY=()
    fi
}
complete -F _ipnmt_completion ipnmt
COMPEOF
    
    chmod 644 "$completion_script"
    echo_success "Completion installed"
}

create_config_dir() {
    echo_info "Creating config directory..."
    local config_dir="/etc/ipnmt3"
    mkdir -p "$config_dir"
    cat > "$config_dir/ipnmt3.conf" << 'EOF'
DEFAULT_INTERFACE=""
WIFI_INTERFACE=""
WIFI_TIMEOUT=30
PING_COUNT=4
TRACEROUTE_MAX_HOPS=30
DEBUG=false
LOG_LEVEL="INFO"
LOG_FILE="/var/log/ipnmt3.log"
ENABLE_COLORS=true
EOF
    chmod 644 "$config_dir/ipnmt3.conf"
    echo_success "Config created at /etc/ipnmt3"
}

verify_installation() {
    echo_info "Verifying installation..."
    [ -x "$BIN_DIR/ipnmt" ] && echo_success "Binary OK" || { echo_error "Binary failed"; exit 1; }
    command -v ipnmt &>/dev/null && echo_success "In PATH" || echo_warning "Add $BIN_DIR to PATH"
    "$BIN_DIR/ipnmt" --version &>/dev/null && echo_success "Version OK" || { echo_error "Version failed"; exit 1; }
    echo_success "Installation verified"
}

show_summary() {
    echo ""
    echo "=========================================="
    echo "    IPNMT 3 Installation Complete"
    echo "=========================================="
    echo ""
    echo "Installed to: $INSTALL_DIR"
    echo "Binary:      $BIN_DIR/ipnmt"
    echo "Config:      /etc/ipnmt3/"
    echo ""
    echo "Usage:"
    echo "  ipnmt --help"
    echo "  ipnmt ifaces"
    echo "  ipnmt wifi-scan"
    echo ""
}

main() {
    echo ""
    echo "=========================================="
    echo "    IPNMT 3 Installation"
    echo "=========================================="
    echo ""
    check_root
    check_system
    install_dependencies
    install_binary
    install_man_page
    install_completion
    create_config_dir
    verify_installation
    show_summary
}

case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [--help|--version|--prefix=DIR|--uninstall]"
        exit 0;;
    --version|-v)
        echo "IPNMT 3 Installer v3.0.0"
        exit 0;;
    --prefix=*)
        INSTALL_DIR="${1#*=}"
        BIN_DIR="$INSTALL_DIR/bin"
        LIB_DIR="$INSTALL_DIR/lib/ipnmt3"
        SHARE_DIR="$INSTALL_DIR/share/ipnmt3"
        MAN_DIR="$INSTALL_DIR/share/man/man1"
        shift; main "$@";;
    --uninstall)
        echo "Uninstalling IPNMT 3..."
        rm -f "$BIN_DIR/ipnmt" /usr/bin/ipnmt
        rm -rf "$LIB_DIR" "$SHARE_DIR"
        rm -f "$MAN_DIR/ipnmt.1.gz"
        rm -rf /etc/ipnmt3
        echo "Uninstalled."; exit 0;;
    *)
        main "$@";;
esac
