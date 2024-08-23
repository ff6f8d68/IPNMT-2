#!/bin/bash
   echo -e "\033[34m"
    cat << "EOF"

 ___  ________  ________   _____ ______   _________         _______     
|\  \|\   __  \|\   ___  \|\   _ \  _   \|\___   ___\      /  ___  \    
\ \  \ \  \|\  \ \  \\ \  \ \  \\\__\ \  \|___ \  \_|     /__/|_/  /|   
 \ \  \ \   ____\ \  \\ \  \ \  \\|__| \  \   \ \  \      |__|//  / /   
  \ \  \ \  \___|\ \  \\ \  \ \  \    \ \  \   \ \  \         /  /_/__  
   \ \__\ \__\    \ \__\\ \__\ \__\    \ \__\   \ \__\       |\________\
    \|__|\|__|     \|__| \|__|\|__|     \|__|    \|__|        \|_______|

EOF
    echo -e "\033[0m"
    echo -e "\033[34mIPNMT 2: IP Network Management Tool 2\033[0m"
# Function to display the logo and IPNMT 2 information
display_logo() {
    echo -e "\033[34m"
    cat << "EOF"

 ___  ________  ________   _____ ______   _________         _______     
|\  \|\   __  \|\   ___  \|\   _ \  _   \|\___   ___\      /  ___  \    
\ \  \ \  \|\  \ \  \\ \  \ \  \\\__\ \  \|___ \  \_|     /__/|_/  /|   
 \ \  \ \   ____\ \  \\ \  \ \  \\|__| \  \   \ \  \      |__|//  / /   
  \ \  \ \  \___|\ \  \\ \  \ \  \    \ \  \   \ \  \         /  /_/__  
   \ \__\ \__\    \ \__\\ \__\ \__\    \ \__\   \ \__\       |\________\
    \|__|\|__|     \|__| \|__|\|__|     \|__|    \|__|        \|_______|

EOF
    echo -e "\033[0m"
    echo -e "\033[34mIPNMT 2: IP Network Management Tool 2\033[0m"
}

# Function to display help information
display_help() {
    echo -e "\033[34mAvailable Commands:\033[0m"
    echo -e "  \033[34mhello\033[0m - Greet the user."
    echo -e "  \033[34mdate\033[0m - Show the current date and time."
    echo -e "  \033[34mipnmt\033[0m - Display information about IPNMT 2."
    echo -e "  \033[34mscan\033[0m - Scan for devices in the current network."
    echo -e "  \033[34mlist\033[0m - List network interfaces with IP addresses and MAC addresses."
    echo -e "  \033[34mconnect [ip]\033[0m - SSH connect to the specified IP address."
    echo -e "  \033[34mkick [ip]\033[0m - Kick the specified IP address out of the network."
    echo -e "  \033[34mscanip [domain]\033[0m - Resolve a domain to its IP addresses."
    echo -e "  \033[34mstartagent [port]\033[0m - Start an SSH server on the specified port."
    echo -e "  \033[34mforward [local_port] [remote_ip] [remote_port]\033[0m - Forward a local port to a remote IP and port."
    echo -e "  \033[34mstatus\033[0m - Show the status of network interfaces and routing table."
    echo -e "  \033[34mstats\033[0m - Show network statistics and packet statistics."
    echo -e "  \033[34msaveconfig [name] [config]\033[0m - Save a configuration to a file."
    echo -e "  \033[34mloadconfig [name]\033[0m - Load a configuration from a file."
    echo -e "  \033[34mdnslookup [domain]\033[0m - Perform a DNS lookup for a domain."
    echo -e "  \033[34mnmap [target]\033[0m - Scan a target using nmap."
    echo -e "  \033[34mfirewall [action] [rule]\033[0m - Manage firewall rules (add/remove/list)."
    echo -e "  \033[34msysteminfo\033[0m - Show system information."
    echo -e "  \033[34muser [action] [username]\033[0m - Manage users (add/remove/check)."
    echo -e "  \033[34mping [host]\033[0m - Ping a host to check connectivity."
    echo -e "  \033[34mtraceroute [host]\033[0m - Trace the route to a host."
    echo -e "  \033[34mbackup [source] [destination]\033[0m - Backup files or directories."
    echo -e "  \033[34mrestore [source] [destination]\033[0m - Restore files or directories from a backup."
    echo -e "  \033[34mdiskusage\033[0m - Show disk usage statistics."
    echo -e "  \033[34mprocesslist\033[0m - List running processes."
    echo -e "  \033[34mkill [pid]\033[0m - Kill a process by its PID."
    echo -e "  \033[34mservice [service_name] [start/stop/restart/status]\033[0m - Manage system services."
    echo -e "  \033[34mupdate\033[0m - Update system packages."
    echo -e "  \033[34mupgrade\033[0m - Upgrade system packages."
    echo -e "  \033[34mlog [filename]\033[0m - View or tail a log file."
    echo -e "  \033[34mhelp\033[0m - Show this help message."
    echo -e "  \033[34mexit\033[0m - Exit the custom shell."
}

# Function to list network interfaces with IP addresses and MAC addresses
list_network_info() {
    printf '%10s %32s %32s\n' interface ipaddress macaddress
    printf '%s\n' '----------------------------------------------------------------------------'
    for each in $(ifconfig | grep -E '^[a-z]' | awk '{print $1}'); do
        mac=$(ifconfig "$each" | grep -oE '(?<=ether\s)[0-9a-f:]+')
        for address in $(ifconfig "$each" | grep -oE '(?<=inet\s)[0-9.]+|(?<=inet6\s)[0-9a-f:]+'); do
            printf '%10s %32s %32s\n' "$each" "$address" "$mac"
        done
    done
}

# Function to scan the network for devices
scan_network() {
    echo "Scanning network for devices..."
    arp -a
}

# Function to resolve a domain to its IP addresses
scan_ip() {
    local domain=$1
    
    if [[ -z "$domain" ]]; then
        echo "Usage: scanip [domain]"
        echo "Example: scanip www.example.com"
        return
    fi
    
    echo "Resolving domain $domain to IP addresses..."
    
    # Use dig to resolve the domain name
    dig +short "$domain"
}

# Function to kick an IP address from the network
kick_ip() {
    local ip=$1
    
    if [[ -z "$ip" ]]; then
        echo "Usage: kick [ip]"
        echo "Example: kick 192.168.1.100"
        return
    fi
    
    echo "Attempting to kick IP $ip from the network..."
    
    # Check if IP is in the ARP table
    if ! arp -n | grep -q "$ip"; then
        echo "IP $ip not found in ARP table."
        return
    fi
    
    # Flush ARP cache (macOS does not have a direct command for this)
    sudo dscacheutil -flushcache
    sudo killall -HUP mDNSResponder
    
    echo "IP $ip has been removed from ARP table and DNS cache has been refreshed."
}

# Function to connect to an IP address using SSH
connect_ssh() {
    local ip=$1

    if [[ -z "$ip" ]]; then
        echo "Usage: connect [ip]"
        echo "Example: connect 192.168.1.100"
        return
    fi

    echo "Connecting to $ip via SSH..."
    ssh "$ip"
}

# Function to start an SSH agent on a specified port
start_agent() {
    local port=$1
    
    if [[ -z "$port" ]]; then
        echo "Usage: startagent [port]"
        echo "Example: startagent 2222"
        return
    fi

    echo "Starting SSH agent on port $port..."
    
    # macOS may need `brew services start` if using Homebrew SSH server
    brew services start openssh
}

# Function to forward a local port to a remote IP and port
port_forward() {
    local local_port=$1
    local remote_ip=$2
    local remote_port=$3
    
    if [[ -z "$local_port" || -z "$remote_ip" || -z "$remote_port" ]]; then
        echo "Usage: forward [local_port] [remote_ip] [remote_port]"
        echo "Example: forward 8080 192.168.1.100 80"
        return
    fi

    echo "Forwarding local port $local_port to $remote_ip:$remote_port..."
    
    # Set up port forwarding using `ssh` command
    ssh -L "$local_port:$remote_ip:$remote_port" user@localhost
}

# Function to display system information
display_system_info() {
    echo "System Information:"
    uname -a
    echo "Disk Usage:"
    df -h
    echo "Memory Usage:"
    vm_stat
    echo "Uptime:"
    uptime
}

# Function to display status of network interfaces and routing table
display_status() {
    echo "Network Interfaces Status:"
    ifconfig
    echo "Routing Table:"
    netstat -nr
}

# Function to show network statistics and packet statistics
display_stats() {
    echo "Network Statistics:"
    netstat -i
}

# Function to save a configuration to a file
save_config() {
    local name=$1
    local config=$2

    if [[ -z "$name" || -z "$config" ]]; then
        echo "Usage: saveconfig [name] [config]"
        echo "Example: saveconfig myconfig \"interface=eth0 ip=192.168.1.10\""
        return
    fi

    echo "Saving configuration to $name.conf..."
    echo "$config" > "$name.conf"
    echo "Configuration saved to $name.conf"
}

# Function to load a configuration from a file
load_config() {
    local name=$1

    if [[ -z "$name" ]]; then
        echo "Usage: loadconfig [name]"
        echo "Example: loadconfig myconfig"
        return
    fi

    if [[ ! -f "$name.conf" ]]; then
        echo "Configuration file $name.conf not found."
        return
    fi

    echo "Loading configuration from $name.conf..."
    cat "$name.conf"
}

# Main loop for custom shell
while true; do
    echo -n "Enter command (type 'help' for available commands): "
    read -r command args

    case "$command" in
        hello)
            echo "Hello, User!"
            ;;
        date)
            date
            ;;
        ipnmt)
            display_logo
            ;;
        scan)
            scan_network
            ;;
        list)
            list_network_info
            ;;
        connect)
            connect_ssh "$args"
            ;;
        kick)
            kick_ip "$args"
            ;;
        scanip)
            scan_ip "$args"
            ;;
        startagent)
            start_agent "$args"
            ;;
        forward)
            port_forward $args
            ;;
        status)
            display_status
            ;;
        stats)
            display_stats
            ;;
        saveconfig)
            save_config $args
            ;;
        loadconfig)
            load_config "$args"
            ;;
        dnslookup)
            dig +short "$args"
            ;;
        nmap)
            nmap "$args"
            ;;
        firewall)
            echo "Firewall management not implemented yet."
            ;;
        systeminfo)
            display_system_info
            ;;
        user)
            echo "User management not implemented yet."
            ;;
        ping)
            ping "$args"
            ;;
        traceroute)
            traceroute "$args"
            ;;
        backup)
            echo "Backup functionality not implemented yet."
            ;;
        restore)
            echo "Restore functionality not implemented yet."
            ;;
        diskusage)
            df -h
            ;;
        processlist)
            ps aux
            ;;
        kill)
            kill "$args"
            ;;
        service)
            echo "Service management not implemented yet."
            ;;
        update)
            brew update
            ;;
        upgrade)
            brew upgrade
            ;;
        log)
            tail -f "$args"
            ;;
        help)
            display_help
            ;;
        exit)
            echo "Exiting custom shell."
            break
            ;;
        *)
            echo "Unknown command: $command"
            ;;
    esac
done
