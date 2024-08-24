#!/bin/bash

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

# Encryption and Decryption Key (hardcoded for simplicity)
ENCRYPTION_KEY="SuperSecretKey"

# Function to encrypt a message
encrypt_message() {
    local message=$1
    if [[ -z "$message" ]]; then
        echo "Usage: encrypt [message]"
        return
    fi
    echo "$message" | openssl enc -aes-256-cbc -a -salt -pass pass:"$ENCRYPTION_KEY"
}

# Function to start a listener
start_listener() {
    echo "Starting listener..."
    while true; do
        read -p "Enter an encrypted message: " encrypted_message
        if [[ "$encrypted_message" == "exit" ]]; then
            echo "Listener stopped."
            break
        fi
        echo "$encrypted_message" | openssl enc -aes-256-cbc -d -a -pass pass:"$ENCRYPTION_KEY"
    done
}

# Function to send an encrypted message to the network
send_encrypted_message() {
    local message=$1
    if [[ -z "$message" ]]; then
        echo "Usage: send [message]"
        return
    fi
    encrypted_message=$(encrypt_message "$message")
    echo "Encrypted message: $encrypted_message"
    echo "$encrypted_message" | nc -w 1 -u 255.255.255.255 12345
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
    echo -e "  \033[34mencrypt [message]\033[0m - Encrypt a message."
    echo -e "  \033[34mlisten\033[0m - Start a listener to receive encrypted messages."
    echo -e "  \033[34msend [message]\033[0m - Send an encrypted message."
    echo -e "  \033[34mhelp\033[0m - Show this help message."
    echo -e "  \033[34mexit\033[0m - Exit the custom shell."
}

# Function to list network interfaces with IP addresses and MAC addresses
list_network_info() {
    printf '%10s %32s %32s\n' interface ipaddress macaddress
    printf '%s\n' '----------------------------------------------------------------------------'
    for each in $(ip address | grep -oP '(^[\d]+:\s)\K[\d\w]+'); do
        mac=$(ip address show ${each} | grep -oP '(?<=link/ether\s)\K[\da-f:]+|(?<=link/loopback\s)\K[\da-f:]+')
        for address in $(ip address show ${each} | grep -oP '(?<=inet\s)\K[\d.]+|(?<=inet6\s)\K[\da-f:]+'); do
            printf '%10s %32s %32s\n' ${each} ${address} ${mac}
        done
    done
}

# Function to scan the network for devices
scan_network() {
    echo "Scanning network for devices..."
    sudo arp -a
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
        echo "Error: IP $ip not found in the ARP table."
        return
    fi
    
    # Retrieve the MAC address associated with the IP
    local mac
    mac=$(arp -n | grep "$ip" | awk '{print $3}')
    
    if [[ -z "$mac" ]]; then
        echo "Error: Unable to retrieve MAC address for IP $ip."
        return
    fi
    
    echo "Found MAC address $mac for IP $ip. Blocking network access..."
    
    # Use iptables to block traffic from the MAC address
    sudo iptables -A INPUT -m mac --mac-source "$mac" -j DROP
    
    if [[ $? -eq 0 ]]; then
        echo "Successfully kicked IP $ip from the network."
    else
        echo "Error: Failed to kick IP $ip from the network."
    fi
}

# Function to connect to a remote server via SSH
connect_to_ip() {
    local ip=$1
    
    if [[ -z "$ip" ]]; then
        echo "Usage: connect [ip]"
        echo "Example: connect 192.168.1.100"
        return
    fi
    
    echo "Connecting to $ip via SSH..."
    ssh "$ip"
}

# Function to perform a DNS lookup for a domain
dns_lookup() {
    local domain=$1
    
    if [[ -z "$domain" ]]; then
        echo "Usage: dnslookup [domain]"
        echo "Example: dnslookup www.example.com"
        return
    fi
    
    echo "Performing DNS lookup for domain $domain..."
    
    # Use dig to perform the DNS lookup
    dig "$domain"
}

# Function to scan a target using nmap
nmap_scan() {
    local target=$1
    
    if [[ -z "$target" ]]; then
        echo "Usage: nmap [target]"
        echo "Example: nmap 192.168.1.0/24"
        return
    fi
    
    echo "Scanning target $target using nmap..."
    nmap "$target"
}

# Function to add or remove firewall rules
manage_firewall() {
    local action=$1
    local rule=$2
    
    if [[ -z "$action" || -z "$rule" ]]; then
        echo "Usage: firewall [action] [rule]"
        echo "Example: firewall add 192.168.1.100"
        echo "Example: firewall remove 192.168.1.100"
        echo "Example: firewall list"
        return
    fi
    
    case "$action" in
        add)
            echo "Adding firewall rule to allow $rule..."
            sudo ufw allow from "$rule"
            ;;
        remove)
            echo "Removing firewall rule for $rule..."
            sudo ufw delete allow from "$rule"
            ;;
        list)
            echo "Listing firewall rules..."
            sudo ufw status numbered
            ;;
        *)
            echo "Invalid action. Usage: firewall [add/remove/list] [rule]"
            ;;
    esac
}

# Function to start an SSH server on the specified port
start_ssh_agent() {
    local port=$1
    
    if [[ -z "$port" ]]; then
        echo "Usage: startagent [port]"
        echo "Example: startagent 2222"
        return
    fi
    
    echo "Starting SSH server on port $port..."
    sudo /usr/sbin/sshd -p "$port"
}

# Function to forward a local port to a remote IP and port
port_forwarding() {
    local local_port=$1
    local remote_ip=$2
    local remote_port=$3
    
    if [[ -z "$local_port" || -z "$remote_ip" || -z "$remote_port" ]]; then
        echo "Usage: forward [local_port] [remote_ip] [remote_port]"
        echo "Example: forward 8080 192.168.1.100 80"
        return
    fi
    
    echo "Forwarding local port $local_port to $remote_ip:$remote_port..."
    ssh -L "$local_port":"$remote_ip":"$remote_port" "$remote_ip"
}

# Function to show the status of network interfaces and routing table
show_status() {
    echo "Network Interfaces:"
    ip address
    echo "Routing Table:"
    ip route
}

# Function to show network statistics and packet statistics
show_stats() {
    echo "Network Statistics:"
    netstat -s
    echo "Packet Statistics:"
    ip -s link
}

# Function to save a configuration to a file
save_config() {
    local name=$1
    local config=$2
    
    if [[ -z "$name" || -z "$config" ]]; then
        echo "Usage: saveconfig [name] [config]"
        echo "Example: saveconfig myconfig 'ip address show'"
        return
    fi
    
    echo "Saving configuration to $name.conf..."
    eval "$config" > "$name.conf"
}

# Function to load a configuration from a file
load_config() {
    local name=$1
    
    if [[ -z "$name" ]]; then
        echo "Usage: loadconfig [name]"
        echo "Example: loadconfig myconfig"
        return
    fi
    
    echo "Loading configuration from $name.conf..."
    source "$name.conf"
}

# Function to show system information
system_info() {
    echo "System Information:"
    uname -a
    echo "CPU Information:"
    lscpu
    echo "Memory Information:"
    free -h
    echo "Disk Information:"
    df -h
}

# Function to manage users (add/remove/check)
manage_users() {
    local action=$1
    local username=$2
    
    if [[ -z "$action" || -z "$username" ]]; then
        echo "Usage: user [action] [username]"
        echo "Example: user add myuser"
        echo "Example: user remove myuser"
        echo "Example: user check myuser"
        return
    fi
    
    case "$action" in
        add)
            echo "Adding user $username..."
            sudo adduser "$username"
            ;;
        remove)
            echo "Removing user $username..."
            sudo deluser "$username"
            ;;
        check)
            echo "Checking if user $username exists..."
            if id "$username" &>/dev/null; then
                echo "User $username exists."
            else
                echo "User $username does not exist."
            fi
            ;;
        *)
            echo "Invalid action. Usage: user [add/remove/check] [username]"
            ;;
    esac
}

# Function to ping a host to check connectivity
ping_host() {
    local host=$1
    
    if [[ -z "$host" ]]; then
        echo "Usage: ping [host]"
        echo "Example: ping www.example.com"
        return
    fi
    
    echo "Pinging host $host..."
    ping -c 4 "$host"
}

# Function to trace the route to a host
trace_route() {
    local host=$1
    
    if [[ -z "$host" ]]; then
        echo "Usage: traceroute [host]"
        echo "Example: traceroute www.example.com"
        return
    fi
    
    echo "Tracing route to host $host..."
    traceroute "$host"
}

# Function to backup files or directories
backup_data() {
    local source=$1
    local destination=$2
    
    if [[ -z "$source" || -z "$destination" ]]; then
        echo "Usage: backup [source] [destination]"
        echo "Example: backup /path/to/source /path/to/backup"
        return
    fi
    
    echo "Backing up $source to $destination..."
    rsync -avh "$source" "$destination"
}

# Function to restore files or directories from a backup
restore_data() {
    local source=$1
    local destination=$2
    
    if [[ -z "$source" || -z "$destination" ]]; then
        echo "Usage: restore [source] [destination]"
        echo "Example: restore /path/to/backup /path/to/restore"
        return
    fi
    
    echo "Restoring $source to $destination..."
    rsync -avh "$source" "$destination"
}

# Function to show disk usage statistics
disk_usage() {
    echo "Disk Usage Statistics:"
    df -h
}

# Function to list running processes
process_list() {
    echo "Running Processes:"
    ps aux
}

# Function to kill a process by its PID
kill_process() {
    local pid=$1
    
    if [[ -z "$pid" ]]; then
        echo "Usage: kill [pid]"
        echo "Example: kill 12345"
        return
    fi
    
    echo "Killing process with PID $pid..."
    sudo kill "$pid"
}

# Function to manage system services
manage_service() {
    local service_name=$1
    local action=$2
    
    if [[ -z "$service_name" || -z "$action" ]]; then
        echo "Usage: service [service_name] [start/stop/restart/status]"
        echo "Example: service apache2 start"
        return
    fi
    
    echo "$action service $service_name..."
    sudo systemctl "$action" "$service_name"
}

# Function to update system packages
update_system() {
    echo "Updating system packages..."
    sudo apt-get update
}

# Function to upgrade system packages
upgrade_system() {
    echo "Upgrading system packages..."
    sudo apt-get upgrade -y
}

# Function to view or tail a log file
view_log() {
    local filename=$1
    
    if [[ -z "$filename" ]]; then
        echo "Usage: log [filename]"
        echo "Example: log /var/log/syslog"
        return
    fi
    
    echo "Displaying last 10 lines of log file $filename..."
    tail -n 10 "$filename"
}

# Function to clear a log file
clear_log() {
    local filename=$1
    
    if [[ -z "$filename" ]]; then
        echo "Usage: clearlog [filename]"
        echo "Example: clearlog /var/log/syslog"
        return
    fi
    
    echo "Clearing log file $filename..."
    sudo truncate -s 0 "$filename"
}

# Main function to handle the commands
main() {
    local command=$1
    shift
    
    case "$command" in
        check)
            check_ip "$@"
            ;;
        kick)
            kick_ip "$@"
            ;;
        connect)
            connect_to_ip "$@"
            ;;
        dnslookup)
            dns_lookup "$@"
            ;;
        nmap)
            nmap_scan "$@"
            ;;
        firewall)
            manage_firewall "$@"
            ;;
        startagent)
            start_ssh_agent "$@"
            ;;
        forward)
            port_forwarding "$@"
            ;;
        status)
            show_status "$@"
            ;;
        stats)
            show_stats "$@"
            ;;
        saveconfig)
            save_config "$@"
            ;;
        loadconfig)
            load_config "$@"
            ;;
        sysinfo)
            system_info "$@"
            ;;
        user)
            manage_users "$@"
            ;;
        ping)
            ping_host "$@"
            ;;
        traceroute)
            trace_route "$@"
            ;;
        backup)
            backup_data "$@"
            ;;
        restore)
            restore_data "$@"
            ;;
        disk)
            disk_usage "$@"
            ;;
        process)
            process_list "$@"
            ;;
        kill)
            kill_process "$@"
            ;;
        service)
            manage_service "$@"
            ;;
        update)
            update_system "$@"
            ;;
        upgrade)
            upgrade_system "$@"
            ;;
        log)
            view_log "$@"
            ;;
        clearlog)
            clear_log "$@"
            ;;
        *)
            echo "Invalid command: $command"
            echo "Available commands: check, kick, connect, dnslookup, nmap, firewall, startagent, forward, status, stats, saveconfig, loadconfig, sysinfo, user, ping, traceroute, backup, restore, disk, process, kill, service, update, upgrade, log, clearlog"
            ;;
    esac
}

# Entry point of the script
main "$@"
