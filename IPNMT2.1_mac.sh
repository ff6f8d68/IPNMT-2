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
    echo -e "  \033[34mencrypt [filename]\033[0m - Encrypt a file."
    echo -e "  \033[34mlistener start [port]\033[0m - Start a network listener on the specified port."
    echo -e "  \033[34mhelp\033[0m - Show this help message."
    echo -e "  \033[34mexit\033[0m - Exit the custom shell."
    echo -e "  \033[34mnetlog\033[0m - log all activity in the network"
}
monitor_network() {
# Define log file location
logfile="network_activity.log"

# Ensure log file is created and writable
touch "$logfile" || { echo "Error: Cannot create log file at $logfile"; exit 1; }

# Function to log network activity
log_network_activity() {
    local message=$1
    echo "$(date): $message" >> "$logfile"
    echo "$message"  # Print to console
}
    echo "Monitoring network traffic. Logging to $logfile..."

    # Start capturing network traffic with tcpdump
    sudo tcpdump |
    while IFS= read -r line; do
        # Filter out non-essential traffic
        if [[ "$line" == *"Flags [S]"* || "$line" == *"Flags [P.]"* ]]; then
            # Look for HTTP requests (GET/POST), DNS queries, and suspicious domains
            if [[ "$line" == *"HTTP"* || "$line" == *"GET"* || "$line" == *"POST"* ]]; then
                log_network_activity "HTTP request: $line"
            elif [[ "$line" == *"DNS"* ]]; then
                log_network_activity "DNS query: $line"
            elif [[ "$line" == *"Telegram"* || "$line" == *"Discord"* || "$line" == *"Pastebin"* ]]; then
                log_network_activity "Suspicious traffic: $line"
            else
                log_network_activity "User traffic: $line"
            fi
        fi
    done
}
# Function to list network interfaces with IP addresses and MAC addresses
list_network_info() {
    printf '%10s %32s %32s\n' interface ipaddress macaddress
    printf '%s\n' '----------------------------------------------------------------------------'
    for each in $(ifconfig -l); do
        mac=$(ifconfig "$each" | grep -oE '([0-9a-f]{2}[:]){5}[0-9a-f]{2}')
        for address in $(ifconfig "$each" | grep -oE 'inet [0-9.]+|inet6 [0-9a-f:]+'); do
            address=$(echo "$address" | awk '{print $2}')
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
    if ! arp -a | grep -q "$ip"; then
        echo "IP $ip not found in ARP table."
        return
    fi
    
    # Flush ARP cache
    sudo arp -d "$ip"
    
    echo "IP $ip has been removed from ARP table."
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
        echo "Example: startagent 22"
        return
    fi

    sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
    echo "Connect with the IP:"
    curl ifconfig.me
    echo ""
    echo "And the username:"
    whoami
    echo ""
    echo "The SSH server is running on port $port."
}

# Function to forward a local port to a remote IP and port
forward_port() {
    local local_port=$1
    local remote_ip=$2
    local remote_port=$3

    if [[ -z "$local_port" || -z "$remote_ip" || -z "$remote_port" ]]; then
        echo "Usage: forward [local_port] [remote_ip] [remote_port]"
        echo "Example: forward 8080 192.168.1.100 80"
        return
    fi

    echo "Forwarding local port $local_port to $remote_ip:$remote_port..."
    ssh -L "$local_port:$remote_ip:$remote_port" "$remote_ip"
}

# Function to display network status
network_status() {
    echo "Network status:"
    ifconfig
    netstat -nr
}

# Function to display network statistics
network_stats() {
    echo "Network statistics:"
    netstat -i
}

# Function to save a configuration to a file
save_config() {
    local name=$1
    local config=$2

    if [[ -z "$name" || -z "$config" ]]; then
        echo "Usage: saveconfig [name] [config]"
        echo "Example: saveconfig myconfig 'config content'"
        return
    fi

    echo "$config" > "$name"
    echo "Configuration saved as $name."
}

# Function to load a configuration from a file
load_config() {
    local name=$1

    if [[ -z "$name" ]]; then
        echo "Usage: loadconfig [name]"
        echo "Example: loadconfig myconfig"
        return
    fi

    if [[ ! -f "$name" ]]; then
        echo "Configuration file $name not found."
        return
    fi

    cat "$name"
}

# Function to perform a DNS lookup
dns_lookup() {
    local domain=$1
    
    if [[ -z "$domain" ]]; then
        echo "Usage: dnslookup [domain]"
        echo "Example: dnslookup www.example.com"
        return
    fi
    
    echo "Performing DNS lookup for $domain..."
    dig "$domain"
}

# Function to scan a target using nmap
nmap_scan() {
    local target=$1
    
    if [[ -z "$target" ]]; then
        echo "Usage: nmap [target]"
        echo "Example: nmap 192.168.1.1"
        return
    fi
    
    echo "Scanning target $target with nmap..."
    nmap "$target"
}

# Function to manage firewall rules
firewall_manage() {
    local action=$1
    local rule=$2
    
    if [[ -z "$action" || -z "$rule" ]]; then
        echo "Usage: firewall [action] [rule]"
        echo "Actions: add, remove, list"
        echo "Example: firewall add 'block port 80'"
        return
    fi
    
    case "$action" in
        add)
            echo "Adding firewall rule: $rule"
            # Placeholder command for adding firewall rule
            sudo pfctl -a "$rule" -f /etc/pf.conf
            ;;
        remove)
            echo "Removing firewall rule: $rule"
            # Placeholder command for removing firewall rule
            sudo pfctl -a "$rule" -f /etc/pf.conf
            ;;
        list)
            echo "Listing firewall rules:"
            sudo pfctl -sr
            ;;
        *)
            echo "Invalid action. Use add, remove, or list."
            ;;
    esac
}

# Function to show system information
system_info() {
    echo "System Information:"
    uname -a
    sw_vers
}

# Function to manage users
manage_users() {
    local action=$1
    local username=$2
    
    if [[ -z "$action" || -z "$username" ]]; then
        echo "Usage: user [action] [username]"
        echo "Actions: add, remove, check"
        echo "Example: user add johndoe"
        return
    fi
    
    case "$action" in
        add)
            echo "Adding user $username..."
            sudo dscl . -create /Users/"$username"
            sudo dscl . -create /Users/"$username" UserShell /bin/bash
            sudo dscl . -create /Users/"$username" RealName "$username"
            sudo dscl . -create /Users/"$username" UniqueID "1001"
            sudo dscl . -create /Users/"$username" PrimaryGroupID 1000
            sudo dscl . -create /Users/"$username" NFSHomeDirectory /Users/"$username"
            sudo dscl . -passwd /Users/"$username" password
            sudo createhomedir -u "$username"
            ;;
        remove)
            echo "Removing user $username..."
            sudo dscl . -delete /Users/"$username"
            ;;
        check)
            echo "Checking user $username..."
            id "$username"
            ;;
        *)
            echo "Invalid action. Use add, remove, or check."
            ;;
    esac
}
ddos() {
    local target_ip=$1
    if [[ -z "$target_ip" ]]; then
        echo "Usage: ddos [target_ip]"
        echo "Example: ddos 192.168.1.100"
        return
    fi
    echo "Launching DDoS attack on $target_ip..."
 
host="$1"
shift
declare -i npings=50
declare -i duration=5

while getopts ":n:t:" opt
do
case $opt in
n) let npings=$OPTARG;;
t) let duration=$OPTARG;;
\?) echo "Usage: source dos.sh host [-n npings] [-t duration]" >&2;;
esac
done
 

for (( i=0; $i<$npings; i++ ))
do
ping "$host" > /dev/null &
done


sleep $duration
killall ping


unset opt i host npings duration
}
# Function to ping a host
ping_host() {
    local host=$1
    
    if [[ -z "$host" ]]; then
        echo "Usage: ping [host]"
        echo "Example: ping 192.168.1.1"
        return
    fi
    
    echo "Pinging host $host..."
    ping -c 4 "$host"
}

# Function to trace the route to a host
traceroute_host() {
    local host=$1
    
    if [[ -z "$host" ]]; then
        echo "Usage: traceroute [host]"
        echo "Example: traceroute www.example.com"
        return
    fi
    
    echo "Tracing route to $host..."
    traceroute "$host"
}

# Function to backup files or directories
backup_files() {
    local source=$1
    local destination=$2
    
    if [[ -z "$source" || -z "$destination" ]]; then
        echo "Usage: backup [source] [destination]"
        echo "Example: backup /path/to/source /path/to/destination"
        return
    fi
    
    echo "Backing up $source to $destination..."
    rsync -av --progress "$source" "$destination"
}

# Function to restore files or directories from a backup
restore_files() {
    local source=$1
    local destination=$2
    
    if [[ -z "$source" || -z "$destination" ]]; then
        echo "Usage: restore [source] [destination]"
        echo "Example: restore /path/to/backup /path/to/restore"
        return
    fi
    
    echo "Restoring from $source to $destination..."
    rsync -av --progress "$source" "$destination"
}

# Function to show disk usage statistics
disk_usage() {
    echo "Disk usage statistics:"
    df -h
}

# Function to list running processes
process_list() {
    echo "Running processes:"
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
    kill "$pid"
}

# Function to manage system services
manage_services() {
    local service_name=$1
    local action=$2
    
    if [[ -z "$service_name" || -z "$action" ]]; then
        echo "Usage: service [service_name] [start/stop/restart/status]"
        echo "Example: service ssh start"
        return
    fi
    
    case "$action" in
        start)
            echo "Starting service $service_name..."
            sudo launchctl load -w /System/Library/LaunchDaemons/"$service_name".plist
            ;;
        stop)
            echo "Stopping service $service_name..."
            sudo launchctl unload -w /System/Library/LaunchDaemons/"$service_name".plist
            ;;
        restart)
            echo "Restarting service $service_name..."
            sudo launchctl unload -w /System/Library/LaunchDaemons/"$service_name".plist
            sudo launchctl load -w /System/Library/LaunchDaemons/"$service_name".plist
            ;;
        status)
            echo "Checking status of service $service_name..."
            sudo launchctl list | grep "$service_name"
            ;;
        *)
            echo "Invalid action. Use start, stop, restart, or status."
            ;;
    esac
}

# Function to update system packages
update_system() {
    echo "Updating system packages..."
    softwareupdate --all --install --force
}

# Function to upgrade system packages
upgrade_system() {
    echo "Upgrading system packages..."
    sudo softwareupdate --all --install --force
}

# Function to view or tail a log file
view_log() {
    local filename=$1
    
    if [[ -z "$filename" ]]; then
        echo "Usage: log [filename]"
        echo "Example: log /var/log/system.log"
        return
    fi
    
    echo "Viewing log file $filename..."
    tail -f "$filename"
}

# Function to encrypt a file
encrypt_file() {
    local filename=$1
    
    if [[ -z "$filename" ]]; then
        echo "Usage: encrypt [filename]"
        echo "Example: encrypt /path/to/file.txt"
        return
    fi
    
    echo "Encrypting file $filename..."
    openssl enc -aes-256-cbc -salt -in "$filename" -out "$filename.enc"
}

# Function to start a network listener
start_listener() {
    local port=$1
    
    if [[ -z "$port" ]]; then
        echo "Usage: listener start [port]"
        echo "Example: listener start 8080"
        return
    fi
    
    echo "Starting network listener on port $port..."
    nc -l "$port"
}

# Main loop
while true; do
    # Get the username
    username=$(whoami)

    # Display the prompt with the username
    echo -n "$username/IPNMT 2 shell> "
    read -r input

    case "$input" in
        help)
            echo "Available commands:"
            echo "portforward - Forward local port to a remote IP and port"
            echo "network_status - Display network status"
            echo "network_stats - Display network statistics"
            echo "saveconfig - Save a configuration to a file"
            echo "loadconfig - Load a configuration from a file"
            echo "dnslookup - Perform a DNS lookup"
            echo "nmap - Scan a target using nmap"
            echo "firewall - Manage firewall rules"
            echo "system_info - Show system information"
            echo "user - Manage users"
            echo "ping - Ping a host"
            echo "traceroute - Trace the route to a host"
            echo "backup - Backup files or directories"
            echo "restore - Restore files or directories from a backup"
            echo "disk_usage - Show disk usage statistics"
            echo "process_list - List running processes"
            echo "kill - Kill a process by its PID"
            echo "service - Manage system services"
            echo "update_system - Update system packages"
            echo "upgrade_system - Upgrade system packages"
            echo "log - View or tail a log file"
            echo "encrypt - Encrypt a file"
            echo "listener - Start a network listener"
            echo "exit - Exit the program"
            ;;
        portforward)
            port_forward "$2" "$3" "$4" "$5"
            ;;
        network_status)
            network_status
            ;;
        network_stats)
            network_stats
            ;;
        saveconfig)
            save_config "$2" "$3"
            ;;
        loadconfig)
            load_config "$2"
            ;;
        dnslookup)
            dns_lookup "$2"
            ;;
        nmap)
            nmap_scan "$2"
            ;;
        firewall)
            firewall_manage "$2" "$3"
            ;;
        system_info)
            system_info
            ;;
        user)
            manage_users "$2" "$3"
            ;;
        ping)
            ping_host "$2"
            ;;
        traceroute)
            traceroute_host "$2"
            ;;
        backup)
            backup_files "$2" "$3"
            ;;
        restore)
            restore_files "$2" "$3"
            ;;
        disk_usage)
            disk_usage
            ;;
        process_list)
            process_list
            ;;
        kill)
            kill_process "$2"
            ;;
        service)
            manage_services "$2" "$3"
            ;;
        update_system)
            update_system
            ;;
        upgrade_system)
            upgrade_system
            ;;
        log)
            view_log "$2"
            ;;
        encrypt)
            encrypt_file "$2"
            ;;
        listener)
            start_listener "$2"
            ;;
        ddos)
            ddos "$args" -n 50 -t 5
            ;;
          netlog)
            monitor_network
            ;;
        exit)
            break
            ;;
        *)
            echo "Invalid command. Type 'help' for a list of commands."
            ;;
    esac
done
