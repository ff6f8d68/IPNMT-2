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
    echo -e "  \033[34mhelp\033[0m - Show this help message."
    echo -e "  \033[34mexit\033[0m - Exit the custom shell."
}

# Function to list network interfaces with IP addresses and MAC addresses
list_network_info() {
 #!/bin/bash

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
    sudo systemctl start sshd
    sudo systemctl enable sshd
    echo "connect with the IP:"
    curl ifconfig.me
    echo "
    "
    echo "and the username:"
    whoami
}

# Start custom shell loop
while true; do
    # Clear the screen and display the logo
    clear
    display_logo

    # Get the username
    local username=$(whoami)

    # Display the prompt with the username
    echo -n "${username}/IPNMT 2 shell> "
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
        "startagent")
            start_agent "$args"
            ;;
        "help")
            display_help
            ;;
        "exit")
            echo "Goodbye!"
            break
            ;;
        *)
            echo "Unknown command: $cmd"
            ;;
    esac

    # Wait for user input to continue
    read -n 1 -s -r -p "Press any key to continue..."
done
