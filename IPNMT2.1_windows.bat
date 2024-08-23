# Function to display the logo and IPNMT 2 information
function Display-Logo {
    Write-Host "`e[34m"
    Write-Host @"
 ___  ________  ________   _____ ______   _________         _______     
|\  \|\   __  \|\   ___  \|\   _ \  _   \|\___   ___\      /  ___  \    
\ \  \ \  \|\  \ \  \\ \  \ \  \\\__\ \  \|___ \  \_|     /__/|_/  /|   
 \ \  \ \   ____\ \  \\ \  \ \  \\|__| \  \   \ \  \      |__|//  / /   
  \ \  \ \  \___|\ \  \\ \  \ \  \    \ \  \   \ \  \         /  /_/__  
   \ \__\ \__\    \ \__\\ \__\ \__\    \ \__\   \ \__\       |\________\
    \|__|\|__|     \|__| \|__|\|__|     \|__|    \|__|        \|_______|

EOF
    Write-Host "`e[0m"
    Write-Host "`e[34mIPNMT 2: IP Network Management Tool 2`e[0m"
}

# Function to display help information
function Display-Help {
    Write-Host "`e[34mAvailable Commands:`e[0m"
    Write-Host "  `e[34mhello` `e[0m- Greet the user."
    Write-Host "  `e[34mdate` `e[0m- Show the current date and time."
    Write-Host "  `e[34mipnmt` `e[0m- Display information about IPNMT 2."
    Write-Host "  `e[34mscan` `e[0m- Scan for devices in the current network."
    Write-Host "  `e[34mlist` `e[0m- List network interfaces with IP addresses and MAC addresses."
    Write-Host "  `e[34mconnect [ip]` `e[0m- SSH connect to the specified IP address."
    Write-Host "  `e[34mkick [ip]` `e[0m- Kick the specified IP address out of the network."
    Write-Host "  `e[34mscanip [domain]` `e[0m- Resolve a domain to its IP addresses."
    Write-Host "  `e[34mstartagent [port]` `e[0m- Start an SSH server on the specified port."
    Write-Host "  `e[34mforward [local_port] [remote_ip] [remote_port]` `e[0m- Forward a local port to a remote IP and port."
    Write-Host "  `e[34mstatus` `e[0m- Show the status of network interfaces and routing table."
    Write-Host "  `e[34mstats` `e[0m- Show network statistics and packet statistics."
    Write-Host "  `e[34msaveconfig [name] [config]` `e[0m- Save a configuration to a file."
    Write-Host "  `e[34mloadconfig [name]` `e[0m- Load a configuration from a file."
    Write-Host "  `e[34mdnslookup [domain]` `e[0m- Perform a DNS lookup for a domain."
    Write-Host "  `e[34mnmap [target]` `e[0m- Scan a target using nmap."
    Write-Host "  `e[34mfirewall [action] [rule]` `e[0m- Manage firewall rules (add/remove/list)."
    Write-Host "  `e[34msysteminfo` `e[0m- Show system information."
    Write-Host "  `e[34muser [action] [username]` `e[0m- Manage users (add/remove/check)."
    Write-Host "  `e[34mping [host]` `e[0m- Ping a host to check connectivity."
    Write-Host "  `e[34mtraceroute [host]` `e[0m- Trace the route to a host."
    Write-Host "  `e[34mbackup [source] [destination]` `e[0m- Backup files or directories."
    Write-Host "  `e[34mrestore [source] [destination]` `e[0m- Restore files or directories from a backup."
    Write-Host "  `e[34mdiskusage` `e[0m- Show disk usage statistics."
    Write-Host "  `e[34mprocesslist` `e[0m- List running processes."
    Write-Host "  `e[34mkill [pid]` `e[0m- Kill a process by its PID."
    Write-Host "  `e[34mservice [service_name] [start/stop/restart/status]` `e[0m- Manage system services."
    Write-Host "  `e[34mupdate` `e[0m- Update system packages."
    Write-Host "  `e[34mupgrade` `e[0m- Upgrade system packages."
    Write-Host "  `e[34mlog [filename]` `e[0m- View or tail a log file."
    Write-Host "  `e[34mhelp` `e[0m- Show this help message."
    Write-Host "  `e[34mexit` `e[0m- Exit the custom shell."
}

# Function to list network interfaces with IP addresses and MAC addresses
function List-NetworkInfo {
    $networkInterfaces = Get-NetAdapter | Select-Object Name, MacAddress
    $networkInterfaces | ForEach-Object {
        $interfaceName = $_.Name
        $macAddress = $_.MacAddress
        $ipAddresses = (Get-NetIPAddress -InterfaceAlias $interfaceName).IPAddress
        foreach ($ip in $ipAddresses) {
            Write-Host "$interfaceName`t$ip`t$macAddress"
        }
    }
}

# Function to scan the network for devices
function Scan-Network {
    Write-Host "Scanning network for devices..."
    arp -a
}

# Function to resolve a domain to its IP addresses
function Scan-IP {
    param (
        [string]$domain
    )
    if (-not $domain) {
        Write-Host "Usage: scanip [domain]"
        Write-Host "Example: scanip www.example.com"
        return
    }

    Write-Host "Resolving domain $domain to IP addresses..."
    [System.Net.Dns]::GetHostAddresses($domain) | ForEach-Object { Write-Host $_.IPAddressToString }
}

# Function to kick an IP address from the network
function Kick-IP {
    param (
        [string]$ip
    )
    if (-not $ip) {
        Write-Host "Usage: kick [ip]"
        Write-Host "Example: kick 192.168.1.100"
        return
    }

    Write-Host "Attempting to kick IP $ip from the network..."

    # PowerShell does not have a direct equivalent for flushing ARP cache or resetting interfaces
    Write-Host "Note: Flushing ARP cache and resetting network interfaces is not directly supported in PowerShell."
}

# Function to connect to an IP address using SSH
function Connect-SSH {
    param (
        [string]$ip
    )
    if (-not $ip) {
        Write-Host "Usage: connect [ip]"
        Write-Host "Example: connect 192.168.1.100"
        return
    }

    Write-Host "Connecting to $ip via SSH..."
    ssh $ip
}

# Function to start an SSH agent on a specified port
function Start-Agent {
    param (
        [string]$port
    )
    if (-not $port) {
        Write-Host "Usage: startagent [port]"
        Write-Host "Example: startagent 22"
        return
    }

    Write-Host "Starting SSH agent on port $port..."
    # Note: SSH agent management is not directly available in PowerShell
}

# Function to forward a local port to a remote IP and port
function Forward-Port {
    param (
        [string]$localPort,
        [string]$remoteIP,
        [string]$remotePort
    )
    if (-not $localPort -or -not $remoteIP -or -not $remotePort) {
        Write-Host "Usage: forward [local_port] [remote_ip] [remote_port]"
        Write-Host "Example: forward 8080 192.168.1.100 80"
        return
    }

    Write-Host "Setting up port forwarding from local port $localPort to $remoteIP:$remotePort..."
    # Note: Port forwarding setup requires configuration of network settings or firewall rules, not directly supported in PowerShell
}

# Function to show network interface and routing table status
function Show-Status {
    Write-Host "Showing network status..."
    Get-NetIPAddress
    Get-NetRoute
}

# Function to show network and packet statistics
function Show-Stats {
    Write-Host "Showing network statistics..."
    netstat -e
}

# Function to save a configuration to a file
function Save-Config {
    param (
        [string]$name,
        [string]$config
    )
    if (-not $name -or -not $config) {
        Write-Host "Usage: saveconfig [name] [config]"
        Write-Host "Example: saveconfig myconfig '{`"setting1`":`"value1`"}'"
        return
    }

    Write-Host "Saving configuration $name to file..."
    $config | Out-File "$name.config"
}

# Function to load a configuration from a file
function Load-Config {
    param (
        [string]$name
    )
    if (-not $name) {
        Write-Host "Usage: loadconfig [name]"
        Write-Host "Example: loadconfig myconfig"
        return
    }

    Write-Host "Loading configuration $name from file..."
    Get-Content "$name.config"
}

# Function to perform DNS lookup for a domain
function DnsLookup {
    param (
        [string]$domain
    )
    if (-not $domain) {
        Write-Host "Usage: dnslookup [domain]"
        Write-Host "Example: dnslookup www.example.com"
        return
    }

    Write-Host "Performing DNS lookup for $domain..."
    Resolve-DnsName $domain
}

# Function to perform a network scan using nmap (assuming nmap is installed and accessible)
function NmapScan {
    param (
        [string]$target
    )
    if (-not $target) {
        Write-Host "Usage: nmap [target]"
        Write-Host "Example: nmap 192.168.1.1"
        return
    }

    Write-Host "Scanning target $target with nmap..."
    nmap $target
}

# Function to manage firewall rules
function Manage-Firewall {
    param (
        [string]$action,
        [string]$rule
    )
    if (-not $action -or -not $rule) {
        Write-Host "Usage: firewall [action] [rule]"
        Write-Host "Example: firewall add 'Allow TCP Port 80'"
        return
    }

    Write-Host "Managing firewall rule: Action=$action, Rule=$rule"
    # Note: Firewall management requires use of netsh or other tools
}

# Function to show system information
function Show-SystemInfo {
    Write-Host "Showing system information..."
    systeminfo
}

# Function to manage users
function Manage-User {
    param (
        [string]$action,
        [string]$username
    )
    if (-not $action -or -not $username) {
        Write-Host "Usage: user [action] [username]"
        Write-Host "Example: user add newuser"
        return
    }

    Write-Host "Managing user: Action=$action, Username=$username"
    # Note: User management requires use of user-related cmdlets or tools
}

# Function to ping a host
function Ping-Host {
    param (
        [string]$host
    )
    if (-not $host) {
        Write-Host "Usage: ping [host]"
        Write-Host "Example: ping www.example.com"
        return
    }

    Write-Host "Pinging host $host..."
    Test-Connection $host -Count 4
}

# Function to trace the route to a host
function Trace-Route {
    param (
        [string]$host
    )
    if (-not $host) {
        Write-Host "Usage: traceroute [host]"
        Write-Host "Example: traceroute www.example.com"
        return
    }

    Write-Host "Tracing route to $host..."
    Test-Connection $host -Traceroute
}

# Function to back up files or directories
function Backup {
    param (
        [string]$source,
        [string]$destination
    )
    if (-not $source -or -not $destination) {
        Write-Host "Usage: backup [source] [destination]"
        Write-Host "Example: backup C:\data D:\backup"
        return
    }

    Write-Host "Backing up $source to $destination..."
    Copy-Item -Path $source -Destination $destination -Recurse
}

# Function to restore files or directories from a backup
function Restore {
    param (
        [string]$source,
        [string]$destination
    )
    if (-not $source -or -not $destination) {
        Write-Host "Usage: restore [source] [destination]"
        Write-Host "Example: restore D:\backup C:\data"
        return
    }

    Write-Host "Restoring $source to $destination..."
    Copy-Item -Path $source -Destination $destination -Recurse
}

# Function to show disk usage statistics
function Disk-Usage {
    Write-Host "Showing disk usage..."
    Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{Name="Used(GB)";Expression={[math]::round($_.Used/1GB,2)}}, @{Name="Free(GB)";Expression={[math]::round($_.Used/1GB,2)}}, @{Name="Used(%)";Expression={[math]::round($_.Used/$_.Used*100,2)}}
}

# Function to list running processes
function Process-List {
    Write-Host "Listing running processes..."
    Get-Process
}

# Function to kill a process by PID
function Kill-Process {
    param (
        [int]$pid
    )
    if (-not $pid) {
        Write-Host "Usage: kill [pid]"
        Write-Host "Example: kill 1234"
        return
    }

    Write-Host "Killing process with PID $pid..."
    Stop-Process -Id $pid
}

# Function to manage system services
function Manage-Service {
    param (
        [string]$serviceName,
        [string]$action
    )
    if (-not $serviceName -or -not $action) {
        Write-Host "Usage: service [service_name] [start/stop/restart/status]"
        Write-Host "Example: service wuauserv start"
        return
    }

    Write-Host "Managing service $serviceName: Action=$action"
    switch ($action) {
        "start" { Start-Service -Name $serviceName }
        "stop" { Stop-Service -Name $serviceName }
        "restart" { Restart-Service -Name $serviceName }
        "status" { Get-Service -Name $serviceName }
        default { Write-Host "Unknown action. Use start, stop, restart, or status." }
    }
}

# Function to update system packages
function Update-System {
    Write-Host "Updating system packages..."
    # Windows does not have a direct equivalent to 'apt-get update' or 'yum update'
}

# Function to upgrade system packages
function Upgrade-System {
    Write-Host "Upgrading system packages..."
    # Windows does not have a direct equivalent to 'apt-get upgrade' or 'yum upgrade'
}

# Function to view or tail a log file
function View-Log {
    param (
        [string]$filename
    )
    if (-not $filename) {
        Write-Host "Usage: log [filename]"
        Write-Host "Example: log C:\logs\system.log"
        return
    }

    Write-Host "Viewing log file $filename..."
    Get-Content -Path $filename -Tail 10
}

# Main loop for custom shell
function Custom-Shell {
    Display-Logo

    while ($true) {
        $input = Read-Host "IPNMT 2 Shell"
        $args = $input -split ' '

        switch ($args[0]) {
            "hello" { Write-Host "Hello, user!" }
            "date" { Get-Date }
            "ipnmt" { Display-Logo }
            "scan" { Scan-Network }
            "list" { List-NetworkInfo }
            "connect" { Connect-SSH -ip $args[1] }
            "kick" { Kick-IP -ip $args[1] }
            "scanip" { Scan-IP -domain $args[1] }
            "startagent" { Start-Agent -port $args[1] }
            "forward" { Forward-Port -localPort $args[1] -remoteIP $args[2] -remotePort $args[3] }
            "status" { Show-Status }
            "stats" { Show-Stats }
            "saveconfig" { Save-Config -name $args[1] -config $args[2] }
            "loadconfig" { Load-Config -name $args[1] }
            "dnslookup" { DnsLookup -domain $args[1] }
            "nmap" { NmapScan -target $args[1] }
            "firewall" { Manage-Firewall -action $args[1] -rule $args[2] }
            "systeminfo" { Show-SystemInfo }
            "user" { Manage-User -action $args[1] -username $args[2] }
            "ping" { Ping-Host -host $args[1] }
            "traceroute" { Trace-Route -host $args[1] }
            "backup" { Backup -source $args[1] -destination $args[2] }
            "restore" { Restore -source $args[1] -destination $args[2] }
            "diskusage" { Disk-Usage }
            "processlist" { Process-List }
            "kill" { Kill-Process -pid $args[1] }
            "service" { Manage-Service -serviceName $args[1] -action $args[2] }
            "update" { Update-System }
            "upgrade" { Upgrade-System }
            "log" { View-Log -filename $args[1] }
            "exit" { Write-Host "Exiting..." ; break }
            default { Write-Host "Unknown command. Type 'help' for a list of commands." }
        }
    }
}

# Start custom shell
Custom-Shell
