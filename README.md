# IPNMT 2 Shell Script

## Overview

IPNMT 2 is a custom shell script designed for IP Network Management. It provides various network and system management functionalities including network scanning, SSH connections, firewall management, and more.

## Features

- Display logo and information about IPNMT 2
- Network management commands such as scanning, listing interfaces, and resolving domains
- System management commands including user management, service control, and system updates
- Backup and restore functionalities
- Disk usage and process management
- Log file viewing and tailing

## Usage
Commands

Here is a list of available commands you can use within the IPNMT 2 shell:

General Commands
´ hello - Greet the user.´ 
´ date - Show the current date and time.´ 
´ ipnmt - Display information about IPNMT 2.´ 
´ help - Show help information.´ 
´ exit - Exit the custom shell.´ 
´ Network Commands´ 
´ scan - Scan for devices in the current network.´ 
´ list - List network interfaces with IP addresses and MAC addresses.´ 
´ connect [ip] - SSH connect to the specified IP address.´ 
´ kick [ip] - Kick the specified IP address out of the network.´ 
´ scanip [domain] - Resolve a domain to its IP addresses.´ 
´ startagent [port] - Start an SSH server on the specified port.´ 
´ forward [local_port] [remote_ip] [remote_port] - Forward a local port to a remote IP and port.
´ status - Show the status of network interfaces and routing table.
´ stats - Show network statistics and packet statistics.
´ dnslookup [domain] - Perform a DNS lookup for a domain.
´ nmap [target] - Scan a target using nmap.
´ System Commands
´ systeminfo - Show system information.
´ user [action] [username] - Manage users (add/remove/check).
´ ping [host] - Ping a host to check connectivity.
´ traceroute [host] - Trace the route to a host.
´ backup [source] [destination] - Backup files or directories.
´ restore [source] [destination] - Restore files or directories from a backup.
´ diskusage - Show disk usage statistics.
´ processlist - List running processes.
´ kill [pid] - Kill a process by its PID.
´ service [service_name] [start/stop/restart/status] - Manage system services.
´ update - Update system packages.
upgrade - Upgrade system packages.
log [filename] - View or tail a log file.
Configuration Commands
saveconfig [name] [config] - Save a configuration to a file.
loadconfig [name] - Load a configuration from a file.
Firewall Commands
firewall [action] [rule] - Manage firewall rules (add/remove/list).
Example Usage

Scan network for devices:
bash
Copy code
scan
List network interfaces with IP and MAC addresses:
bash
Copy code
list
Connect to an IP address via SSH:
bash
Copy code
connect 192.168.1.100
Resolve a domain to its IP addresses:
bash
Copy code
scanip example.com
Start an SSH server on port 2222:
bash
Copy code
startagent 2222
Forward local port 8080 to remote IP 192.168.1.100 on port 80:
bash
Copy code
forward 8080 192.168.1.100 80
Show system information:
bash
Copy code
systeminfo
Backup a directory:
bash
Copy code
backup /path/to/source /path/to/destination
Notes

Commands must be entered exactly as specified. Incorrect usage or missing arguments may result in errors or unintended behavior.
Some commands require sudo privileges.
License

This script is provided as-is. Use it at your own risk. For any modifications or contributions, please adhere to best practices and ensure compatibility with your system.
