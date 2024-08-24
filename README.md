



![Screenshot_2024-08-23_at_12 40 16_PM-removebg-preview](https://github.com/user-attachments/assets/66fb0b53-4b22-433d-b618-db734aed75d3)






# IPNMT 2

## info

how well and how this tool runs depents on your OS

i got the idea from here: https://youtu.be/Xv6U2I7Fj_o?t=780

the windows version currently doesnt work to use this on windows download the linux version and run it with git

## Overview

IPNMT 2 is a custom shell script designed for IP Network Management. It provides various network and system management functionalities including network scanning, SSH connections, firewall management, and more.

## Features


- Network management commands such as scanning, listing interfaces, and resolving domains
- System management commands including user management, service control, and system updates
- Backup and restore functionalities
- Disk usage and process management
- Log file viewing and tailing

## Usage



Commands

Here is a list of available commands you can use within the IPNMT 2 shell:

- hello - Greet the user.
- date - Show the current date and time.
- ipnmt - Display information about IPNMT 2.
- scan - Scan for devices in the current network.
- list - List network interfaces with IP addresses and MAC addresses.
- connect [ip] - SSH connect to the specified IP address.
- kick [ip] - Kick the specified IP address out of the network.
- scanip [domain] - Resolve a domain to its IP addresses.
- startagent [port] - Start an SSH server on the specified port.
- forward [local_port] [remote_ip] [remote_port] - Forward a local port to a remote IP and port.
- status - Show the status of network interfaces and routing table.
- stats - Show network statistics and packet statistics.
- saveconfig [name] [config] - Save a configuration to a file.
- loadconfig [name] - Load a configuration from a file.
- dnslookup [domain] - Perform a DNS lookup for a domain.
- nmap [target] - Scan a target using nmap.
- firewall [action] [rule] - Manage firewall rules (add/remove/list).
- systeminfo - Show system information.
- user [action] [username] - Manage users (add/remove/check).
- ping [host] - Ping a host to check connectivity.
- traceroute [host] - Trace the route to a host.
- backup [source] [destination] - Backup files or directories.
- restore [source] [destination] - Restore files or directories from a backup.
- diskusage - Show disk usage statistics.
- processlist - List running processes.
- kill [pid] - Kill a process by its PID.
- service [service_name] [start/stop/restart/status] - Manage system services.
- update - Update system packages.
- upgrade - Upgrade system packages.
- log [filename] - View or tail a log file.
- encrypt [filename] - Encrypt a file.
- listener start [port] - Start a network listener on the specified port.
- help - Show this help message.
- exit - Exit the custom shell.


Commands must be entered exactly as specified. Incorrect usage or missing arguments may result in errors or unintended behavior.
Some commands require sudo privileges.
License

