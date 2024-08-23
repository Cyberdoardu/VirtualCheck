# Virtual Machine & Container Detection

**This Python code can detect if it's running inside a virtual machine or container.**

## Checks Performed:
1. **MAC Address Verification**: Checks for MAC addresses commonly used by virtual machines.
2. **CPU Core Count**: Verifies if the number of CPU cores is below the typical threshold for physical machines.
3. **CPU Clock Speed**: Detects unusually low CPU clock speeds that might indicate virtualization.
4. **ARP Table Inspection**: Checks if the ARP table is empty, which is common in virtualized environments.
5. **Docker Environment**: Checks for the presence of the `.dockerenv` file to detect Docker containers.
6. **Sudo Availability**: Verifies if the `sudo` command is present, as it may be missing in some containers.
7. **User Logins**: Inspects the number of logged-in users, as containers often lack multiple users.
8. **Hypervisor Detection**: Reads `/proc/cpuinfo` to check for a hypervisor flag, indicating virtualization.
9. **Systemd Detect Virt**: Uses the `systemd-detect-virt` command to identify virtualization platforms.
10. **NTP Synchronization**: Compares timestamps to detect potential debug modes or unsynchronized environments, common in VMs.
11. **Memory Information**: Checks if the total memory available is unusually low, which may suggest a VM or container.

## Features:
- Supports **verbose mode** (`-v` flag) to show detailed test progress
- Uses **NTP synchronization** to detect potential debug modes in VMs

## Output:
The results are compiled into a detailed **report** listing all detected indicators, including the type of **virtualization platform**, if applicable.
