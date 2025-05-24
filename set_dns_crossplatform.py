import platform
import os
import re
import subprocess
import ctypes # For Windows privilege check
import sys # For sys.exit()
import json # For saving/loading original DNS settings
import time
import socket
import urllib.request
# import argparse # Removed for terminal menu focus

# --- ANSI Color Codes ---
# These might not work on all terminals (e.g., older Windows consoles)
RESET = "\x1b[0m"
RED = "\x1b[91m"
GREEN = "\x1b[92m"
YELLOW = "\x1b[93m"
BLUE = "\x1b[94m"
CYAN = "\x1b[96m"
WHITE = "\x1b[97m"

# --- Constants ---
# ORIGINAL_DNS_CONFIG_FILE = "original_dns_config.json" # Will be a class attribute

# --- Helper Functions (can remain outside or become static methods) ---

def is_command_available(command):
    """
    Checks if a command is available in the system's PATH.
    Tries common flags like --version or --help to verify executability.

    Args:
        command (str): The command to check.

    Returns:
        bool: True if the command seems available, False otherwise.
    """
    try:
        # Try with --version first
        subprocess.run([command, "--version"], capture_output=True, text=True, timeout=2)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        try: # Some commands don't have --version, try help
            subprocess.run([command, "--help"], capture_output=True, text=True, timeout=2)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            # For commands like `which`, we can just check existence
            if command == "which": # `which` itself doesn't have --version or --help in a standard way
                 try:
                    subprocess.run(["which", "ls"], capture_output=True, text=True, check=True, timeout=2)
                    return True
                 except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                    return False
            return False

def get_default_linux_interface():
    """
    Tries to get the default network interface on Linux by checking the route to a public IP.

    Returns:
        str or None: The name of the default interface, or None if not found or an error occurs.
    """
    try:
        # Get the interface associated with the default route to a public IP (e.g., 1.1.1.1)
        # Use 'ip -4 route' to specifically target IPv4
        result = subprocess.run(["ip", "-4", "route", "get", "1.1.1.1"], capture_output=True, text=True, check=True)
        # Expected output might look like: "1.1.1.1 dev eth0 src 192.168.1.100 uid 1000 \n    cache "
        match = re.search(r"dev\s+([^\s]+)", result.stdout)
        if match:
            return match.group(1)
    except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
        # print(f"Could not determine default interface: {e}") # Keep silent during normal operation
        pass # Silently fail, caller will handle None
    return None

def is_service_active(service_name):
    """
    Checks if a systemd service is active using 'systemctl is-active'.

    Args:
        service_name (str): The name of the systemd service.

    Returns:
        bool: True if the service is active, False otherwise or if systemctl is not available.
    """
    if not is_command_available("systemctl"):
        return False # Cannot check systemd service status if systemctl is not present
    try:
        result = subprocess.run(["systemctl", "is-active", service_name], capture_output=True, text=True)
        return result.returncode == 0 and result.stdout.strip() == "active"
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    except Exception as e:
        # print(f"Error checking service {service_name} status: {e}") # Keep silent
        return False


class DnsManager:
    ORIGINAL_DNS_CONFIG_FILE = "original_dns_config.json"
    DNS_CONFIG_FILE = "dnsConf.txt"
    TEST_URLS_FILE = os.path.join("test_data", "test_urls.txt")

    def __init__(self):
        self.current_os = self._get_os()
        print(f"{BLUE}Detected OS: {self.current_os}{RESET}")

    def load_test_urls(self, filepath=None):
        """
        Loads a list of URLs from a file (one URL per line).
        Returns a list of URLs.
        """
        if filepath is None:
            filepath = self.TEST_URLS_FILE
        urls = []
        if not os.path.exists(filepath):
            print(f"{RED}Test URLs file not found: {filepath}{RESET}")
            return urls
        try:
            with open(filepath, "r") as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith("#"):
                        urls.append(url)
        except Exception as e:
            print(f"{RED}Error reading test URLs file: {e}{RESET}")
        return urls

    def benchmark_dns_providers(self, dns_entries=None, test_urls=None, per_url_timeout=3):
        """
        Test each DNS provider by setting it, then timing access to each test URL.
        Reports timing results for each provider.
        """
        if dns_entries is None:
            dns_entries = self.parse_dns_config()
        if not dns_entries:
            print(f"{RED}No DNS entries to test.{RESET}")
            return

        if test_urls is None:
            test_urls = self.load_test_urls()
        if not test_urls:
            print(f"{RED}No test URLs found to benchmark DNS.{RESET}")
            return

        results = []
        print(f"{CYAN}Starting DNS benchmark for {len(dns_entries)} providers on {len(test_urls)} URLs...{RESET}")

        for entry in dns_entries:
            name = entry['name']
            ips = entry['ips']
            print(f"{BLUE}\nTesting DNS: {name} ({', '.join(ips)}){RESET}")

            # Set DNS for this provider
            set_success = False
            if self.current_os == "windows":
                set_success = self._set_dns_windows(ips)
            elif self.current_os == "linux":
                set_success = self._set_dns_linux(ips)
            elif self.current_os == "macos":
                set_success = self._set_dns_macos(ips)
            else:
                print(f"{RED}Unsupported OS for DNS setting.{RESET}")
                continue

            if not set_success:
                print(f"{RED}Failed to set DNS for {name}. Skipping benchmark for this provider.{RESET}")
                results.append({'name': name, 'ips': ips, 'error': 'Failed to set DNS'})
                continue

            self.flush_dns()
            time.sleep(1)  # Give the system a moment to apply DNS

            provider_result = {'name': name, 'ips': ips, 'timings': [], 'errors': []}
            for url in test_urls:
                start = time.time()
                try:
                    # Only fetch headers to minimize data transfer
                    req = urllib.request.Request(url, method="HEAD")
                    with urllib.request.urlopen(req, timeout=per_url_timeout) as resp:
                        status = resp.status
                    elapsed = time.time() - start
                    provider_result['timings'].append((url, elapsed, status))
                    print(f"{GREEN}  {url} - {elapsed:.2f}s (status {status}){RESET}")
                except Exception as e:
                    elapsed = time.time() - start
                    provider_result['timings'].append((url, None, None))
                    provider_result['errors'].append((url, str(e)))
                    print(f"{YELLOW}  {url} - ERROR: {e}{RESET}")

            results.append(provider_result)

        print(f"\n{CYAN}DNS Benchmark Results:{RESET}")
        for res in results:
            print(f"{WHITE}\nProvider: {res['name']} ({', '.join(res['ips'])}){RESET}")
            for url, elapsed, status in res['timings']:
                if elapsed is not None:
                    print(f"  {url:40} {elapsed:.2f}s (status {status})")
                else:
                    print(f"  {url:40} ERROR")
            if res.get('errors'):
                print(f"{YELLOW}  Errors:{RESET}")
                for url, err in res['errors']:
                    print(f"    {url}: {err}")

        print(f"\n{CYAN}Benchmark complete.{RESET}")

    def _get_os(self, test_platform_system=None):
        """
        Detects the current operating system.
        An optional 'test_platform_system' argument can be provided for testing purposes.

        Args:
            test_platform_system (str, optional): A string to override platform.system().
                                                Defaults to None.

        Returns:
            str: "windows", "linux", "macos", or "unknown".
        """
        system_to_check = test_platform_system if test_platform_system is not None else platform.system()
        system_lower = system_to_check.lower()

        if "windows" in system_lower:
            return "windows"
        elif "linux" in system_lower:
            return "linux"
        elif "darwin" in system_lower: # darwin is the system name for macOS
            return "macos"
        else:
            return "unknown"

    def _is_valid_ip(self, ip):
        """
        Validates an IPv4 address.

        Args:
            ip (str): The IP address string to validate.

        Returns:
            bool: True if valid IPv4, False otherwise.
        """
        # Regex for IPv4 address
        pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if pattern.match(ip):
            parts = ip.split(".")
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        return False

    def parse_dns_config(self, filepath=None):
        """
        Parses a DNS configuration file (e.g., "dnsConf.txt").
        Expected format in the file is: Name,IP1,IP2 (e.g., Google Public DNS,8.8.8.8,8.8.4.4)
        Lines starting with '#' or empty lines are ignored.

        Args:
            filepath (str, optional): The path to the DNS configuration file.
                                      Defaults to the class's DNS_CONFIG_FILE.

        Returns:
            list[dict] or None: A list of dicts with 'name' and 'ips' keys, e.g.
                                [{'name': ..., 'ips': [ip1, ip2]}, ...]
                                Returns None if the file is not found, empty, or no valid
                                IP addresses are found, or if an error occurs.
        """
        if filepath is None:
            filepath = self.DNS_CONFIG_FILE

        dns_servers = []
        if not os.path.exists(filepath):
            print(f"{RED}Error: Configuration file '{filepath}' not found.{RESET}")
            print(f"{WHITE}Please create a {self.DNS_CONFIG_FILE} file in the script directory.{RESET}")
            return None

        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()

            if not lines:
                print(f"{RED}Error: Configuration file '{filepath}' is empty.{RESET}")
                return None

            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):  # Skip empty lines and comments
                    continue

                # Expect CSV: Name,IP1,IP2
                parts = [p.strip() for p in line.split(',')]
                if len(parts) < 2:
                    print(f"{YELLOW}Warning: Malformed line in config (expected at least name and one IP): {line}{RESET}")
                    continue

                name = parts[0]
                ips = []
                for ip in parts[1:]:
                    if self._is_valid_ip(ip):
                        ips.append(ip)
                    else:
                        print(f"{YELLOW}Warning: Invalid IP address format found: {ip}{RESET}")

                if ips:
                    dns_servers.append({'name': name, 'ips': ips})
                else:
                    print(f"{YELLOW}Warning: No valid IPs found for DNS entry: {name}{RESET}")

            if not dns_servers:
                print(f"{RED}No valid DNS server entries found in the configuration file.{RESET}")
                return None

            return dns_servers
        except Exception as e:
            print(f"{RED}Error reading or parsing configuration file '{filepath}': {e}{RESET}")
            return None

    # --- OS-Specific DNS Setting Methods ---

    def _set_dns_windows(self, dns_servers):
        """
        Sets DNS servers for Windows.
        It finds active network interfaces and applies the DNS settings to them.

        Args:
            dns_servers (list[str]): A list of DNS server IP addresses.

        Returns:
            bool: True if DNS was successfully set for at least one interface, False otherwise.
        """
        print(f"{BLUE}Attempting to set DNS for Windows with servers: {dns_servers}{RESET}")
        if not dns_servers:
            print(f"{RED}No DNS servers provided.{RESET}")
            return False # Indicate failure: no servers

        overall_success = False # Track if at least one interface was configured

        try:
            # Get interface details using netsh
            result = subprocess.run(["netsh", "interface", "show", "interface"], capture_output=True, text=True, check=True, shell=True)
            interfaces_output = result.stdout

            active_interfaces = []
            lines = interfaces_output.strip().split('\n')
            if len(lines) > 2: # Header, separator, then data
                for line in lines[2:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == "Enabled" and parts[1] == "Connected":
                        interface_name = " ".join(parts[3:])
                        if interface_name:
                             active_interfaces.append(interface_name)

            if not active_interfaces:
                print(f"{YELLOW}No active (Enabled and Connected) network interfaces found.{RESET}")
                return False # Indicate failure: no interfaces

            print(f"{BLUE}Found active interfaces: {active_interfaces}{RESET}")

            for interface_name in active_interfaces:
                print(f"{BLUE}\nConfiguring interface: '{interface_name}'{RESET}")

                # Set primary DNS server
                cmd_set = ["netsh", "interface", "ipv4", "set", "dnsserver", f"name=\"{interface_name}\"", "static", f"addr=\"{dns_servers[0]}\"", "validate=no"]
                # print(f"Executing: {' '.join(cmd_set)}") # Keep command print for debug if needed
                try:
                    set_result = subprocess.run(cmd_set, capture_output=True, text=True, check=True, shell=True)
                    print(f"{GREEN}Successfully set primary DNS for '{interface_name}': {dns_servers[0]}{RESET}")
                    # if set_result.stdout: print(f"Output: {set_result.stdout.strip()}")
                    # if set_result.stderr: print(f"Stderr: {set_result.stderr.strip()}")

                    # Add secondary and tertiary DNS servers if provided
                    for i, dns_server_ip in enumerate(dns_servers[1:], start=1): # start=1 for index (2nd DNS is index 2)
                        cmd_add = ["netsh", "interface", "ipv4", "add", "dnsserver", f"name=\"{interface_name}\"", f"addr=\"{dns_server_ip}\"", f"index={i+1}", "validate=no"]
                        # print(f"Executing: {' '.join(cmd_add)}") # Keep command print
                        try:
                            add_result = subprocess.run(cmd_add, capture_output=True, text=True, check=True, shell=True)
                            print(f"{GREEN}Successfully added DNS server {dns_server_ip} (index {i+1}) for '{interface_name}'{RESET}")
                            # if add_result.stdout: print(f"Output: {add_result.stdout.strip()}")
                            # if add_result.stderr: print(f"Stderr: {add_add.stderr.strip()}\") # This is often empty on success

                        except subprocess.CalledProcessError as e:
                            print(f"{RED}Error adding DNS server {dns_server_ip} for '{interface_name}': {e}{RESET}")
                            print(f"{WHITE}Stderr: {e.stderr.strip() if hasattr(e, 'stderr') and e.stderr else 'N/A'}{RESET}")
                        except FileNotFoundError:
                            print(f"{RED}Error: 'netsh' command not found. Ensure it's in your system PATH.{RESET}")
                            return False # Stop further processing if netsh is missing
                        except Exception as e:
                            print(f"{RED}An unexpected error occurred while adding DNS for '{interface_name}': {e}{RESET}")
                    overall_success = True # At least one primary DNS set successfully

                except subprocess.CalledProcessError as e:
                    print(f"{RED}Error setting primary DNS for '{interface_name}': {e}{RESET}")
                    # print(f"Command: {' '.join(e.cmd)}") # Keep command print for debug if needed
                    print(f"{WHITE}Stderr: {e.stderr.strip() if hasattr(e, 'stderr') and e.stderr else 'N/A'}{RESET}")
                    print(f"{WHITE}Please ensure the script is run with administrator privileges and the interface name is correct.{RESET}")
                except FileNotFoundError:
                    print(f"{RED}Error: 'netsh' command not found. Ensure it's in your system PATH.{RESET}")
                    return False # Stop further processing if netsh is missing
                except Exception as e:
                    print(f"{RED}An unexpected error occurred while setting primary DNS for '{interface_name}': {e}{RESET}")

            return overall_success
        except subprocess.CalledProcessError as e:
            print(f"{RED}Error getting network interfaces: {e}{RESET}")
            print(f"{WHITE}Stderr: {e.stderr.strip() if hasattr(e, 'stderr') and e.stderr else 'N/A'}{RESET}")
            return False
        except FileNotFoundError:
            print(f"{RED}Error: 'netsh' command not found. Ensure it's in your system PATH.{RESET}")
            return False
        except Exception as e:
            print(f"{RED}An unexpected error occurred while getting interfaces: {e}{RESET}")
            return False

    def _flush_dns_windows(self):
        """
        Flushes the DNS cache on Windows using 'ipconfig /flushdns'.

        Returns:
            bool: True if successful, False otherwise.
        """
        print(f"{BLUE}Attempting to flush DNS cache for Windows...{RESET}")
        try:
            result = subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, check=True)
            print(f"{GREEN}Successfully flushed DNS cache.{RESET}")
            # if result.stdout: print(f"Output: {result.stdout.strip()}\")
            # if result.stderr: print(f"Stderr: {result.stderr.strip()}") # Should be empty on success typically
            return True
        except subprocess.CalledProcessError as e:
            print(f"{RED}Error flushing DNS cache: {e}{RESET}")
            print(f"{WHITE}Stderr: {e.stderr.strip() if hasattr(e, 'stderr') and e.stderr else 'N/A'}{RESET}")
            print(f"{WHITE}Please ensure the script is run with administrator privileges.{RESET}")
            return False
        except FileNotFoundError:
            print(f"{RED}Error: 'ipconfig' command not found. Ensure it's in your system PATH.{RESET}")
            return False
        except Exception as e:
            print(f"{RED}An unexpected error occurred during DNS flush: {e}{RESET}")
            return False

    def _set_dns_linux(self, dns_servers):
        """
        Sets DNS servers for Linux.
        Tries methods in order: nmcli, resolvectl, then direct /etc/resolv.conf modification.

        Args:
            dns_servers (list[str]): A list of DNS server IP addresses.

        Returns:
            bool: True if DNS was successfully set by any method, False otherwise.
        """
        print(f"{BLUE}Attempting to set DNS for Linux with servers: {dns_servers}{RESET}")
        if not dns_servers:
            print(f"{RED}No DNS servers provided.{RESET}")
            return False

        dns_servers_comma_str = ",".join(dns_servers) # For nmcli command argument

        # Method 1: NetworkManager (nmcli) - Preferred if available
        if is_command_available("nmcli"):
            print(f"{BLUE}\nAttempting to set DNS using nmcli...{RESET}")
            try:
                # Get active connections and their devices
                result = subprocess.run(["nmcli", "-t", "-f", "DEVICE,NAME", "connection", "show", "--active"], capture_output=True, text=True, check=True)
                active_connections = {} # Map device -> connection name
                for line in result.stdout.strip().split('\n'):
                     parts = line.split(':')
                     if len(parts) >= 2 and parts[0] and parts[1]: # Ensure device and connection name are present
                          device = parts[0]
                          connection_name = parts[1]
                          active_connections[device] = connection_name

                if not active_connections:
                    print(f"{YELLOW}nmcli: No active connections found.{RESET}")
                else:
                    success = False
                    for device, connection in active_connections.items():
                        print(f"{BLUE}nmcli: Configuring connection \'{connection}\' on device \'{device}\'{RESET}")

                        # Modify the connection profile
                        cmd_modify_conn = ["sudo", "nmcli", "connection", "modify", connection, "ipv4.dns", dns_servers_comma_str]
                        # print(f"nmcli: Executing: {' '.join(cmd_modify_conn)}") # Add print for debugging
                        modify_conn_result = subprocess.run(cmd_modify_conn, capture_output=True, text=True)

                        if modify_conn_result.returncode == 0:
                            print(f"{GREEN}nmcli: Successfully modified connection \'{connection}\'.{RESET}")
                            # Reapply the connection to make changes effective - IMPORTANT!
                            cmd_up_conn = ["sudo", "nmcli", "connection", "up", connection]
                            # print(f"nmcli: Executing: {' '.join(cmd_up_conn)}") # Add print for debugging
                            up_conn_result = subprocess.run(cmd_up_conn, capture_output=True, text=True)

                            if up_conn_result.returncode == 0:
                                print(f"{GREEN}nmcli: Successfully reapplied connection \'{connection}\'.{RESET}")
                                success = True # Mark success if at least one connection is updated
                            else:
                                print(f"{RED}nmcli: Error reapplying connection \'{connection}\': {up_conn_result.stderr.strip()}{RESET}")
                                # print(f"{WHITE}nmcli: stdout: {up_conn_result.stdout.strip()}{RESET}") # Add stdout for debugging

                        else:
                             print(f"{RED}nmcli: Error modifying connection \'{connection}\': {modify_conn_result.stderr.strip()}{RESET}")
                             # print(f"{WHITE}nmcli: stdout: {modify_conn_result.stdout.strip()}{RESET}") # Add stdout for debugging

                    if success:
                        return True # Return True if at least one connection was successfully modified and brought up.

            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print(f"{RED}nmcli: Error during execution: {e}{RESET}")
            except Exception as e:
                print(f"{RED}nmcli: An unexpected error occurred: {e}{RESET}")

        # Method 2: systemd-resolve (resolvectl) - Second preference
        if is_command_available("resolvectl"):
            print(f"{BLUE}\nAttempting to set DNS using resolvectl...{RESET}")
            interface = get_default_linux_interface() # Determine the primary interface
            if interface:
                cmd = ["sudo", "resolvectl", "dns", interface] + dns_servers
                # print(f"resolvectl: Executing: {' '.join(cmd)}")
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode == 0:
                        print(f"{GREEN}resolvectl: Successfully set DNS for interface \'{interface}\'.{RESET}")
                        return True
                    else:
                        print(f"{RED}resolvectl: Error setting DNS: {result.stderr.strip() or result.stdout.strip()}{RESET}")
                except (subprocess.CalledProcessError, FileNotFoundError) as e:
                    print(f"{RED}resolvectl: Error during execution: {e}{RESET}")
                except Exception as e:
                    print(f"{RED}resolvectl: An unexpected error occurred: {e}{RESET}")
                else:
                    print(f"{YELLOW}resolvectl: Could not determine default network interface.{RESET}")

        # Method 3: Direct /etc/resolv.conf modification (Fallback, last resort)
        print(f"{YELLOW}\nAttempting to modify /etc/resolv.conf directly (use with caution)...{RESET}")
        resolv_conf_path = "/etc/resolv.conf"

        # Perform safety checks before modifying /etc/resolv.conf
        if os.path.islink(resolv_conf_path):
            link_target = os.readlink(resolv_conf_path)
            known_dynamic_targets = [
                "systemd/resolve/stub-resolv.conf",
                "systemd/resolve/resolv.conf",
                "NetworkManager/resolv.conf",
                "run/resolvconf/resolv.conf"
            ]
            if any(target in link_target for target in known_dynamic_targets):
                print(f"{YELLOW}Warning: {resolv_conf_path} is a symlink to \'{link_target}\'. Direct modification is unsafe and will likely be overwritten.{RESET}")
                print(f"{WHITE}Please configure DNS using the appropriate tool (nmcli, resolvectl, or network configuration files).{RESET}")
                return False # Indicate failure due to unsafe operation

        # Check for generator comments (even if not a symlink)
        try:
            if os.path.exists(resolv_conf_path):
                with open(resolv_conf_path, 'r') as f:
                    current_content = f.read(1024) # Read first 1KB for comments
                    generator_comments = [
                        "# Generated by NetworkManager",
                        "# Generated by resolvconf",
                        "# Generated by systemd-resolved",
                        "# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)",
                        "#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN"
                    ]
                    if any(comment in current_content for comment in generator_comments):
                        print(f"{YELLOW}Warning: {resolv_conf_path} appears to be managed by another service "
                              "(e.g., NetworkManager, resolvconf, systemd-resolved)."
                              f"Direct modification is unsafe and will likely be overwritten.{RESET}")
                        print(f"{WHITE}Please configure DNS using the appropriate tool (nmcli, resolvectl, or network configuration files).{RESET}")
                        return False # Indicate failure due to unsafe operation
            else:
                 print(f"{YELLOW}Warning: {resolv_conf_path} does not exist. Creating it might be safe if no other service manages DNS.{RESET}")
                 # Proceed with writing if it doesn't exist and no other method worked.

        except Exception as e:
            print(f"{RED}Error reading {resolv_conf_path} for checks: {e}{RESET}")
            # If we can't read it for checks but it exists, it's risky to proceed.
            print(f"{YELLOW}Due to error reading resolv.conf for safety checks, skipping direct modification.{RESET}")
            return False # Indicate failure due to read error

        # If safety checks pass or file doesn't exist, proceed with backup and write
        try:
            backup_path = "/etc/resolv.conf.bak_set_dns_py" # More specific backup name
            # Only backup if the file exists
            if os.path.exists(resolv_conf_path):
                print(f"{BLUE}Backing up current {resolv_conf_path} to {backup_path}...{RESET}")
                # Ensure privileges for cp
                subprocess.run(["sudo", "cp", "-f", resolv_conf_path, backup_path], check=True)

            print(f"{BLUE}Writing new DNS configuration to {resolv_conf_path}...{RESET}")
            # Prepare content
            new_resolv_content = "# DNS configuration managed by set_dns_crossplatform.py (manual override)\n"
            for server in dns_servers:
                new_resolv_content += f"nameserver {server}\n"
            # Optionally add search domains if needed: new_resolv_content += "search yourdomain.com\n"

            # Write using sudo with a temporary file to handle permissions
            temp_resolv_path = "/tmp/resolv.conf.new"
            with open(temp_resolv_path, 'w') as tmp_f:
                tmp_f.write(new_resolv_content)

            subprocess.run(["sudo", "mv", "-f", temp_resolv_path, resolv_conf_path], check=True)
            print(f"{GREEN}Successfully wrote new DNS servers to {resolv_conf_path}.{RESET}")
            print(f"{YELLOW}Warning: This direct modification might be temporary and overwritten by system services if not configured properly elsewhere.{RESET}")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
            print(f"{RED}Error modifying {resolv_conf_path}: {e}{RESET}")
            print(f"{WHITE}Make sure you are running the script with sudo privileges for cp/mv operations.{RESET}")
            return False # Indicate failure

        # If none of the methods succeeded
        print(f"{RED}\nFailed to set DNS using any available method on Linux.{RESET}")
        return False

    def _flush_dns_linux(self):
        """
        Flushes DNS cache on Linux.
        Tries methods in order: resolvectl, nscd restart, dnsmasq restart.

        Returns:
            bool: True if any known cache flushing method succeeded, False otherwise.
        """
        print(f"{BLUE}\nAttempting to flush DNS cache for Linux...{RESET}")
        flushed_successfully = False

        # Method 1: systemd-resolve (resolvectl)
        if is_command_available("resolvectl"):
            print(f"{BLUE}Attempting to flush DNS cache using resolvectl...{RESET}")
            try:
                result = subprocess.run(["sudo", "resolvectl", "flush-caches"], capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"{GREEN}resolvectl: Successfully flushed DNS caches.{RESET}")
                    flushed_successfully = True
                else:
                    print(f"{RED}resolvectl: Error flushing caches: {result.stderr.strip() or result.stdout.strip()}{RESET}")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print(f"{RED}resolvectl: Error during execution: {e}{RESET}")
            except Exception as e:
                print(f"{RED}resolvectl: An unexpected error occurred: {e}{RESET}")

        if flushed_successfully:
            return True # If resolvectl worked, we're done.

        # Method 2: nscd (Name Service Cache Daemon) - If resolvectl didn't work or wasn't available
        # Check if nscd executable exists AND systemctl is available or init.d script exists
        if is_command_available("nscd") and (is_command_available("systemctl") or os.path.exists("/etc/init.d/nscd")):
            print("\nAttempting to flush DNS using nscd...")
            restarted_nscd = False
            if is_command_available("systemctl"):
                try:
                    # Check if service is active or even exists before trying to restart
                    if is_service_active("nscd") or is_service_active("nscd.service"):
                        result = subprocess.run(["sudo", "systemctl", "restart", "nscd"], capture_output=True, text=True)
                        if result.returncode == 0:
                            print("nscd: Successfully restarted via systemctl.")
                            restarted_nscd = True
                        else:
                            print(f"nscd: Error restarting via systemctl: {result.stderr.strip()}")
                    # else: print("nscd: Service not active or found via systemctl, not attempting restart.") # Keep silent

                except Exception as e:
                    print(f"{RED}nscd: Error with systemctl restart: {e}{RESET}")

            if not restarted_nscd and os.path.exists("/etc/init.d/nscd"): # Fallback to init.d script
                print("nscd: Trying init.d script...")
                try:
                    result = subprocess.run(["sudo", "/etc/init.d/nscd", "restart"], capture_output=True, text=True)
                    if result.returncode == 0:
                        print("nscd: Successfully restarted via init.d script.")
                        restarted_nscd = True
                    else:
                        print(f"nscd: Error restarting via init.d: {result.stderr.strip() or result.stdout.strip()}")
                except Exception as e:
                    print(f"nscd: Error with init.d restart: {e}")

            if restarted_nscd:
                flushed_successfully = True # If nscd restarted, count as success for flushing.


        if flushed_successfully:
            return True # If nscd worked, we're done.

        # Method 3: dnsmasq - If other methods didn't work or weren't available
        if is_command_available("dnsmasq") and (is_command_available("systemctl") or os.path.exists("/etc/init.d/dnsmasq")):
            print("\nAttempting to flush DNS using dnsmasq...")
            restarted_dnsmasq = False
            if is_command_available("systemctl"):
                try:
                    dnsmasq_service_names = ["dnsmasq", "dnsmasq.service"]
                    active_dnsmasq_service = None
                    for name in dnsmasq_service_names:
                        if is_service_active(name):
                            active_dnsmasq_service = name
                            break

                    if active_dnsmasq_service:
                        result = subprocess.run(["sudo", "systemctl", "restart", active_dnsmasq_service], capture_output=True, text=True)
                        if result.returncode == 0:
                            print(f"dnsmasq: Successfully restarted '{active_dnsmasq_service}' via systemctl.")
                            restarted_dnsmasq = True
                        else:
                            print(f"dnsmasq: Error restarting '{active_dnsmasq_service}' via systemctl: {result.stderr.strip()}")
                    # else: print("dnsmasq: Service not active or found via systemctl, not attempting restart.") # Keep silent
                except Exception as e:
                    print(f"{RED}dnsmasq: Error with systemctl restart: {e}{RESET}")

            if not restarted_dnsmasq and os.path.exists("/etc/init.d/dnsmasq"): # Fallback to init.d
                print(f"{BLUE}dnsmasq: Trying init.d script...{RESET}")
                try:
                    result = subprocess.run(["sudo", "/etc/init.d/dnsmasq", "restart"], capture_output=True, text=True)
                    if result.returncode == 0:
                        print(f"{GREEN}dnsmasq: Successfully restarted via init.d script.{RESET}")
                        restarted_dnsmasq = True
                    else:
                        print(f"{RED}dnsmasq: Error restarting via init.d: {result.stderr.strip() or result.stdout.strip()}{RESET}")
                except Exception as e:
                    print(f"{RED}dnsmasq: Error with init.d restart: {e}{RESET}")

            if restarted_dnsmasq:
                flushed_successfully = True # If dnsmasq restarted, count as success for flushing.


        if flushed_successfully:
            return True
        else:
            print(f"{YELLOW}\nNo readily available DNS cache flushing method succeeded on Linux for this configuration.{RESET}")
            print(f"{WHITE}Manual intervention might be required depending on your specific setup (e.g., restarting network service).{RESET}")
            return False


    def _set_dns_macos(self, dns_servers):
        """
        Sets DNS servers for macOS using 'networksetup'.
        It finds all network services and applies DNS settings to each.

        Args:
            dns_servers (list[str]): A list of DNS server IP addresses.

        Returns:
            bool: True if DNS was successfully set for at least one service, False otherwise.
        """
        print(f"{BLUE}Attempting to set DNS for macOS with servers: {dns_servers}{RESET}")
        if not dns_servers:
            print(f"{RED}No DNS servers provided.{RESET}")
            # Special case: If no servers are provided, we might interpret this as
            # setting to "empty" which often reverts to DHCP.
            dns_servers_str = "empty"
            print("No specific DNS servers provided, will attempt to set to automatic/DHCP using 'empty'.")
        else:
             dns_servers_str = " ".join(dns_servers)


        try:
            # List all network services using networksetup
            list_services_cmd = ["networksetup", "-listallnetworkservices"]
            # print(f"Executing: {' '.join(list_services_cmd)}") # Keep command print
            result = subprocess.run(list_services_cmd, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"{RED}Error listing network services: {result.stderr.strip() or result.stdout.strip()}{RESET}")
                print(f"{WHITE}Ensure 'networksetup' is available and you have necessary permissions (should run with sudo).{RESET}")
                return False

            services = result.stdout.strip().split('\n')
            # Filter out the header line and empty lines
            services = [s for s in services if not s.startswith("An asterisk") and s.strip()]

            if not services:
                print(f"{YELLOW}No network services found to configure.{RESET}")
                return False

            print(f"{BLUE}Found network services: {services}{RESET}")
            success_on_any_service = False


            for service in services:
                if not service.strip(): # Skip empty lines just in case
                    continue

                print(f"\nConfiguring DNS for service: '{service}'")

                set_dns_cmd = ["sudo", "networksetup", "-setdnsservers", service, dns_servers_str]
                # print(f"Executing: {' '.join(set_dns_cmd)}")

                try:
                    set_result = subprocess.run(set_dns_cmd, capture_output=True, text=True) # No check=True here, check returncode
                    if set_result.returncode == 0:
                        # networksetup commands often print to stdout on success, e.g. nothing or new settings
                        print(f"{GREEN}Successfully set DNS for '{service}'.{RESET}")
                        # if set_result.stdout.strip(): print(f"{WHITE}Output: {set_result.stdout.strip()}{RESET}\")
                        success_on_any_service = True
                    else:
                        # Common errors: service not active, or permission issues.
                        error_message = set_result.stderr.strip() or set_result.stdout.strip() or "Unknown error"
                        print(f"{RED}Error setting DNS for '{service}': {error_message}{RESET}")
                        if "You must run this tool as root." in error_message:
                            print(f"{WHITE}macOS: Permission denied. Please ensure the script is run with sudo.{RESET}")
                        # Do not return False here immediately, try other services.

                except FileNotFoundError:
                    print(f"{RED}Error: 'networksetup' command not found. This should not happen on macOS.{RESET}")
                    return False # Critical command missing
                except Exception as e:
                    print(f"{RED}An unexpected error occurred while configuring '{service}': {e}{RESET}")

            if not success_on_any_service:
                print(f"{RED}\nFailed to set DNS for any active service on macOS.{RESET}")
                return False
            return True

        except subprocess.CalledProcessError as e:
            print(f"{RED}Error executing networksetup command: {e}{RESET}")
            print(f"{WHITE}Stderr: {e.stderr.strip()}{RESET}")
            return False
        except FileNotFoundError:
            print(f"{RED}Error: 'networksetup' command not found. Ensure macOS is correctly installed.{RESET}")
            return False
        except Exception as e:
            print(f"{RED}An unexpected error occurred in _set_dns_macos: {e}{RESET}")
            return False

    def _flush_dns_macos(self):
        print(f"{BLUE}\nAttempting to flush DNS cache for macOS...{RESET}")
        flushed_successfully = False

        # 1. dscacheutil -flushcache (Older macOS versions, but often run for good measure)
        print(f"{BLUE}Attempting: sudo dscacheutil -flushcache{RESET}")
        try:
            cmd_dscache = ["sudo", "dscacheutil", "-flushcache"]
            # Added check=True, as dscacheutil should exist, but might have permission issues.
            # If it genuinely doesn\'t exist (very old/custom system), FileNotFoundError will be caught.
            result_dscache = subprocess.run(cmd_dscache, capture_output=True, text=True, check=True)
            print(f"{GREEN}dscacheutil: Successfully ran flushcache command.{RESET}")
            # if result_dscache.stdout.strip(): print(f"{WHITE}Output: {result_dscache.stdout.strip()}{RESET}") # Often just prints 'Cache flushed' or nothing
            flushed_successfully = True # Mark success if dscacheutil command execution didn\'t raise an error

        except FileNotFoundError:
            print(f"{WHITE}dscacheutil: Command not found (common on newer macOS, not necessarily a failure).{RESET}")
            # Continue to the next method, don\'t mark overall failure
        except subprocess.CalledProcessError as e:
             print(f"{RED}dscacheutil: Error running flushcache (return code {e.returncode}): {e.stderr.strip() or e.stdout.strip()}{RESET}")
             if "Operation not permitted" in (e.stderr.strip() or e.stdout.strip()):
                 print(f"{WHITE}dscacheutil: Permission denied. Ensure script is run with sudo.{RESET}")
             # Continue to the next method, don\'t mark overall failure

        except Exception as e:
            print(f"{RED}dscacheutil: An unexpected error occurred: {e}{RESET}")
            # Continue to the next method

        # 2. killall -HUP mDNSResponder (This is the primary method for modern macOS)
        print(f"{BLUE}\nAttempting: sudo killall -HUP mDNSResponder{RESET}")
        try:
            cmd_mdns = ["sudo", "killall", "-HUP", "mDNSResponder"]
            # Added check=True, as killall should exist. Failure implies process not running or permission issue.
            result_mdns = subprocess.run(cmd_mdns, capture_output=True, text=True, check=True)
            print(f"{GREEN}mDNSResponder: Successfully sent HUP signal to flush cache.{RESET}")
            # if result_mdns.stdout.strip(): print(f"{WHITE}Output: {result_mdns.stdout.strip()}{RESET}") # Often empty
            flushed_successfully = True # Mark success

        except FileNotFoundError:
            print(f"{RED}killall: Command not found. This indicates a severe issue with the OS environment.{RESET}")
            return False # Critical command missing
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() or e.stdout.strip() or "Unknown error"
            print(f"{RED}mDNSResponder: Error sending HUP signal (return code {e.returncode}): {error_msg}{RESET}")
            if "No matching processes" in error_msg:
                print(f"{WHITE}mDNSResponder: Process not found (it might not be running).{RESET}")
                flushed_successfully = True # Process not running means no cache to flush via HUP
            elif "Operation not permitted" in error_msg or "must be run as root" in error_msg.lower():
                print(f"{WHITE}mDNSResponder: Permission denied. Ensure script is run with sudo.{RESET}")
                return False # Permission issue is a blocking failure

            # If other CalledProcessError occurs, it's a failure for this method.
        except Exception as e:
            print(f"{RED}mDNSResponder: An unexpected error occurred: {e}{RESET}")
            # Don\'t return False immediately, previous flush might have worked

        # Check if at least one method indicated success
        if flushed_successfully:
             print(f"{GREEN}\nDNS cache flush attempt completed for macOS.{RESET}")
             return True
        else:
            print(f"{RED}\nFailed to flush DNS cache using known methods on macOS.{RESET}")
            return False

    # --- Methods to GET current DNS settings ---

    def _get_current_dns_windows(self):
        print(f"{BLUE}\nGetting current DNS settings for Windows...{RESET}")
        original_settings = {}
        try:
            interfaces_result = subprocess.run(["netsh", "interface", "show", "interface"], capture_output=True, text=True, check=True, shell=True)
            active_interfaces_names = []
            lines = interfaces_result.stdout.strip().split('\n')
            if len(lines) > 2:
                for line in lines[2:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == "Enabled" and parts[1] == "Connected":
                        interface_name = " ".join(parts[3:])
                        if interface_name:
                            active_interfaces_names.append(interface_name)

            if not active_interfaces_names:
                print(f"{YELLOW}Windows: No active interfaces found to get DNS settings from.{RESET}")
                return None

            for if_name in active_interfaces_names:
                print(f"{BLUE}Windows: Checking DNS for interface '{if_name}'{RESET}")
                cmd = ["netsh", "interface", "ipv4", "show", "dnsservers", f"name=\"{if_name}\""]
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
                    output = result.stdout.strip()
                    current_dns_servers = []

                    if "dhcp" in output.lower():
                        # Try to find DNS servers listed even if DHCP - these might be the DHCP assigned ones
                        # Example DHCP output: "DNS servers configured through DHCP:  192.168.1.1"
                        # The pattern needs to match the IP after the colon.
                        dns_lines = re.findall(r"configured through DHCP:\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", output, re.MULTILINE)
                        # Sometimes netsh lists additional DHCP servers below the first one, like static ones
                        additional_dns_lines = re.findall(r"^\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", output, re.MULTILINE)
                        current_dns_servers.extend(dns_lines)
                        current_dns_servers.extend(additional_dns_lines)

                        # Filter for valid IPs, although netsh should list valid ones
                        current_dns_servers = [ip for ip in current_dns_servers if self._is_valid_ip(ip)]


                        print(f"Windows: Interface '{if_name}' uses DHCP for DNS. Servers found: {current_dns_servers if current_dns_servers else 'None explicitly listed'}")
                        original_settings[if_name] = {"servers": current_dns_servers, "dhcp": True, "method": "netsh"}

                    else: # Statically configured
                        # Find "Statically Configured DNS Servers:" line and subsequent indented lines
                        static_match = re.search(r"Statically Configured DNS Servers:\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", output)
                        if static_match:
                            current_dns_servers.append(static_match.group(1))

                        additional_dns_lines = re.findall(r"^\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", output, re.MULTILINE)
                        current_dns_servers.extend(additional_dns_lines)

                         # Filter for valid IPs
                        current_dns_servers = [ip for ip in current_dns_servers if self._is_valid_ip(ip)]
                        if current_dns_servers:
                            print(f"{WHITE}Windows: Interface '{if_name}' has static DNS: {current_dns_servers}{RESET}")
                            original_settings[if_name] = {"servers": current_dns_servers, "dhcp": False, "method": "netsh"}
                        else:
                            print(f"{YELLOW}Windows: Interface '{if_name}' - No static DNS servers found, might be DHCP or unconfigured.{RESET}")
                            # If no static and not explicitly DHCP, could be unconfigured or another state.
                            # For restore purposes, treating as \"dhcp\" might be safest if no IPs found.
                            original_settings[if_name] = {"servers": [], "dhcp": True, "method": "netsh_unknown_fallback_to_dhcp"}


                except subprocess.CalledProcessError as e:
                    print(f"{RED}Windows: Error getting DNS for interface '{if_name}': {e.stderr.strip()}{RESET}")
                except Exception as e_gen:
                     print(f"{RED}Windows: Unexpected error getting DNS for '{if_name}': {e_gen}{RESET}")


            return original_settings if original_settings else None
        except Exception as e:
            print(f"{RED}Windows: Error listing interfaces: {e}{RESET}")
            return None

    def _get_current_dns_linux(self):
        print(f"{BLUE}\nGetting current DNS settings for Linux...{RESET}")
        original_settings = {}

        # Try nmcli first
        if is_command_available("nmcli"):
            print(f"{BLUE}Linux: Trying nmcli...{RESET}")
            try:
                # Get active devices
                result_dev = subprocess.run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "dev"], capture_output=True, text=True, check=True)
                for line in result_dev.stdout.strip().split('\n'):
                    parts = line.split(':')
                    if len(parts) == 3 and parts[2] == "connected":
                        device = parts[0]
                        # Skip loopback and bridge devices unless they are the only active ones?
                        # For simplicity, check all \'connected\' devices reported by \'dev\'.
                        # if device == "lo" or device.startswith("docker"): # Skip common virtual/loopback interfaces
                        #     # print(f"{WHITE}Linux (nmcli): Skipping virtual/loopback device \'{device}\'.{RESET}")
                        #     continue
                        print(f"{BLUE}Linux (nmcli): Checking device '{device}'{RESET}")
                        show_result = subprocess.run(["nmcli", "dev", "show", device], capture_output=True, text=True, check=True)
                        dns_servers = []
                        dhcp_dns = []
                        # Assume DHCP by default, look for static settings

                        for L in show_result.stdout.splitlines():
                            # Manually configured DNS
                            if "IP4.DNS[" in L:
                                dns_ip = L.split(":", 1)[1].strip()
                                if self._is_valid_ip(dns_ip):
                                    dns_servers.append(dns_ip)
                            # DHCP provided DNS
                            if "DHCP4.OPTION[6]" in L: # DNS servers from DHCP
                                # Example format: 'DHCP4.OPTION[6]: domain_name_servers = 1.2.3.4 5.6.7.8'
                                match = re.search(r"=\s*([\d\.\s]+)", L)
                                if match:
                                     dhcp_ips_str = match.group(1).strip()
                                     dhcp_dns.extend([ip for ip in dhcp_ips_str.split() if self._is_valid_ip(ip)])

                        # Check if the connection is set to ignore auto DNS (manual only)
                        ignore_auto = False
                        try:
                             # Get connection name for the device first
                            conn_result = subprocess.run(["nmcli", "-t", "-f", "DEVICE,NAME", "connection", "show", "--active"], capture_output=True, text=True, check=True)
                            connection_name = None
                            for conn_line in conn_result.stdout.strip().split('\n'):
                                 conn_parts = conn_line.split(':')
                                 if len(conn_parts) >= 2 and conn_parts[0] == device:
                                     connection_name = conn_parts[1]
                                     break

                            if connection_name:
                                ignore_result = subprocess.run(["nmcli", "-t", "-f", "ipv4.ignore-auto-dns", "connection", "show", connection_name], capture_output=True, text=True, check=True)
                                if ignore_result.stdout.strip().lower() == "yes":
                                    ignore_auto = True
                                    # print(f"Linux (nmcli): Connection '{connection_name}' ignores auto DNS.")

                        except Exception as e_ignore:
                            # print(f"Linux (nmcli): Error checking ignore-auto-dns for '{device}': {e_ignore}")
                            pass # Silently fail check if nmcli call fails


                        # Logic: If ipv4.ignore-auto-dns is 'yes', only IP4.DNS are effective (static).
                        # If 'no' (default), DHCP4.OPTION[6] are usually preferred unless IP4.DNS is also set (mixed or override).
                        # Simplification: If IP4.DNS is present, consider it static configuration. Otherwise, check DHCP4.OPTION[6].
                        if dns_servers:
                            print(f"Linux (nmcli): Device '{device}' has static DNS: {dns_servers}")
                            original_settings[device] = {"servers": dns_servers, "dhcp": False, "method": "nmcli"}
                        elif dhcp_dns and not ignore_auto: # Only consider DHCP if not ignoring auto DNS
                            print(f"Linux (nmcli): Device '{device}' uses DHCP for DNS. Servers: {dhcp_dns}")
                            original_settings[device] = {"servers": dhcp_dns, "dhcp": True, "method": "nmcli"} # Store DHCP ones if found
                        else:
                            print(f"Linux (nmcli): Device '{device}' - No explicit DNS found via nmcli show, or ignoring auto DNS.")
                             # It's hard to be certain here without more context.
                            original_settings[device] = {"servers": [], "dhcp": True, "method": "nmcli_unknown_fallback_to_dhcp"} # Assume DHCP fallback


            except Exception as e:
                print(f"{RED}Linux (nmcli): Error: {e}{RESET}")

        # Try systemd-resolve next (if nmcli didn\'t find anything or failed)
        if not original_settings and is_command_available("resolvectl"):
            print(f"{BLUE}Linux: Trying resolvectl...{RESET}")
            interface = get_default_linux_interface()
            if interface:
                try:
                    result = subprocess.run(["resolvectl", "status", interface], capture_output=True, text=True, check=True)
                    dns_servers = []
                    # Parse DNS servers from resolvectl status output
                    # Look for "Current DNS Server:", "DNS Servers:", "Link DNS Servers:", "DNS Domain:"
                    # The relevant ones are usually "DNS Servers:" or "Link DNS Servers:"
                    for line in result.stdout.splitlines():
                        if "DNS Servers:" in line or "Link DNS Servers:" in line:
                             parts = line.split(":", 1)
                             if len(parts) > 1:
                                 ips = parts[1].strip().split()
                                 for ip_addr in ips:
                                     # Clean up potential IPv6 addresses or extra characters
                                     cleaned_ip = ip_addr.split('%')[0].strip() # Remove link-local scope
                                     if self._is_valid_ip(cleaned_ip) and cleaned_ip not in dns_servers:
                                         dns_servers.append(cleaned_ip)

                    if dns_servers:
                        print(f"{WHITE}Linux (resolvectl): Interface \'{interface}\' using DNS: {dns_servers} (parsed from status){RESET}")
                        # It\'s hard to tell if these are from DHCP or static via resolvectl status easily for all cases.
                        # systemd-resolved often gets them from systemd-networkd or NetworkManager.
                        # For restoration, `resolvectl revert` is the key if managed by systemd-resolved.
                        original_settings[interface] = {"servers": dns_servers, "dhcp": "unknown_revert_to_resolvectl", "method": "resolvectl"}
                    else:
                         print(f"{WHITE}Linux (resolvectl): No DNS servers found for \'{interface}\'. Assuming DHCP managed by systemd-resolved.{RESET}")
                         original_settings[interface] = {"servers": [], "dhcp": True, "method": "resolvectl"}


                except Exception as e:
                    print(f"{RED}Linux (resolvectl): Error for interface {interface}: {e}{RESET}")
            else:
                print(f"{YELLOW}Linux (resolvectl): Could not determine default interface.{RESET}")


        # Fallback: Read /etc/resolv.conf directly (with caveats)
        if not original_settings:
            print(f"{BLUE}Linux: Trying direct /etc/resolv.conf read as fallback...{RESET}")
            try:
                resolv_conf_path = "/etc/resolv.conf"
                if os.path.exists(resolv_conf_path) and not os.path.islink(resolv_conf_path):
                    # Check for generator comments
                    is_managed = False
                    try:
                        with open(resolv_conf_path, 'r') as f:
                            content = f.read(1024)
                            if "# Generated by" in content:
                                is_managed = True
                    except Exception: pass # Ignore read errors for this check

                    if is_managed:
                        print(f"{YELLOW}Linux: /etc/resolv.conf is not a symlink but seems auto-generated. Skipping direct read for safety.{RESET}")
                        # return None # Avoid using potentially misleading info
                    else:
                         dns_servers = []
                         with open(resolv_conf_path, 'r') as f:
                            for line in f:
                                line = line.strip()
                                if line.startswith("nameserver"):
                                    parts = line.split()
                                    if len(parts) > 1 and self._is_valid_ip(parts[1]):
                                        dns_servers.append(parts[1])
                         if dns_servers:
                            print(f"{WHITE}Linux (/etc/resolv.conf): Found DNS: {dns_servers}{RESET}")
                            # Assume static if manually edited /etc/resolv.conf
                            original_settings["/etc/resolv.conf"] = {"servers": dns_servers, "dhcp": False, "method": "resolv.conf"}
                            # return original_settings # Return immediately if this method is used

            except Exception as e:
                print(f"{RED}Linux (/etc/resolv.conf): Error: {e}{RESET}")


        return None if not original_settings else original_settings


    def _get_current_dns_macos(self):
        print(f"{BLUE}\nGetting current DNS settings for macOS...{RESET}")
        original_settings = {}
        try:
            list_services_cmd = ["networksetup", "-listallnetworkservices"]
            result_services = subprocess.run(list_services_cmd, capture_output=True, text=True, check=True)
            services = [s for s in result_services.stdout.strip().split('\n') if not s.startswith("An asterisk") and s.strip()]

            if not services:
                print(f"{YELLOW}macOS: No network services found.{RESET}")
                return None

            for service in services:
                print(f"{BLUE}macOS: Checking DNS for service '{service}'{RESET}")
                cmd = ["networksetup", "-getdnsservers", service]
                try:
                    result_dns = subprocess.run(cmd, capture_output=True, text=True, check=True)
                    output = result_dns.stdout.strip()
                    if "aren\'t any DNS Servers set" in output or output.lower().strip() == "there": # networksetup -getdnsservers can output "There aren\'t any DNS Servers set on ..."
                        print(f"{WHITE}macOS: Service '{service}' uses DHCP for DNS (no servers listed or explicitly set to empty).{RESET}")
                        original_settings[service] = {"servers": [], "dhcp": True, "method": "networksetup"}
                    else:
                         # networksetup -getdnsservers outputs each server on a new line
                        current_dns_servers = [ip.strip() for ip in output.splitlines() if self._is_valid_ip(ip.strip())]
                        if current_dns_servers:
                            print(f"{WHITE}macOS: Service '{service}' has static DNS: {current_dns_servers}{RESET}")
                            original_settings[service] = {"servers": current_dns_servers, "dhcp": False, "method": "networksetup"}
                        else:
                             # Should not happen often if output is not "aren\'t any", but possible if IPs are invalid.
                            print(f"{YELLOW}macOS: Service '{service}' output did not yield valid static DNS IPs. Assuming DHCP fallback.{RESET}")
                            original_settings[service] = {"servers": [], "dhcp": True, "method": "networksetup_unknown_fallback_to_dhcp"}


                except subprocess.CalledProcessError as e:
                    # This can happen if a service is disabled or invalid, networksetup returns non-zero.
                    print(f"{RED}macOS: Error getting DNS for service '{service}': {e.stderr.strip() or e.stdout.strip()}{RESET}")
                    # Continue to the next service
                except Exception as e_gen:
                    print(f"{RED}macOS: Unexpected error for service '{service}': {e_gen}{RESET}")
                    # Continue to the next service

            return original_settings if original_settings else None
        except Exception as e:
            print(f"{RED}macOS: Error listing network services: {e}{RESET}")
            return None


    def save_original_dns_settings(self, original_settings, filepath=None):
        if filepath is None:
            filepath = self.ORIGINAL_DNS_CONFIG_FILE

        if original_settings:
            print(f"{BLUE}\nSaving original DNS settings to {filepath}...{RESET}")
            try:
                # Ensure the structure includes the OS key
                data_to_save = {self.current_os: original_settings}
                with open(filepath, 'w') as f:
                    json.dump(data_to_save, f, indent=4)
                print(f"{GREEN}Original DNS settings saved successfully.{RESET}")
            except IOError as e:
                print(f"{RED}Error: Could not write original DNS settings to file {filepath}: {e}{RESET}")
            except Exception as e_gen:
                print(f"{RED}Unexpected error saving original DNS settings: {e_gen}{RESET}")


    def load_original_dns_settings(self, filepath=None):
        if filepath is None:
            filepath = self.ORIGINAL_DNS_CONFIG_FILE

        if not os.path.exists(filepath):
            print(f"{RED}Error: Original DNS settings file '{filepath}' not found. Cannot restore.{RESET}")
            return None
        try:
            with open(filepath, 'r') as f:
                full_settings = json.load(f)
            print(f"{GREEN}Successfully loaded original DNS settings from {filepath}.{RESET}")

            # Retrieve settings for the current OS
            return full_settings.get(self.current_os, {}) # Return settings for current OS, or empty dict if OS not found

        except (IOError, json.JSONDecodeError) as e:
            print(f"{RED}Error reading or parsing original DNS settings file '{filepath}': {e}{RESET}")
            return None
        except Exception as e_gen:
            print(f"{RED}Unexpected error loading original DNS settings: {e_gen}{RESET}")
            return None

    # --- DNS Restoration Methods ---

    def _restore_dns_windows(self, settings):
        print(f"{BLUE}\nRestoring DNS settings for Windows...{RESET}")
        success = True
        if not settings:
            print(f"{YELLOW}Windows: No settings found for restoration.{RESET}")
            return False

        for interface_name, config in settings.items():
            print(f"{BLUE}Windows: Restoring DNS for interface '{interface_name}'{RESET}")
            is_dhcp = config.get("dhcp", False) # Default to not DHCP if unspecified
            servers = config.get("servers", [])
            method = config.get("method", "") # Not strictly needed for Windows, but good practice

            try:
                if is_dhcp:
                    # netsh set source=dhcp effectively clears static and gets from DHCP
                    cmd = ["netsh", "interface", "ipv4", "set", "dnsservers", f"name=\"{interface_name}\"", "source=dhcp"]
                    # print(f"{WHITE}Executing: {' '.join(cmd)}{RESET}") # Optional: show command
                    result = subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
                    print(f"{GREEN}Windows: Successfully set \'{interface_name}\' to DHCP for DNS.{RESET}")
                    # if result.stdout.strip(): print(f"{WHITE}Output: {result.stdout.strip()}{RESET}")
                elif servers: # Static configuration
                    # First, set the primary DNS server.
                    cmd_set = ["netsh", "interface", "ipv4", "set", "dnsservers", f"name=\"{interface_name}\"", "static", f"addr=\"{servers[0]}\"", "validate=no"]
                    # print(f"{WHITE}Executing: {' '.join(cmd_set)}{RESET}") # Optional: show command
                    subprocess.run(cmd_set, capture_output=True, text=True, check=True, shell=True)
                    print(f"{GREEN}Windows: Successfully set primary DNS for \'{interface_name}\' to {servers[0]}.{RESET}")
                    # Then add secondary/tertiary servers.
                    # Note: index=2 for the second server, index=3 for the third, etc.
                    for i, dns_server_ip in enumerate(servers[1:], start=1):
                         if not self._is_valid_ip(dns_server_ip):
                             print(f"{YELLOW}Windows: Skipping invalid IP during restore: {dns_server_ip}{RESET}")
                             continue
                         cmd_add = ["netsh", "interface", "ipv4", "add", "dnsservers", f"name=\"{interface_name}\"", f"addr=\"{dns_server_ip}\"", f"index={i+1}", "validate=no"]
                         # print(f"{WHITE}Executing: {' '.join(cmd_add)}{RESET}") # Optional: show command
                         subprocess.run(cmd_add, capture_output=True, text=True, check=True, shell=True)
                         print(f"{GREEN}Windows: Successfully added DNS {dns_server_ip} (index {i+1}) for \'{interface_name}\'.{RESET}")

                else:
                    print(f"{YELLOW}Windows: No valid DNS restore configuration found for '{interface_name}' (neither DHCP flag nor static IPs). Skipping.{RESET}")
                    success = False
                    continue # Skip to next interface

            except subprocess.CalledProcessError as e:
                print(f"{RED}Windows: Error restoring DNS for '{interface_name}': {e.stderr.strip() or e.stdout.strip()}{RESET}")
                success = False # Mark failure for this specific interface, but continue trying others if possible
            except FileNotFoundError:
                print(f"{RED}Windows: 'netsh' command not found. Cannot restore.{RESET}")
                return False # Critical failure, stop restoring
            except Exception as e_gen:
                print(f"{RED}Windows: Unexpected error restoring DNS for '{interface_name}': {e_gen}{RESET}")
                success = False # Mark failure for this interface

        return success # Return overall success status

    def _restore_dns_linux(self, settings):
        print(f"{BLUE}\nRestoring DNS settings for Linux...{RESET}")
        success = True
        if not settings:
            print(f"{YELLOW}Linux: No settings found for restoration.{RESET}")
            return False

        for interface_id, config in settings.items(): # interface_id can be device name or "/etc/resolv.conf"
            print(f"{BLUE}Linux: Restoring DNS for '{interface_id}' using recorded method '{config.get('method', 'unknown')}'{RESET}")
            is_dhcp = config.get("dhcp", False)
            servers = config.get("servers", [])
            method = config.get("method", "")

            try:
                if method == "nmcli" or method == "nmcli_unknown_fallback_to_dhcp":
                    # Find the connection name for the device
                    conn_result = subprocess.run(["nmcli", "-t", "-f", "DEVICE,NAME", "connection", "show", "--active"], capture_output=True, text=True, check=True)
                    connection_name = None
                    for line in conn_result.stdout.strip().split('\n'):
                        parts = line.split(':')
                        if len(parts) >= 2 and parts[0] == interface_id:
                            connection_name = parts[1]
                            break

                    if connection_name:
                        print(f"{BLUE}Linux (nmcli): Found active connection '{connection_name}' for device '{interface_id}'.{RESET}")

                        # Determine the DNS setting based on original configuration
                        # If original was DHCP, set dns to empty and ensure ignore-auto-dns is 'no'
                        # If original was static, set dns to the saved servers and ignore-auto-dns 'yes'
                        if is_dhcp:
                             dns_setting_arg = "" # Empty string tells nmcli to use auto DNS
                             ignore_auto_arg = "no" # Ensure DHCP servers are used
                             print(f"{WHITE}Linux (nmcli): Restoring '{connection_name}' to use DHCP DNS.{RESET}")
                        elif servers:
                             # Filter saved servers just in case they became invalid
                            valid_servers = [ip for ip in servers if self._is_valid_ip(ip)]
                            if not valid_servers:
                                print(f"{YELLOW}Linux (nmcli): No valid saved static IPs for '{connection_name}'. Cannot restore static config. Skipping this interface.{RESET}")
                                success = False
                                continue # Skip to next interface
                            dns_setting_arg = ",".join(valid_servers)
                            ignore_auto_arg = "yes" # Ensure only manual servers are used
                            print(f"{WHITE}Linux (nmcli): Restoring '{connection_name}' to use static DNS: {valid_servers}.{RESET}")
                        else:
                            print(f"{YELLOW}Linux (nmcli): No valid restore config (neither DHCP flag nor servers) for connection '{connection_name}'. Skipping.{RESET}")
                            success = False
                            continue # Skip to next interface


                        # Modify the connection profile - set DNS and ignore-auto-dns flag
                        cmd_modify_conn = ["sudo", "nmcli", "connection", "modify", connection_name,
                                           "ipv4.dns", dns_setting_arg,
                                           "ipv4.ignore-auto-dns", ignore_auto_arg]
                        # print(f"{WHITE}Linux (nmcli): Executing: {' '.join(cmd_modify_conn)}{RESET}") # Optional: show command
                        subprocess.run(cmd_modify_conn, capture_output=True, text=True, check=True)
                        print(f"{GREEN}Linux (nmcli): Successfully modified connection \'{connection_name}\'.{RESET}")

                        # Reapply the connection to make changes effective
                        cmd_up_conn = ["sudo", "nmcli", "connection", "up", connection_name]
                        # print(f"{WHITE}Linux (nmcli): Executing: {' '.join(cmd_up_conn)}{RESET}") # Optional: show command
                        subprocess.run(cmd_up_conn, capture_output=True, text=True, check=True)
                        print(f"{GREEN}Linux (nmcli): Successfully reactivated connection \'{connection_name}\'.{RESET}")


                    else:
                        print(f"{YELLOW}Linux (nmcli): Could not find active connection for device '{interface_id}'. Cannot restore via nmcli connection commands.{RESET}")
                        success = False # Mark failure for this interface

                elif method == "resolvectl":
                    # `resolvectl revert` is the simplest way to restore systemd-resolved managed interfaces
                    # This command reverts the interface to get DNS from DHCP or other link-local configs.
                    print(f"{BLUE}Linux (resolvectl): Attempting to revert DNS for interface \'{interface_id}\'.{RESET}")
                    cmd = ["sudo", "resolvectl", "revert", interface_id]
                    # print(f"{WHITE}Linux (resolvectl): Executing: {' '.join(cmd)}{RESET}") # Optional: show command
                    subprocess.run(cmd, capture_output=True, text=True, check=True)
                    # Note: `revert` handles going back to DHCP. If original was static configured
                    # *via systemd-networkd/resolved config files*, revert is also appropriate.
                    # If the original static was set *manually* via `resolvectl dns`,
                    # `revert` will unset it, effectively going back to auto/DHCP unless other configs exist.
                    # For this script\'s purpose, `revert` is the best general approach for this method.
                    print(f"{GREEN}Linux (resolvectl): Successfully reverted DNS for interface \'{interface_id}\'.{RESET}")


                elif method == "resolv.conf": # Direct modification restoration
                    backup_path = "/etc/resolv.conf.bak_set_dns_py" # Use the specific backup name
                    if os.path.exists(backup_path):
                        print(f"{BLUE}Linux (/etc/resolv.conf): Restoring from backup {backup_path}{RESET}")
                        # Use sudo with mv for permission
                        subprocess.run(["sudo", "mv", "-f", backup_path, "/etc/resolv.conf"], check=True)
                        print(f"{GREEN}Linux (/etc/resolv.conf): Successfully restored from backup.{RESET}")
                    else:
                        print(f"{YELLOW}Linux (/etc/resolv.conf): Backup file {backup_path} not found. Cannot restore manually modified resolv.conf.{RESET}")
                        success = False # Mark failure for this interface

                else:
                    print(f"{YELLOW}Linux: Unknown restoration method (\'{method}\') or configuration for \'{interface_id}\'. Skipping.{RESET}")
                    success = False # Mark failure for this interface

            except subprocess.CalledProcessError as e:
                print(f"{RED}Linux: Error restoring DNS for '{interface_id}': {e.stderr.strip() or e.stdout.strip()}{RESET}")
                if "Operation not permitted" in (e.stderr.strip() or e.stdout.strip()):
                    print(f"{WHITE}Linux: Permission denied. Ensure script is run with sudo.{RESET}")
                    return False # Permission issue is a blocking failure
                success = False # Mark failure for this interface

            except FileNotFoundError as e_fnf:
                print(f"{RED}Linux: Command \'{e_fnf.filename}\' not found during restore for \'{interface_id}\'. Cannot restore.{RESET}")
                return False # Critical failure, stop restoring
            except Exception as e_gen:
                print(f"{RED}Linux: Unexpected error restoring DNS for '{interface_id}': {e_gen}{RESET}")
                success = False # Mark failure for this interface

        return success # Return overall success status


    def _restore_dns_macos(self, settings):
        print(f"{BLUE}\nRestoring DNS settings for macOS...{RESET}")
        success = True
        if not settings:
            print(f"{YELLOW}macOS: No settings found for restoration.{RESET}")
            return False

        for service_name, config in settings.items():
            print(f"{BLUE}macOS: Restoring DNS for service '{service_name}'{RESET}")
            is_dhcp = config.get("dhcp", False)
            servers = config.get("servers", [])
            method = config.get("method", "") # Not strictly needed, should be 'networksetup'

            try:
                if is_dhcp:
                    # Using "empty" with networksetup -setdnsservers typically sets the service to use DHCP DNS.
                    cmd = ["sudo", "networksetup", "-setdnsservers", service_name, "empty"]
                    print(f"{WHITE}macOS: Setting service \'{service_name}\' to DHCP DNS.{RESET}")
                elif servers:
                    # Filter saved servers just in case they became invalid
                    valid_servers = [ip for ip in servers if self._is_valid_ip(ip)]
                    if not valid_servers:
                        print(f"{YELLOW}macOS: No valid saved static IPs for service \'{service_name}\'. Cannot restore static config. Skipping this service.{RESET}")
                        success = False
                        continue # Skip to next service
                    cmd = ["sudo", "networksetup", "-setdnsservers", service_name] + valid_servers
                    print(f"{WHITE}macOS: Setting service \'{service_name}\' to static DNS: {valid_servers}.{RESET}")
                else:
                    print(f"{YELLOW}macOS: No valid DNS restore configuration found for \'{service_name}\' (neither DHCP flag nor servers). Skipping.{RESET}")
                    success = False
                    continue # Skip to next service

                # print(f"{WHITE}Executing: {' '.join(cmd)}{RESET}") # Optional: show command
                subprocess.run(cmd, capture_output=True, text=True, check=True)
                print(f"{GREEN}Successfully restored DNS for '{service_name}'.{RESET}")

            except subprocess.CalledProcessError as e:
                print(f"{RED}macOS: Error restoring DNS for '{service_name}': {e.stderr.strip() or e.stdout.strip()}{RESET}")
                if "Operation not permitted" in (e.stderr.strip() or e.stdout.strip()) or "must be run as root" in (e.stderr.strip() or e.stdout.strip()).lower():
                    print(f"{WHITE}macOS: Permission denied. Ensure script is run with sudo.{RESET}")
                    return False # Permission issue is a blocking failure
                success = False # Mark failure for this service

            except FileNotFoundError:
                print(f"{RED}macOS: 'networksetup' command not found. Cannot restore.{RESET}")
                return False # Critical failure
            except Exception as e_gen:
                print(f"{RED}macOS: Unexpected error restoring DNS for '{service_name}': {e_gen}{RESET}")
                success = False # Mark failure for this service

        return success # Return overall success status

    def check_privileges(self):
        """Checks if the script is running with administrator/root privileges."""
        print(f"{BLUE}Checking privileges for OS: {self.current_os}...{RESET}") # Added print statement

        if self.current_os == "windows":
            try:
                # Access windll only if running on Windows
                if hasattr(ctypes, "windll"):
                    # Use a try-except block as IsUserAnAdmin might not exist in all environments
                    try:
                         is_admin = (ctypes.windll.shell32.IsUserAnAdmin() != 0)  # type: ignore[attr-defined]
                         if is_admin:
                             print(f"{GREEN}Windows: Administrator privileges detected.{RESET}")
                         else:
                             print(f"{YELLOW}Windows: Administrator privileges NOT detected.{RESET}")
                         return is_admin
                    except AttributeError:
                         print(f"{RED}Error: ctypes.windll.shell32.IsUserAnAdmin not found. Cannot check admin status on this Windows version.{RESET}")
                         print(f"{YELLOW}Assuming elevated privileges for now, but operations might fail.{RESET}")
                         # In a real scenario, you might want to exit or raise an error here.
                         # For this script, we'll allow it to proceed but warn.
                         # If the script was launched with "Run as Administrator", this check might still fail
                         # depending on environment, but subprocess commands requiring admin might still work.
                         # Let's assume success for the check if the API call fails, but add a warning.
                         return True # Assume true for the check if the check itself errors, but print warning.
                else:
                    print(f"{YELLOW}ctypes.windll not available (not running on Windows or unusual env). Cannot reliably check admin status.{RESET}")
                    print(f"{YELLOW}Assuming elevated privileges for now, but operations might fail.{RESET}")
                    return True # Assume true for the check if the check itself errors, but print warning.

            except Exception as e:
                print(f"{RED}Error checking Windows admin status: {e}{RESET}")
                print(f"{YELLOW}Assuming elevated privileges for now, but operations might fail.{RESET}")
                return True # Assume true for the check if the check itself errors, but print warning.

        elif self.current_os == "linux" or self.current_os == "macos":
            # Check if effective user ID is 0 (root)
            if hasattr(os, 'geteuid'):
                is_root = (os.geteuid() == 0)
                if is_root:
                    print(f"{GREEN}{self.current_os.capitalize()}: Root privileges detected.{RESET}")
                else:
                    print(f"{YELLOW}{self.current_os.capitalize()}: Root privileges NOT detected.{RESET}")
                return is_root
            else:
                 print(f"{YELLOW}Warning: Cannot check root privileges on {self.current_os}. \'os.geteuid\' not available.{RESET}")
                 print(f"{YELLOW}Assuming elevated privileges for now, but operations might fail.{RESET}")
                 return True # Assume true if check is not possible, but warn.

        else:
            print(f"{RED}Unknown OS ({self.current_os}): Cannot determine privilege level.{RESET}")
            return False # Cannot proceed without knowing privilege requirements

    def flush_dns(self): # Combined flush function
        print(f"{BLUE}\nAttempting to flush DNS for {self.current_os} after operations...{RESET}")
        if self.current_os == "windows":
            self._flush_dns_windows()
        elif self.current_os == "linux":
            self._flush_dns_linux()
        elif self.current_os == "macos":
            self._flush_dns_macos()
        else:
            print(f"{YELLOW}DNS flush not supported for unknown OS: {self.current_os}{RESET}")

    # --- Main Flow Methods called by the menu ---

    def run_set_dns_flow(self):
        print(f"{CYAN}\n--- Set New DNS Process ---{RESET}")
        if not self.check_privileges():
            print(f"{RED}\nError: Setting DNS requires administrator/root privileges.{RESET}")
            if self.current_os == "windows": print(f"{WHITE}Please run this script as an Administrator.{RESET}")
            elif self.current_os in ["linux", "macos"]: print(f"{WHITE}Please run this script with sudo.{RESET}")
            return # Exit function, not script

        # Get and save current DNS settings BEFORE changing them
        print(f"{BLUE}Gathering current DNS settings before making changes...{RESET}")
        os_specific_original_dns = {}
        if self.current_os == "windows":
            os_specific_original_dns = self._get_current_dns_windows()
        elif self.current_os == "linux":
            os_specific_original_dns = self._get_current_dns_linux()
        elif self.current_os == "macos":
            os_specific_original_dns = self._get_current_dns_macos()
        else:
            print(f"{YELLOW}Getting current DNS not supported for OS: {self.current_os}{RESET}")
            # Allow proceeding, but warn that restore won\'t work
            os_specific_original_dns = None


        if os_specific_original_dns is not None:
            # self.save_original_dns_settings({self.current_os: os_specific_original_dns}) # Save handled inside the method now
            self.save_original_dns_settings(os_specific_original_dns)
        else:
            print(f"{YELLOW}Warning: Could not retrieve current DNS settings. Restoration might not be possible.{RESET}")

        # Proceed with setting new DNS
        dns_entries = self.parse_dns_config() # From dnsConf.txt
        if dns_entries is None or not dns_entries:
            print(f"{RED}Exiting Set DNS process due to DNS configuration error from {self.DNS_CONFIG_FILE}.{RESET}")
            # original_dns_config.json would remain if it was saved.
            return # Exit function

        # For "Set Custom DNS" (option 1), we just use the first entry for simplicity as originally planned.
        # The "Select DNS by Provider" option (new option 2) will handle user selection.
        selected_entry = dns_entries[0]
        print(f"{BLUE}\nSetting DNS using the first entry from {self.DNS_CONFIG_FILE}: {selected_entry['name']} ({', '.join(selected_entry['ips'])}){RESET}")

        # Flatten IPs for setting DNS
        dns_servers_list = selected_entry['ips']

        set_successful = False
        if self.current_os == "windows":
            set_successful = self._set_dns_windows(dns_servers_list)
            # Add Windows-specific settings changes from run-dns-scripts.bat/set-dns-servers.ps1 if needed
            # Disable IPv6 binding, DoH, Random Name Resolution (based on PS scripts)
            if set_successful and self.current_os == "windows" and self.check_privileges(): # Re-check privileges before system-wide settings
                 print(f"{BLUE}\nApplying additional Windows network settings...{RESET}")
                 try:
                    # Disable IPv6 binding on active adapters (Caution: this is system-wide)
                    # Consider if this should be optional or interface-specific. For now, mirror PS script.
                    # Finding active adapters again...
                    interfaces_result = subprocess.run(["netsh", "interface", "show", "interface"], capture_output=True, text=True, check=True, shell=True)
                    active_interfaces_names = [
                        " ".join(line.split()[3:]) for line in interfaces_result.stdout.strip().split('\n')[2:]
                        if len(line.split()) >= 4 and line.split()[0] == "Enabled" and line.split()[1] == "Connected"
                    ]
                    for if_name in active_interfaces_names:
                         print(f"{BLUE}Windows: Disabling IPv6 binding for \'{if_name}\'...{RESET}")
                         # netsh interface ipv6 set interface \"Interface Name\" disabled
                         cmd_disable_ipv6 = ["netsh", "interface", "ipv6", "set", "interface", f"name=\"{if_name}\"", "disabled"]
                         try:
                             subprocess.run(cmd_disable_ipv6, check=True, capture_output=True, text=True, shell=True)
                             print(f"{GREEN}Windows: IPv6 binding disabled for \'{if_name}\'.{RESET}")
                         except Exception as ipv6_e:
                             print(f"{YELLOW}Windows: Warning: Could not disable IPv6 binding for \'{if_name}\': {ipv6_e}{RESET}")


                    # Disable DNS over HTTPS (DoH) and Random Name Resolution via Registry (Mirroring PS script)
                    print(f"{BLUE}Windows: Setting DoH and Random Name Resolution via Registry...{RESET}")
                    try:
                        # Need admin privileges for registry changes. Assumed by the outer check.
                        subprocess.run(["reg", "add", "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\Dnscache\\\\Parameters", "/v", "EnableAutoDOH", "/t", "REG_DWORD", "/d", "0", "/f"], check=True, capture_output=True, text=True, shell=True)
                        print(f"{GREEN}Windows: Disabled automatic DoH.{RESET}")
                    except Exception as doh_e:
                        print(f"{YELLOW}Windows: Warning: Could not disable automatic DoH via Registry: {doh_e}{RESET}")

                    try:
                        subprocess.run(["reg", "add", "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\Dnscache\\\\Parameters", "/v", "QueryIpMatching", "/t", "REG_DWORD", "/d", "0", "/f"], check=True, capture_output=True, text=True, shell=True)
                        print(f"{GREEN}Windows: Disabled Random Name Resolution.{RESET}")
                    except Exception as random_e:
                        print(f"{YELLOW}Windows: Warning: Could not disable Random Name Resolution via Registry: {random_e}{RESET}")

                 except Exception as win_extra_e:
                    print(f"{RED}Windows: An error occurred restoring extra Windows settings: {win_extra_e}{RESET}")


        elif self.current_os == "linux":
            set_successful = self._set_dns_linux(dns_servers_list)
        elif self.current_os == "macos":
            set_successful = self._set_dns_macos(dns_servers_list)
        else:
            print("Operating system not supported by this script for setting DNS.")
            return # Exit function

        if set_successful:
            print("\nNew DNS settings applied successfully (or attempted).")
            self.flush_dns() # General flush call
        else:
            print("\nFailed to apply new DNS settings. Check logs above.")
            print("You might need to manually restore your original DNS settings.")


    def run_select_dns_by_provider_flow(self):
        print(f"{CYAN}\n--- Select DNS by Provider Process ---{RESET}")
        if not self.check_privileges():
            print(f"{RED}\nError: Setting DNS requires administrator/root privileges.{RESET}")
            if self.current_os == "windows": print(f"{WHITE}Please run this script as an Administrator.{RESET}")
            elif self.current_os in ["linux", "macos"]: print(f"{WHITE}Please run this script with sudo.{RESET}")
            return # Exit function, not script

        # Get and save current DNS settings BEFORE changing them
        print(f"{BLUE}Gathering current DNS settings before making changes...{RESET}")
        os_specific_original_dns = {}
        if self.current_os == "windows":
            os_specific_original_dns = self._get_current_dns_windows()
        elif self.current_os == "linux":
            os_specific_original_dns = self._get_current_dns_linux()
        elif self.current_os == "macos":
            os_specific_original_dns = self._get_current_dns_macos()
        else:
            print(f"{YELLOW}Getting current DNS not supported for OS: {self.current_os}{RESET}")
            # Allow proceeding, but warn that restore won't work
            os_specific_original_dns = None

        if os_specific_original_dns is not None:
            self.save_original_dns_settings(os_specific_original_dns)
        else:
            print(f"{YELLOW}Warning: Could not retrieve current DNS settings. Restoration might not be possible.{RESET}")


        dns_entries = self.parse_dns_config()
        if not dns_entries:
            print(f"{RED}Could not load DNS providers from {self.DNS_CONFIG_FILE}. Exiting.{RESET}")
            return

        print(f"{BLUE}\nAvailable DNS Providers:{RESET}")
        for i, entry in enumerate(dns_entries):
            print(f"{WHITE}{i + 1}. {entry['name']} ({', '.join(entry['ips'])}){RESET}")

        while True:
            try:
                choice_index = int(input(f"{CYAN}Enter the number of the DNS provider to set: {RESET}")) - 1
                if 0 <= choice_index < len(dns_entries):
                    selected_entry = dns_entries[choice_index]
                    break
                else:
                    print(f"{YELLOW}Invalid number. Please enter a number between 1 and {len(dns_entries)}.{RESET}")
            except ValueError:
                print(f"{YELLOW}Invalid input. Please enter a number.{RESET}")

        print(f"{BLUE}\nSetting DNS to: {selected_entry['name']} ({', '.join(selected_entry['ips'])}){RESET}")

        dns_servers_list = selected_entry['ips'] # Flatten IPs for setting

        set_successful = False
        if self.current_os == "windows":
            set_successful = self._set_dns_windows(dns_servers_list)
            # Apply additional Windows settings if needed (mirroring run_set_dns_flow)
            if set_successful and self.current_os == "windows" and self.check_privileges():
                 print(f"{BLUE}\nApplying additional Windows network settings...{RESET}")
                 try:
                    interfaces_result = subprocess.run(["netsh", "interface", "show", "interface"], capture_output=True, text=True, check=True, shell=True)
                    active_interfaces_names = [
                        " ".join(line.split()[3:]) for line in interfaces_result.stdout.strip().split('\n')[2:]
                        if len(line.split()) >= 4 and line.split()[0] == "Enabled" and line.split()[1] == "Connected"
                    ]
                    for if_name in active_interfaces_names:
                         print(f"{BLUE}Windows: Disabling IPv6 binding for \'{if_name}\'...{RESET}")
                         cmd_disable_ipv6 = ["netsh", "interface", "ipv6", "set", "interface", f"name=\"{if_name}\"", "disabled"]
                         try:
                             subprocess.run(cmd_disable_ipv6, check=True, capture_output=True, text=True, shell=True)
                             print(f"{GREEN}Windows: IPv6 binding disabled for \'{if_name}\'.{RESET}")
                         except Exception as ipv6_e:
                             print(f"{YELLOW}Windows: Warning: Could not disable IPv6 binding for \'{if_name}\': {ipv6_e}{RESET}")

                    print(f"{BLUE}Windows: Setting DoH and Random Name Resolution via Registry...{RESET}")
                    try:
                        subprocess.run(["reg", "add", "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\Dnscache\\\\Parameters", "/v", "EnableAutoDOH", "/t", "REG_DWORD", "/d", "0", "/f"], check=True, capture_output=True, text=True, shell=True)
                        print(f"{GREEN}Windows: Disabled automatic DoH.{RESET}")
                    except Exception as doh_e:
                        print(f"{YELLOW}Windows: Warning: Could not disable automatic DoH via Registry: {doh_e}{RESET}")

                    try:
                        subprocess.run(["reg", "add", "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\Dnscache\\\\Parameters", "/v", "QueryIpMatching", "/t", "REG_DWORD", "/d", "0", "/f"], check=True, capture_output=True, text=True, shell=True)
                        print(f"{GREEN}Windows: Disabled Random Name Resolution.{RESET}")
                    except Exception as random_e:
                        print(f"{YELLOW}Windows: Warning: Could not disable Random Name Resolution via Registry: {random_e}{RESET}")

                 except Exception as win_extra_e:
                    print(f"{RED}Windows: An error occurred applying extra Windows settings: {win_extra_e}{RESET}")

        elif self.current_os == "linux":
            set_successful = self._set_dns_linux(dns_servers_list)
        elif self.current_os == "macos":
            set_successful = self._set_dns_macos(dns_servers_list)
        else:
            print("Operating system not supported by this script for setting DNS.")
            return # Exit function

        if set_successful:
            print("\nNew DNS settings applied successfully (or attempted).")
            self.flush_dns() # General flush call
        else:
            print("\nFailed to apply new DNS settings. Check logs above.")
            print("You might need to manually restore your original DNS settings.")


    def run_restore_dns_flow(self):
        print(f"{CYAN}\n--- Restore Original DNS Process ---{RESET}")
        if not self.check_privileges():
            print(f"{RED}\nError: Restoring DNS requires administrator/root privileges.{RESET}")
            if self.current_os == "windows": print(f"{WHITE}Please run this script as an Administrator.{RESET}")
            elif self.current_os in ["linux", "macos"]: print(f"{WHITE}Please run this script with sudo.{RESET}")
            return # Exit function

        original_settings = self.load_original_dns_settings()
        # load_original_dns_settings already filters by current OS and handles file not found

        if not original_settings:
            print(f"{RED}Exiting Restoration Process: No original settings found for {self.current_os} in {self.ORIGINAL_DNS_CONFIG_FILE}.{RESET}")
            return # Exit function

        restored_ok = False
        if self.current_os == "windows":
            restored_ok = self._restore_dns_windows(original_settings)
            # Add Windows-specific settings restoration from run-dns-scripts.bat/restore-dns-settings.ps1 if needed
            # Re-enable IPv6 binding, Remove DoH/Random Name Resolution registry keys (based on PS scripts)
            if restored_ok and self.current_os == "windows" and self.check_privileges(): # Re-check privileges before system-wide settings
                 print(f"{BLUE}\nRestoring additional Windows network settings...{RESET}")
                 try:
                    # Enable IPv6 binding on active adapters (Caution: this is system-wide)
                    # Finding active adapters again...
                    interfaces_result = subprocess.run(["netsh", "interface", "show", "interface"], capture_output=True, text=True, check=True, shell=True)
                    active_interfaces_names = [
                        " ".join(line.split()[3:]) for line in interfaces_result.stdout.strip().split('\n')[2:]
                        if len(line.split()) >= 4 and line.split()[0] == "Enabled" and line.split()[1] == "Connected"
                    ]
                    for if_name in active_interfaces_names:
                         print(f"{BLUE}Windows: Enabling IPv6 binding for \'{if_name}\'...{RESET}")
                         # netsh interface ipv6 set interface \"Interface Name\" enabled
                         cmd_enable_ipv6 = ["netsh", "interface", "ipv6", "set", "interface", f"name=\"{if_name}\", enabled"]
                         try:
                             subprocess.run(cmd_enable_ipv6, check=True, capture_output=True, text=True, shell=True)
                             print(f"{GREEN}Windows: IPv6 binding enabled for \'{if_name}\'.{RESET}")
                         except Exception as ipv6_e:
                             print(f"{YELLOW}Windows: Warning: Could not enable IPv6 binding for \'{if_name}\': {ipv6_e}{RESET}")

                    # Remove DoH and Random Name Resolution Registry Keys (Mirroring PS script)
                    print(f"{BLUE}Windows: Restoring default DoH and Random Name Resolution via Registry...{RESET}")
                    try:
                        # Use \'reg delete\' to remove the keys set previously.
                        # /f forces deletion without prompt.
                        subprocess.run(["reg", "delete", "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\Dnscache\\\\Parameters", "/v", "EnableAutoDOH", "/f"], check=False, capture_output=True, text=True, shell=True) # Use check=False as key might not exist
                        print(f"{GREEN}Windows: Removed automatic DoH registry setting.{RESET}")
                    except Exception as doh_e:
                        print(f"{YELLOW}Windows: Warning: Could not remove automatic DoH registry setting: {doh_e}{RESET}")

                    try:
                        subprocess.run(["reg", "delete", "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\Dnscache\\\\Parameters", "/v", "QueryIpMatching", "/f"], check=False, capture_output=True, text=True, shell=True) # Use check=False as key might not exist
                        print(f"{GREEN}Windows: Removed Random Name Resolution registry setting.{RESET}")
                    except Exception as random_e:
                        print(f"{YELLOW}Windows: Warning: Could not remove Random Name Resolution registry setting: {random_e}{RESET}")

                    # The PS script also restarts the Dnscache service. Let\'s add that.
                    print(f"{BLUE}Windows: Restarting Dnscache service...{RESET}")
                    try:
                        # Needs admin privileges. Assumed by the outer check.
                        subprocess.run(["net", "stop", "Dnscache"], check=False, capture_output=True, text=True, shell=True) # Stop it first, ignore errors if not running
                        subprocess.run(["net", "start", "Dnscache"], check=True, capture_output=True, text=True, shell=True) # Start it, check for errors
                        print(f"{GREEN}Windows: Dnscache service restarted.{RESET}")
                    except Exception as service_e:
                         print(f"{YELLOW}Windows: Warning: Could not restart Dnscache service: {service_e}{RESET}")


                 except Exception as win_extra_e:
                    print(f"Windows: An error occurred restoring extra Windows settings: {win_extra_e}")


        elif self.current_os == "linux":
            restored_ok = self._restore_dns_linux(original_settings)
            # Note: Linux specific restoration logic already included within _restore_dns_linux

        elif self.current_os == "macos":
            restored_ok = self._restore_dns_macos(original_settings)
            # Note: macOS specific restoration logic already included within _restore_dns_macos

        else:
            print(f"{RED}Restoration not supported for unknown OS: {self.current_os}{RESET}")
            return # Exit function

        if restored_ok:
            print(f"{GREEN}\nDNS settings restoration attempt completed.{RESET}")
            try:
                # Only remove the file if restoration was reported as successful
                os.remove(self.ORIGINAL_DNS_CONFIG_FILE)
                print(f"{GREEN}Removed original DNS settings file: {self.ORIGINAL_DNS_CONFIG_FILE}{RESET}")
            except OSError as e:
                print(f"{YELLOW}Warning: Could not remove original DNS settings file {self.ORIGINAL_DNS_CONFIG_FILE}: {e}{RESET}")
            except Exception as e_gen:
                 print(f"{RED}Unexpected error removing file {self.ORIGINAL_DNS_CONFIG_FILE}: {e_gen}{RESET}")
        else:
            print(f"{RED}\nDNS restoration encountered errors. Original settings file preserved if it exists.{RESET}")
            print(f"{WHITE}Please check the logs above and manually verify your DNS settings.{RESET}")

        self.flush_dns() # Attempt to flush DNS after restoration as well

    def run_verify_dns_flow(self):
        """
        Provides a simple verification of current DNS settings.
        This is a placeholder; actual verification would involve
        checking active adapter settings and potentially resolving a domain.
        """
        print(f"{CYAN}\n--- Verify DNS Settings ---{RESET}")
        print(f"{WHITE}Note: This is a basic check.{RESET}")
        print(f"{WHITE}To verify, you can:{RESET}")
        print(f"{WHITE}1. Check your network adapter settings via the OS network configuration.{RESET}")
        print(f"{WHITE}2. Use command-line tools like 'nslookup google.com', 'dig google.com', or 'Resolve-DnsName google.com' (Windows).{RESET}")
        print(f"{BLUE}\nAttempting to retrieve current DNS settings for {self.current_os}...{RESET}")
        settings = None
        if self.current_os == "windows":
            settings = self._get_current_dns_windows()
        elif self.current_os == "linux":
            settings = self._get_current_dns_linux()
        elif self.current_os == "macos":
            settings = self._get_current_dns_macos()
        else:
            print(f"{YELLOW}Cannot retrieve current DNS for unknown OS: {self.current_os}{RESET}")
            return

        if settings:
            print(f"{BLUE}\nCurrent DNS settings (from script's retrieval attempt):{RESET}")
            for iface, config in settings.items():
                method = config.get("method", "unknown")
                if config.get("dhcp"):
                     print(f"{WHITE}  Interface/Service \'{iface}\' (Method: {method}): DHCP managed. Servers found: {config['servers'] if config['servers'] else 'None'}{RESET}")
                else:
                     print(f"{WHITE}  Interface/Service \'{iface}\' (Method: {method}): Static. Servers: {config['servers']}{RESET}")
        else:
            print(f"{YELLOW}\nCould not retrieve current DNS settings using known methods.{RESET}")


        # Add a simple ping test for verification
        try:
            print(f"{BLUE}\nAttempting to ping google.com...{RESET}")
            # Use subprocess.run with timeout to avoid hanging
            # -c 1 for linux/macos, -n 1 for windows
            ping_cmd = []
            if self.current_os == "windows":
                ping_cmd = ["ping", "-n", "1", "google.com"]
            elif self.current_os in ["linux", "macos"]:
                ping_cmd = ["ping", "-c", "1", "google.com"]

            if ping_cmd:
                ping_result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=5) # 5 second timeout
                if ping_result.returncode == 0:
                    print(f"{GREEN}Ping to google.com successful. DNS is likely working.{RESET}")
                else:
                    print(f"{YELLOW}Ping to google.com failed (Return Code {ping_result.returncode}). DNS might not be working correctly.{RESET}")
                    # print(f"{WHITE}Ping Output:\n{ping_result.stdout}\n{ping_result.stderr}{RESET}") # Optional: print ping details
            else:
                 print(f"{YELLOW}Ping not supported for OS: {self.current_os}{RESET}")


        except FileNotFoundError:
             print(f"{RED}Ping command not found.{RESET}")
        except subprocess.TimeoutExpired:
             print(f"{RED}Ping command timed out.{RESET}")
        except Exception as ping_e:
             print(f"{RED}An error occurred during ping test: {ping_e}{RESET}")

        print(f"{CYAN}\n--- Verification Complete ---{RESET}")


    # --- Terminal Menu ---
    def run_terminal_menu(self):
        """Runs the interactive terminal menu."""
        while True:
            print(f"{CYAN}\n" + "="*40 + RESET)
            print(f"{CYAN}  Cross-Platform DNS Setter{RESET}")
            print(f"{CYAN}" + "="*40 + RESET)
            print(f"{BLUE}Current OS: {self.current_os.capitalize()}{RESET}")
            print(f"{WHITE}-" * 40 + RESET)
            print(f"{WHITE}1. Set Custom DNS Servers (using first entry from {self.DNS_CONFIG_FILE}){RESET}")
            print(f"{WHITE}2. Select DNS by Provider (from {self.DNS_CONFIG_FILE}){RESET}")
            print(f"{WHITE}3. Restore Original DNS Settings (from {self.ORIGINAL_DNS_CONFIG_FILE} backup){RESET}")
            print(f"{WHITE}4. Verify Current DNS Settings (Basic Check){RESET}")
            print(f"{WHITE}5. Open Web GUI{RESET}")
            print(f"{WHITE}6. Download DNS Config from GitHub{RESET}")
            print(f"{WHITE}7. Benchmark DNS Providers (Test Speed on URLs){RESET}")
            print(f"{WHITE}8. Exit{RESET}")
            print(f"{WHITE}-" * 40 + RESET)

            choice = input(f"{CYAN}Enter your choice (1-8): {RESET}").strip()
            print(f"{WHITE}-" * 40 + RESET)

            if choice == '1':
                self.run_set_dns_flow()
            elif choice == '2':
                self.run_select_dns_by_provider_flow()
            elif choice == '3':
                self.run_restore_dns_flow()
            elif choice == '4':
                self.run_verify_dns_flow()
            elif choice == '5':
                print(f"{BLUE}\\nLaunching Web GUI...{RESET}")
                try:
                    from dns_web_gui import app
                    print(f"{GREEN}Web GUI started at http://localhost:8080{RESET}")
                    print(f"{WHITE}Access the interface in your web browser{RESET}")
                    print(f"{WHITE}Press Ctrl+C to stop the server and return to menu{RESET}")
                    app.run(host='0.0.0.0', port=8080)
                except ImportError:
                    print(f"{RED}Error: Flask not installed. Please install it with: pip install flask{RESET}")
                except Exception as e:
                    print(f"{RED}Error starting web GUI: {e}{RESET}")
            elif choice == '6':
                self.download_dns_config_from_github()
            elif choice == '7':
                self.benchmark_dns_providers()
            elif choice == '8':
                print(f"{CYAN}Exiting...{RESET}")
                break
            else:
                print(f"{RED}\nInvalid choice. Please enter a number between 1 and 8.{RESET}")

            input(f"{WHITE}\nPress Enter to continue...{RESET}") # Pause before showing menu again

    def download_dns_config_from_github(self):
        """
        Downloads the DNS config file from a specified GitHub URL and overwrites the local DNS config file.
        """
        import urllib.request

        github_url = "https://raw.githubusercontent.com/ALIILAPRO/dns-changer/refs/heads/master/config/dns.txt"
        print(f"{CYAN}Downloading DNS config from GitHub...{RESET}")
        try:
            response = urllib.request.urlopen(github_url, timeout=10)
            content = response.read().decode("utf-8")
            with open(self.DNS_CONFIG_FILE, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"{GREEN}DNS config successfully downloaded and updated from GitHub!{RESET}")
        except Exception as e:
            print(f"{RED}Failed to download DNS config: {e}{RESET}")


if __name__ == "__main__":
    # The main execution block now runs the terminal menu.
    # Command-line argument parsing (like --restore) is removed.
    dns_manager = DnsManager()
    dns_manager.run_terminal_menu()
