import unittest
import os
import shutil
import platform
from unittest.mock import patch 

# Add the parent directory to sys.path to allow importing set_dns_crossplatform
import sys
# Assuming test_set_dns_crossplatform.py is in the same directory as set_dns_crossplatform.py
# If it's in a subdirectory, adjust the path accordingly.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

try:
    import set_dns_crossplatform
except ModuleNotFoundError:
    print("ERROR: Could not import set_dns_crossplatform.py. Make sure it's in the same directory or PYTHONPATH is set correctly.")
    sys.exit(1)


class TestDnsScript(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory for test files
        self.test_dir = "temp_test_dns_config"
        os.makedirs(self.test_dir, exist_ok=True)
        self.dummy_conf_path = os.path.join(self.test_dir, "dnsConf.txt")

    def tearDown(self):
        # Remove the temporary directory and its contents
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def write_dummy_config(self, content):
        with open(self.dummy_conf_path, 'w') as f:
            f.write(content)

    # --- Tests for get_os ---
    def test_get_os_windows(self):
        self.assertEqual(set_dns_crossplatform.get_os(test_platform_system="Windows"), "windows")
        self.assertEqual(set_dns_crossplatform.get_os(test_platform_system="Win32NT"), "windows")

    def test_get_os_linux(self):
        self.assertEqual(set_dns_crossplatform.get_os(test_platform_system="Linux"), "linux")

    def test_get_os_macos(self):
        self.assertEqual(set_dns_crossplatform.get_os(test_platform_system="Darwin"), "macos")

    def test_get_os_unknown(self):
        self.assertEqual(set_dns_crossplatform.get_os(test_platform_system="SunOS"), "unknown")
        self.assertEqual(set_dns_crossplatform.get_os(test_platform_system="FreeBSD"), "unknown")
    
    # To test the actual platform.system() call if no argument is passed (optional, less controlled)
    @patch('platform.system')
    def test_get_os_mocked_current_platform(self, mock_system):
        mock_system.return_value = "Linux"
        self.assertEqual(set_dns_crossplatform.get_os(), "linux")
        mock_system.return_value = "Windows"
        self.assertEqual(set_dns_crossplatform.get_os(), "windows")
        mock_system.return_value = "Darwin"
        self.assertEqual(set_dns_crossplatform.get_os(), "macos")


    # --- Tests for parse_dns_config ---
    def test_parse_valid_config_less_than_3_ips(self):
        content = "GoogleDNS1=8.8.8.8\nCloudflareDNS=1.1.1.1\n"
        self.write_dummy_config(content)
        expected = ["8.8.8.8", "1.1.1.1"]
        self.assertEqual(set_dns_crossplatform.parse_dns_config(self.dummy_conf_path), expected)

    def test_parse_valid_config_exactly_3_ips(self):
        content = "DNS1=8.8.8.8\nDNS2=1.1.1.1\nDNS3=9.9.9.9\n"
        self.write_dummy_config(content)
        expected = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        self.assertEqual(set_dns_crossplatform.parse_dns_config(self.dummy_conf_path), expected)

    def test_parse_valid_config_more_than_3_ips(self):
        content = "DNS1=8.8.8.8\nDNS2=1.1.1.1\nDNS3=9.9.9.9\nDNS4=4.4.4.4\n"
        self.write_dummy_config(content)
        expected = ["8.8.8.8", "1.1.1.1", "9.9.9.9"] # Should only take the first 3
        self.assertEqual(set_dns_crossplatform.parse_dns_config(self.dummy_conf_path), expected)

    def test_parse_config_with_comments_and_empty_lines(self):
        content = "# This is a comment\nGoogleDNS1=8.8.8.8\n\nCloudflareDNS=1.1.1.1\n#AnotherComment\n\n"
        self.write_dummy_config(content)
        expected = ["8.8.8.8", "1.1.1.1"]
        self.assertEqual(set_dns_crossplatform.parse_dns_config(self.dummy_conf_path), expected)

    def test_parse_empty_config_file(self):
        content = ""
        self.write_dummy_config(content)
        # Expect None because the file is empty, and parse_dns_config prints an error
        self.assertIsNone(set_dns_crossplatform.parse_dns_config(self.dummy_conf_path))

    def test_parse_config_file_with_only_comments_or_empty_lines(self):
        content = "# Comment 1\n\n# Comment 2\n   \n"
        self.write_dummy_config(content)
        # Expect None because no valid DNS entries are found
        self.assertIsNone(set_dns_crossplatform.parse_dns_config(self.dummy_conf_path))

    def test_parse_config_malformed_entries_no_equals(self):
        content = "GoogleDNS18.8.8.8\nCloudflareDNS=1.1.1.1\n" # First entry malformed
        self.write_dummy_config(content)
        expected = ["1.1.1.1"] # Should skip the malformed one
        self.assertEqual(set_dns_crossplatform.parse_dns_config(self.dummy_conf_path), expected)

    def test_parse_config_malformed_entries_invalid_ip(self):
        content = "GoogleDNS1=8.8.8.256\nCloudflareDNS=1.1.1.1\nAnotherInvalid=123.456.789\nDNS3=9.9.9.9"
        self.write_dummy_config(content)
        expected = ["1.1.1.1", "9.9.9.9"] # Should skip invalid IPs
        self.assertEqual(set_dns_crossplatform.parse_dns_config(self.dummy_conf_path), expected)
    
    def test_parse_config_all_malformed_or_invalid(self):
        content = "GoogleDNS1=8.8.8.256\nNoEqualsHere\nInvalidIP=1.2.3.4.5\n"
        self.write_dummy_config(content)
        self.assertIsNone(set_dns_crossplatform.parse_dns_config(self.dummy_conf_path))


    def test_parse_non_existent_config_file(self):
        non_existent_path = os.path.join(self.test_dir, "non_existent_conf.txt")
        self.assertIsNone(set_dns_crossplatform.parse_dns_config(non_existent_path))

    # --- is_valid_ip tests (already implicitly tested by parse_dns_config tests, but can be explicit) ---
    def test_is_valid_ip_true(self):
        self.assertTrue(set_dns_crossplatform.is_valid_ip("8.8.8.8"))
        self.assertTrue(set_dns_crossplatform.is_valid_ip("192.168.0.1"))
        self.assertTrue(set_dns_crossplatform.is_valid_ip("0.0.0.0"))
        self.assertTrue(set_dns_crossplatform.is_valid_ip("255.255.255.255"))

    def test_is_valid_ip_false(self):
        self.assertFalse(set_dns_crossplatform.is_valid_ip("8.8.8.256"))
        self.assertFalse(set_dns_crossplatform.is_valid_ip("192.168.0"))
        self.assertFalse(set_dns_crossplatform.is_valid_ip("1.1.1.1.1"))
        self.assertFalse(set_dns_crossplatform.is_valid_ip("abc.def.ghi.jkl"))
        self.assertFalse(set_dns_crossplatform.is_valid_ip("8.8.8"))
        self.assertFalse(set_dns_crossplatform.is_valid_ip("8.8.8.8."))
        self.assertFalse(set_dns_crossplatform.is_valid_ip(""))


    # --- Tests for set_dns_windows ---
    @patch('set_dns_crossplatform.subprocess.run')
    @patch('set_dns_crossplatform.get_os', return_value='windows')
    def test_set_dns_windows_one_server(self, mock_get_os, mock_subprocess_run):
        # Mock subprocess.run for 'netsh interface show interface'
        show_interface_output = """
Admin State    State          Type             Interface Name
-------------------------------------------------------------------------
Enabled        Connected      Dedicated        Ethernet
"""
        mock_show_interface_result = unittest.mock.Mock()
        mock_show_interface_result.returncode = 0
        mock_show_interface_result.stdout = show_interface_output
        mock_show_interface_result.stderr = ""

        # Mock subprocess.run for the 'netsh set dnsserver' calls
        mock_set_dns_result = unittest.mock.Mock()
        mock_set_dns_result.returncode = 0
        mock_set_dns_result.stdout = ""
        mock_set_dns_result.stderr = ""

        # Set up the side_effect for subprocess.run
        mock_subprocess_run.side_effect = [
            mock_show_interface_result,  # First call: show interfaces
            mock_set_dns_result          # Second call: set primary DNS
        ]

        dns_servers = ["8.8.8.8"]
        result = set_dns_crossplatform.set_dns_windows(dns_servers)

        self.assertTrue(result) # Should return True because setting succeeded for at least one interface

        # Assert calls to subprocess.run
        mock_subprocess_run.assert_has_calls([
            unittest.mock.call(["netsh", "interface", "show", "interface"], capture_output=True, text=True, check=True, shell=True),
            unittest.mock.call(["netsh", "interface", "ipv4", "set", "dnsserver", 'name="Ethernet"', 'static', 'addr="8.8.8.8"', 'validate=no'], capture_output=True, text=True, check=True, shell=True),
        ])
        self.assertEqual(mock_subprocess_run.call_count, 2) # Ensure no extra calls were made

    @patch('set_dns_crossplatform.subprocess.run')
    @patch('set_dns_crossplatform.get_os', return_value='windows')
    def test_set_dns_windows_three_servers(self, mock_get_os, mock_subprocess_run):
        # Mock subprocess.run for 'netsh interface show interface'
        show_interface_output = """
Admin State    State          Type             Interface Name
-------------------------------------------------------------------------
Enabled        Connected      Dedicated        Ethernet
"""
        mock_show_interface_result = unittest.mock.Mock()
        mock_show_interface_result.returncode = 0
        mock_show_interface_result.stdout = show_interface_output
        mock_show_interface_result.stderr = ""

        # Mock subprocess.run for the 'netsh set/add dnsserver' calls
        mock_dns_command_result = unittest.mock.Mock()
        mock_dns_command_result.returncode = 0
        mock_dns_command_result.stdout = ""
        mock_dns_command_result.stderr = ""

        # Set up the side_effect for subprocess.run
        # First call: show interfaces
        # Second call: set primary DNS
        # Third call: add secondary DNS
        # Fourth call: add tertiary DNS
        mock_subprocess_run.side_effect = [
            mock_show_interface_result,
            mock_dns_command_result,
            mock_dns_command_result,
            mock_dns_command_result,
        ]

        dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        result = set_dns_crossplatform.set_dns_windows(dns_servers)

        self.assertTrue(result)

        # Assert calls to subprocess.run
        mock_subprocess_run.assert_has_calls([
            unittest.mock.call(["netsh", "interface", "show", "interface"], capture_output=True, text=True, check=True, shell=True),
            unittest.mock.call(["netsh", "interface", "ipv4", "set", "dnsserver", 'name="Ethernet"', 'static', 'addr="8.8.8.8"', 'validate=no'], capture_output=True, text=True, check=True, shell=True),
            unittest.mock.call(["netsh", "interface", "ipv4", "add", "dnsserver", 'name="Ethernet"', 'addr="1.1.1.1"', 'index=2', 'validate=no'], capture_output=True, text=True, check=True, shell=True),
            unittest.mock.call(["netsh", "interface", "ipv4", "add", "dnsserver", 'name="Ethernet"', 'addr="9.9.9.9"', 'index=3', 'validate=no'], capture_output=True, text=True, check=True, shell=True),
        ])
        self.assertEqual(mock_subprocess_run.call_count, 4)

    @patch('set_dns_crossplatform.subprocess.run')
    @patch('set_dns_crossplatform.get_os', return_value='windows')
    def test_set_dns_windows_no_active_interfaces(self, mock_get_os, mock_subprocess_run):
        # Mock subprocess.run for 'netsh interface show interface' to return no active interfaces
        show_interface_output = """
Admin State    State          Type             Interface Name
-------------------------------------------------------------------------
Enabled        Disconnected   Dedicated        Wi-Fi
Disabled       Connected      Dedicated        Ethernet
""" # No interfaces with both Enabled and Connected
        mock_show_interface_result = unittest.mock.Mock()
        mock_show_interface_result.returncode = 0
        mock_show_interface_result.stdout = show_interface_output
        mock_show_interface_result.stderr = ""

        # Set up the side_effect for subprocess.run
        mock_subprocess_run.side_effect = [
            mock_show_interface_result,  # First call: show interfaces
        ]

        dns_servers = ["8.8.8.8"]
        result = set_dns_crossplatform.set_dns_windows(dns_servers)

        self.assertFalse(result) # Should return False as no interfaces were configured

        # Assert calls to subprocess.run
        mock_subprocess_run.assert_called_once_with(
            ["netsh", "interface", "show", "interface"],
            capture_output=True, text=True, check=True, shell=True
        )

    @patch('set_dns_crossplatform.subprocess.run')
    @patch('set_dns_crossplatform.get_os', return_value='windows')
    def test_set_dns_windows_netsh_error_listing_interfaces(self, mock_get_os, mock_subprocess_run):
         # Mock subprocess.run for 'netsh interface show interface' to raise an error
        mock_show_interface_error = subprocess.CalledProcessError(1, ["netsh", "interface", "show", "interface"], stderr="Error showing interfaces")

        # Set up the side_effect for subprocess.run
        mock_subprocess_run.side_effect = [
            mock_show_interface_error, # First call: show interfaces fails
        ]

        dns_servers = ["8.8.8.8"]
        result = set_dns_crossplatform.set_dns_windows(dns_servers)

        self.assertFalse(result) # Should return False on error

        # Assert calls to subprocess.run
        mock_subprocess_run.assert_called_once_with(
            ["netsh", "interface", "show", "interface"],
            capture_output=True, text=True, check=True, shell=True
        )


    # --- Tests for restore_dns_windows ---
    @patch('set_dns_crossplatform.subprocess.run')
    @patch('set_dns_crossplatform.get_os', return_value='windows')
    def test_restore_dns_windows_dhcp(self, mock_get_os, mock_subprocess_run):
        settings = {
            "Ethernet": {"servers": [], "dhcp": True, "method": "netsh"}
        }

        # Mock subprocess.run for the 'netsh set source=dhcp' call
        mock_dhcp_command_result = unittest.mock.Mock()
        mock_dhcp_command_result.returncode = 0
        mock_dhcp_command_result.stdout = ""
        mock_dhcp_command_result.stderr = ""

        mock_subprocess_run.side_effect = [mock_dhcp_command_result] # Only one call expected

        result = set_dns_crossplatform.restore_dns_windows(settings)

        self.assertTrue(result)

        # Assert call to subprocess.run
        mock_subprocess_run.assert_called_once_with(
             ["netsh", "interface", "ipv4", "set", "dnsservers", 'name="Ethernet"', "source=dhcp"],
             capture_output=True, text=True, check=True, shell=True
        )

    @patch('set_dns_crossplatform.subprocess.run')
    @patch('set_dns_crossplatform.get_os', return_value='windows')
    def test_restore_dns_windows_static_two_servers(self, mock_get_os, mock_subprocess_run):
        settings = {
            "Ethernet": {"servers": ["10.104.88.8", "10.104.88.9"], "dhcp": False, "method": "netsh"}
        }

        # Mock subprocess.run for the 'netsh set/add dnsserver' calls
        mock_dns_command_result = unittest.mock.Mock()
        mock_dns_command_result.returncode = 0
        mock_dns_command_result.stdout = ""
        mock_dns_command_result.stderr = ""

        # First call: set primary DNS
        # Second call: add secondary DNS
        mock_subprocess_run.side_effect = [
            mock_dns_command_result,
            mock_dns_command_result,
        ]

        result = set_dns_crossplatform.restore_dns_windows(settings)

        self.assertTrue(result)

        # Assert calls to subprocess.run
        mock_subprocess_run.assert_has_calls([
            unittest.mock.call(["netsh", "interface", "ipv4", "set", "dnsserver", 'name="Ethernet"', 'static', 'addr="10.104.88.8"', 'validate=no'], capture_output=True, text=True, check=True, shell=True),
            unittest.mock.call(["netsh", "interface", "ipv4", "add", "dnsserver", 'name="Ethernet"', 'addr="10.104.88.9"', 'index=2', 'validate=no'], capture_output=True, text=True, check=True, shell=True),
        ])
        self.assertEqual(mock_subprocess_run.call_count, 2) # Ensure no extra calls were made

    @patch('set_dns_crossplatform.subprocess.run')
    @patch('set_dns_crossplatform.get_os', return_value='windows')
    def test_restore_dns_windows_netsh_error_setting_dns(self, mock_get_os, mock_subprocess_run):
        settings = {
            "Ethernet": {"servers": ["8.8.8.8"], "dhcp": False, "method": "netsh"}
        }

        # Mock subprocess.run for the 'netsh set dnsserver' call to raise an error
        mock_set_dns_error = subprocess.CalledProcessError(1, ["netsh", "interface", "ipv4", "set", "dnsserver", 'name="Ethernet"', 'static', 'addr="8.8.8.8"', 'validate=no'], stderr="Error setting DNS")

        mock_subprocess_run.side_effect = [mock_set_dns_error]

        result = set_dns_crossplatform.restore_dns_windows(settings)

        self.assertFalse(result) # Should return False on error for that interface

        # Assert call to subprocess.run
        mock_subprocess_run.assert_called_once_with(
             ["netsh", "interface", "ipv4", "set", "dnsserver", 'name="Ethernet"', 'static', 'addr="8.8.8.8"', 'validate=no'],
             capture_output=True, text=True, check=True, shell=True
        )


if __name__ == '__main__':
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
