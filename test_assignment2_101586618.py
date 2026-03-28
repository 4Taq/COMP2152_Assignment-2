"""
Unit Tests for Assignment 2 — Port Scanner
"""

import unittest
from assignment2_101586618 import PortScanner, common_ports



class TestPortScanner(unittest.TestCase):

    def test_scanner_initialization(self):
        """Test that PortScanner initializes with correct target and empty results list."""
        scanner = PortScanner("127.0.0.1")
        self.assertEqual(scanner.target, "127.0.0.1")
        self.assertEqual(scanner.scan_results, [])
        

    def test_get_open_ports_filters_correctly(self):
        """Test that get_open_ports returns only Open ports."""
        scanner = PortScanner("127.0.0.1")
        scanner.scan_results = [
            (22, "Open", "SSH"),
            (23, "Closed", "Telnet"),
            (80, "Open", "HTTP")
        ]
        
        open_ports = scanner.get_open_ports()
        self.assertEqual(len(open_ports), 2)
        ports = [row[0] for row in open_ports]

        self.assertIn(22, ports)
        self.assertIn(80, ports)
        self.assertNotIn(23, ports)



    def test_common_ports_dict(self):
        """Test that common_ports dictionary has correct entries."""
        self.assertEqual(common_ports[80], "HTTP")
        self.assertEqual(common_ports[22], "SSH")
        self.assertEqual(common_ports[443], "HTTPS")
        self.assertEqual(common_ports[21], "FTP")
        

    def test_invalid_target(self):
        """Test that setter rejects empty string target."""
        scanner = PortScanner("127.0.0.1")
        original_target = scanner.target
        
        try:
            scanner.target = ""
        except:
            pass
        
        self.assertEqual(scanner.target, original_target)
        self.assertEqual(scanner.target, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
