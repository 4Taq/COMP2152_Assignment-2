"""
Author: Taha Rahimi Monfared
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading as th
import sqlite3
import os
import platform as plat
import datetime


print("^" * 70)
print("OS: ",plat.python_version())
print("Python version: ", os.name)
print("^" * 70)

# stores commonly used/attacked ports
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    def __init__(self, string):
        self.__target = string

    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, string):
        if string and string.strip():
            self.__target = string
        else:
            raise print("error: target cannot be empty")

    def __del__(self):
        print("networkTool instance destroyed")


# Q3: What is the benefit of using @property and @target.setter?
# take a function as input to modify or enhance its behaviour


# Q1: How does PortScanner reuse code from NetworkTool?
# implemets target method from parent to store a string value to later be used as a target
 


class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = th.Lock()

    def __del__(self):
        print("portScanner instance destroyed")
        super().__del__()

    #  Q4: What would happen without try-except here?
    #  any error from the OS subsystem will halt the scanning process if not handled

    def scan_port(self, port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.0)
                result = sock.connect_ex((self.target, port))
    
                if result == 0:
                    state = "Open"
                else:
                    state = "Closed"

            if port in common_ports:
                service = common_ports[port]
            else:
                service = "Unknown"

            with self.lock:
                self.scan_results.append((port, state, service))

        except OSError as e:
            with self.lock:
                self.scan_results.append((port, "Error", f"({e})"))

    def get_open_ports(self):
        result = [row for row in self.scan_results if row[1] != "Closed"]
        return result

    #  Q2: Why do we use threading instead of scanning one port at a time?
    #  concurrency of scans 

    def scan_range(self, start_port, end_port):
        threads = []
        for p in range(start_port, end_port):
            t = th.Thread(target=self.scan_port, args=(p,))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()


def save_results(target: str, results: list):
    try:
        with sqlite3.connect('scan_history.db') as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    status TEXT,
                    service TEXT,
                    scan_date TEXT NOT NULL
                )
            """)

            # now = datetime.datetime.now(datetime.UTC)
            now = datetime.datetime.now(datetime.UTC).isoformat()
            insert_data = []
            for result in results:
                if len(result) >= 3:
                    port, status, service = result[:3]
                else:
                    continue 

                insert_data.append((
                    target,
                    int(port),
                    status,
                    service,
                    now
                ))

            if insert_data:
                cursor.executemany(""" INSERT INTO scans (target, port, status,
                service, scan_date) VALUES (?, ?, ?, ?, ?) """, insert_data)
                conn.commit()
                print(f"saved {len(insert_data)} results for {target}")
            else:
                print("no valid results to save")

    except sqlite3.Error as e:
        print(f"database error: {e}")
        raise


def load_past_scans():
    try:
        with sqlite3.connect('scan_history.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
            if not cursor.fetchone():
                print("no past scans found.")
                return

            cursor.execute("""
                SELECT target, port, status, service, scan_date
                FROM scans
                ORDER BY scan_date DESC, target, port
            """)
            rows = cursor.fetchall()
            if not rows:
                print("no past scans found.")
                return

            print("past scans history")
            print("-" * 70)
            print(f"{'Target':<18} {'Port':<6} {'Status':<8} {'Service':<12} {'Date':<20}")
            print("-" * 70)

            for row in rows:
                target, port, status, service, date = row

                print(f"{target:<18} {port:<6} {status:<8} {service:<12} {date}")

            print("-" * 70)
            print(f"total records: {len(rows)}")

    except sqlite3.Error as e:
        print(f"database error: {e}")
        print("no past scans found, database access failed")

# ============================================================
# MAIN PROGRAM
# ============================================================


if __name__ == "__main__":
    try:
        # take user input
        target = str(input("enter target address [empty for default]: ")) or "127.0.0.1"
        start_p = int(input("enter starting port: "))
        end_p = int(input("enter endign port: "))
        while start_p <= 0:
            start_p = int(input("start port should be batween 1-1024: "))
        while end_p > 1024:
            end_p = int(input("end port should be between 1-1024: "))

        # init scan
        sc = PortScanner(target)

        print("=" * 50)
        print(f"Scannign {target} from port {start_p} to {end_p}")

        sc.scan_range(start_p, end_p)
        
        open_ports = sc.get_open_ports()
        rows = sc.scan_results

        # print results
        print(f"{'Port':<6} {'Status':<8} {'Service':<12}")
        print("-" * 70)
        for row in rows:
            p, s, svc = row
            print(f"{p:<6} {s:<8} {svc:<12}")
        print("-" * 70)
        print(f"total open ports = {len(open_ports)}")
        print("-" * 70)
        
        # save results
        save_results(target, sc.scan_results)

        print("-" * 70)

        answer = str(input("would you like to see past scan history? (yes/no): "))
        
        if answer == "yes":
            load_past_scans()

    except ValueError as e:
        print("invalid input.", e)
        
    except KeyboardInterrupt as e:
        print(e)

    except NameError:
        raise NameError

# Q5: New Feature Proposal 
# introduce option to scan all ports without specifying range
