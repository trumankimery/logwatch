#!/usr/bin/env python3
"""
logwatch.py — A cross-platform CLI tool to scan and monitor log files for suspicious entries.

Features:
---------
- Performs an initial full scan of a log file for lines containing keywords.
- Optionally writes matched lines from the initial scan to a report file.
- Enters a live-monitoring mode (tail-like) and prints any new matching lines.
- Automatically detects log rotation and resumes watching (works on Linux, macOS, and Windows).
- Can trigger native desktop notifications on matches (optional).

Usage:
------
    python logwatch.py /var/log/auth.log "failed login" "invalid user" --initial-report --alert

Arguments:
----------
    file (str): Path to the log file to monitor.
    keywords (str...): One or more keywords to search for in the log lines.

Optional Flags:
---------------
    -i, --ignore-case         : Perform case-insensitive matching.
    --initial-report          : Run a one-time scan of the full file before live monitoring.
    --report-file <filename>  : Save the results of the initial scan to this file.
    --alert                   : Trigger desktop notification on new matching lines (requires `plyer`).

Dependencies:
-------------
    - plyer (optional, only needed for desktop notifications)
      Install with: pip install plyer

Author:
-------
    Truman Kimery
"""

import re
import time
import argparse
from pathlib import Path
import os  # Needed for SEEK_END and fstat()

try:
    from plyer import notification
except ImportError:
    notification = None


def scan_initial_log(file_path, pattern, report_file=None):
    """
    Perform a one-time full scan of the log file and report lines matching the keyword pattern.

    Args:
        file_path (str): Path to the log file to scan.
        pattern (re.Pattern): Compiled regex pattern to search for in each line.
        report_file (str, optional): If provided, matched lines are written to this file.

    Raises:
        FileNotFoundError: If the log file does not exist.
        PermissionError: If access to the file is denied.
    """
    print("[*] Running initial log scan...")
    matches = []
    log_path = Path(file_path)

    try:
        with log_path.open("r") as f:
            for line in f:
                if pattern.search(line):
                    matches.append(line)
                    print(line, end="")

        if report_file:
            report_path = Path(report_file)
            with report_path.open("w") as out:
                out.writelines(matches)
            print(f"[+] Report written to {report_file}")

    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied reading file: {file_path}")
        exit(1)


def watch_log(file_path, pattern, alert=False):
    """
    Continuously monitor a log file for new lines matching a regex pattern.

    Automatically detects log rotation (via inode or mtime/size checks)
    and reopens the file to resume monitoring.

    Args:
        file_path (str): Path to the log file to monitor.
        pattern (re.Pattern): Compiled regex pattern to search for in new lines.
        alert (bool): If True, trigger a desktop notification on matching lines.

    Raises:
        FileNotFoundError: If the file does not exist when starting.
        PermissionError: If read permissions are denied.
    """
    log_path = Path(file_path)

    def open_log():
        """
        Open the log file for reading and seek to the end.

        Returns:
            Tuple[file, int|None, float, int]: The file object, inode (if available),
                                               modification time, and size.
        """
        print("[*] Running Ongoing log scan...")
        f = log_path.open("r")
        f.seek(0, os.SEEK_END)
        stat = os.fstat(f.fileno())
        inode = getattr(stat, "st_ino", None)
        mtime = log_path.stat().st_mtime
        size = log_path.stat().st_size
        return f, inode, mtime, size

    try:
        f, last_inode, last_mtime, last_size = open_log()
        with f:
            while True:
                line = f.readline()

                if not line:
                    time.sleep(0.1)
                    try:
                        stat = log_path.stat()
                        current_inode = getattr(stat, "st_ino", None)
                        current_mtime = stat.st_mtime
                        current_size = stat.st_size

                        rotated = False
                        if current_inode and current_inode != last_inode:
                            rotated = True
                        elif current_size < last_size and current_mtime <= last_mtime:
                            rotated = True

                        if rotated:
                            print("[*] Log file rotated or truncated. Reopening...")
                            f.close()
                            f, last_inode, last_mtime, last_size = open_log()
                            f.__enter__()  # Re-enter context manager manually
                        else:
                            last_mtime = current_mtime
                            last_size = current_size

                    except FileNotFoundError:
                        print("[!] Log file temporarily missing. Waiting...")
                        time.sleep(1)
                    continue

                if pattern.search(line):
                    print(line, end="")
                    if alert:
                        if notification:
                            notification.notify(
                                title="Log Alert",
                                message=line.strip()[:200],
                                timeout=5
                            )
                        else:
                            print("[!] Alert requested, but 'plyer' is not installed.")

    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped by user.")
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied reading file: {file_path}")
        exit(1)


def parse_args():
    """
    Parse and return the command-line arguments.

    Returns:
        argparse.Namespace: The parsed arguments from the CLI.
    """
    parser = argparse.ArgumentParser(
        description="Watch a log file for keywords and optionally alert or report matches."
    )
    parser.add_argument("file", help="Path to the log file")
    parser.add_argument("keywords", nargs="+", help="Keywords to search for in the log lines")
    parser.add_argument("-i", "--ignore-case", action="store_true",
                        help="Case-insensitive matching")
    parser.add_argument("--initial-report", action="store_true",
                        help="Scan and print all matching lines from the full file before monitoring")
    parser.add_argument("--report-file", type=str,
                        help="Optional file to write initial matches to")
    parser.add_argument("--alert", action="store_true",
                        help="Trigger desktop notification on new matching lines (requires plyer)")
    return parser.parse_args()


def main():
    """
    Entry point of the script. Parses arguments, compiles search pattern,
    performs optional initial scan, then begins live monitoring.
    """
    args = parse_args()
    flags = re.IGNORECASE if args.ignore_case else 0
    pattern = re.compile("|".join(re.escape(k) for k in args.keywords), flags)

    if args.initial_report:
        scan_initial_log(args.file, pattern, args.report_file)

    watch_log(args.file, pattern, alert=args.alert)


if __name__ == "__main__":
    main()