# Logwatch

**Logwatch** is a lightweight, cross-platform Python CLI tool for scanning and live-monitoring log files for suspicious or important entries.

It supports desktop notifications, initial scanning with optional report saving, and robust log rotation detection on Linux, macOS, and Windows.

---

## 🚀 Features

- ✅ One-time initial scan for matching lines
- ✅ Continuous tail-style log monitoring
- ✅ Native desktop notifications (optional)
- ✅ Cross-platform log rotation support
- ✅ Case-insensitive and multi-keyword matching
- ✅ Easy CLI installation via `setup.py`

---

## 📦 Installation

Clone the repo and install locally:

```bash
git clone https://github.com/trumankimery/logwatch.git
cd logwatch
pip install .
```

> 💡 This adds a `logwatch` command you can use from anywhere.

If you plan to develop or modify the script, install it in **editable mode**:

```bash
pip install -e .
```

---

## 🧪 Usage

```bash
logwatch /var/log/auth.log "failed login" "invalid user"
```

With full options:

```bash
logwatch /var/log/auth.log "ssh" "sudo" --initial-report --report-file report.txt --alert
```

---

## 🔧 CLI Options

| Flag                   | Description                                         |
|------------------------|-----------------------------------------------------|
| `--initial-report`     | Scan the entire file first and print matches        |
| `--report-file FILE`   | Save initial matches to a file                      |
| `--ignore-case`, `-i`  | Case-insensitive search                             |
| `--alert`              | Show desktop notification on new matches            |

---

## 🔔 Optional Notifications

Desktop notifications are powered by [`plyer`](https://pypi.org/project/plyer/):

```bash
pip install plyer
```

Notifications will be shown on supported systems (Linux, macOS, Windows).

---

## 📂 Log Rotation Support

`logwatch` automatically detects when a log file has been rotated, truncated, or replaced. It resumes monitoring the new file without missing a beat.

This works on:

- ✅ Linux (inode-based)
- ✅ macOS
- ✅ Windows (file size + timestamp fallback)

---

## 🛠 Example: Monitor Auth Log

```bash
logwatch /var/log/auth.log "invalid user" --alert
```

Monitor multiple patterns:

```bash
logwatch /var/log/syslog "segfault" "OOM" "kernel panic" --ignore-case
```

---

## 📄 License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE) for full details.

---

## 👤 Author

[Truman Kimery](https://github.com/trumankimery)
