# 📚 SSHCracker Wiki - Complete Guide

Welcome to the SSHCracker v3.0 Beta comprehensive documentation. This guide will take you from zero to expert.

---

## 📑 Table of Contents

1. [Introduction](#1-introduction)
2. [Requirements](#2-requirements)
3. [Installation](#3-installation)
4. [Preparing Your Files](#4-preparing-your-files)
5. [Running Your First Scan](#5-running-your-first-scan)
6. [Understanding the Output](#6-understanding-the-output)
7. [Pause and Resume](#7-pause-and-resume)
8. [CLI Flags](#8-cli-flags)
9. [Honeypot Detection](#9-honeypot-detection)
10. [Performance Tuning](#10-performance-tuning)
11. [Troubleshooting](#11-troubleshooting)
12. [FAQ](#12-faq)
13. [Legal Notice](#13-legal-notice)

---

## 1. Introduction

### What is SSHCracker?

SSHCracker is a high-performance SSH brute force tool designed for:
- **Penetration testers** - Testing SSH security on authorized systems
- **Security researchers** - Studying SSH attack patterns
- **System administrators** - Auditing their own infrastructure

### Key Features

| Feature | Description |
|---------|-------------|
| **Multi-threaded** | 100+ workers with 25 connections each |
| **Honeypot Detection** | 11 algorithms to detect fake servers |
| **Pause/Resume** | Save progress and continue later |
| **Auto-save** | Automatic backup every 5 minutes |
| **Professional UI** | Interactive input with validation |

---

## 2. Requirements

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **OS** | Linux, Windows, macOS | Linux |
| **RAM** | 512 MB | 2 GB |
| **CPU** | 1 core | 4+ cores |
| **Network** | Stable connection | High bandwidth |

### Software Requirements

For building from source:
- **Go** version 1.21 or higher

For running pre-built binaries:
- No additional software required

### Installing Go

**Linux (Ubuntu/Debian)**:
```bash
# Update package list
sudo apt update

# Install Go
sudo apt install golang-go

# Verify installation
go version
```

**Linux (Using snap)**:
```bash
sudo snap install go --classic
go version
```

**macOS**:
```bash
# Using Homebrew
brew install go

# Verify
go version
```

**Windows**:
1. Download installer from [golang.org](https://golang.org/dl/)
2. Run the installer
3. Open Command Prompt and verify: `go version`

---

## 3. Installation

### Option A: Download Pre-built Binary (Easiest)

1. Go to [Releases Page](https://github.com/Matrix-Community-ORG/SSHCracker/releases)
2. Download the file for your platform:
   - Linux: `sshcracker-linux-amd64`
   - macOS: `sshcracker-darwin-amd64`
   - Windows: `sshcracker-windows-amd64.exe`
3. Make it executable (Linux/macOS):
   ```bash
   chmod +x sshcracker-*
   ```
4. Run:
   ```bash
   ./sshcracker-*
   ```

### Option B: Build from Source

```bash
# Step 1: Clone the repository
git clone https://github.com/Matrix-Community-ORG/SSHCracker.git

# Step 2: Enter directory
cd SSHCracker

# Step 3: Download dependencies
go mod tidy

# Step 4: Build
go build -o sshcracker ssh.go

# Step 5: Run
./sshcracker
```

---

## 4. Preparing Your Files

You need three files to run SSHCracker:

### 4.1 Username List

Create a file called `users.txt` with one username per line:

```
root
admin
administrator
user
ubuntu
debian
centos
oracle
postgres
mysql
```

**Tips**:
- Start with common usernames like `root`, `admin`
- Add service-specific usernames: `postgres`, `mysql`, `oracle`
- Add cloud provider defaults: `ubuntu`, `ec2-user`, `centos`

### 4.2 Password List

Create a file called `passwords.txt` with one password per line:

```
123456
password
admin
root
12345678
qwerty
letmein
welcome
monkey
dragon
```

**Tips**:
- Start with the most common passwords
- Include variations: `Password1`, `Admin123`
- You can use wordlists like [SecLists](https://github.com/danielmiessler/SecLists)

### 4.3 Target List

Create a file called `targets.txt` with one target per line in `IP:PORT` format:

```
192.168.1.1:22
192.168.1.2:22
10.0.0.1:22
10.0.0.2:2222
```

**Format**: `IP_ADDRESS:PORT`

**Tips**:
- Most SSH servers run on port 22
- Some use alternative ports like 2222, 22222
- You can use domain names: `example.com:22`

### Finding Targets

**Using nmap to find SSH servers**:
```bash
# Scan a network for SSH servers
nmap -p 22 192.168.1.0/24 --open -oG - | grep "22/open" | awk '{print $2":22"}' > targets.txt
```

**Using masscan for faster scanning**:
```bash
# Fast scan for SSH
masscan 192.168.1.0/24 -p22 --rate=1000 -oG masscan.txt
grep "22/open" masscan.txt | awk '{print $4":22"}' > targets.txt
```

---

## 5. Running Your First Scan

### Step-by-Step Guide

1. **Start SSHCracker**:
   ```bash
   ./sshcracker
   ```

2. **You'll see the welcome screen**:
   ```
   ╔══════════════════════════════════════════════════════════════╗
   ║         🚀 SSHCracker v3.0-beta - Setup 🚀                   ║
   ╚══════════════════════════════════════════════════════════════╝
   ```

3. **Enter username file path**:
   ```
   📁 Username list file path: users.txt
   ```

4. **Enter password file path**:
   ```
   🔐 Password list file path: passwords.txt
   ```

5. **Enter target file path**:
   ```
   🌐 IP list file path (ip:port format): targets.txt
   ```

6. **Set timeout** (press Enter for default):
   ```
   ⏱️ Timeout in seconds: 10
   ```

7. **Set workers** (press Enter for default):
   ```
   👷 Maximum workers: 100
   ```

8. **Review scan summary**:
   ```
   ╔══════════════════════════════════════════════════════════════╗
   ║                   📋 SCAN CONFIGURATION                      ║
   ╠══════════════════════════════════════════════════════════════╣
   ║  🌐 Targets:           100 IPs                               ║
   ║  🔑 Combinations:      1,000                                 ║
   ║  ⏱️ Timeout:           10s                                   ║
   ║  👷 Workers:           100                                   ║
   ╚══════════════════════════════════════════════════════════════╝
   ```

9. **Confirm to start**:
   ```
   🚀 Start scan? 
   > ✅ Yes, start scan
     ❌ No, cancel
   ```

10. **Watch the progress**:
    ```
    ╔══════════════════════════════════════════════════════════════╗
    ║      🚀 SSHCracker v3.0-beta - Advanced SSH Brute Force 🚀   ║
    ╠══════════════════════════════════════════════════════════════╣
    ║ 🔍 Progress:      500/1,000 ( 50.0%)                         ║
    ║ ⚡ Speed:        125.3 checks/sec                            ║
    ║ ✅ Successful: 3  | ❌ Failed: 495  | 🍯 Honeypots: 2         ║
    ╚══════════════════════════════════════════════════════════════╝
    ```

---

## 6. Understanding the Output

### 6.1 Output Files

After a scan, you'll find these files:

| File | Purpose |
|------|---------|
| `su-goods.txt` | Successfully cracked credentials |
| `detailed-results.txt` | Full details with system info |
| `honeypots.txt` | Detected honeypot servers |
| `combo.txt` | Generated credential combinations |

### 6.2 su-goods.txt Format

```
192.168.1.10:22@root:password123
192.168.1.15:22@admin:admin
10.0.0.5:22@ubuntu:ubuntu
```

Format: `IP:PORT@USERNAME:PASSWORD`

### 6.3 detailed-results.txt Format

```
=== 🎯 SSH Success 🎯 ===
🌐 Target: 192.168.1.10:22
🔑 Credentials: root:password123
🖥️ Hostname: webserver01
🐧 OS: Linux webserver01 5.4.0-42-generic
📡 SSH Version: OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
⚡ Response Time: 234ms
🔌 Open Ports: [22 80 443 3306]
🍯 Honeypot Score: 2
🕒 Timestamp: 2026-01-03 15:30:45
========================
```

### 6.4 honeypots.txt Format

```
HONEYPOT: 192.168.1.50:22@root:root (Score: 8)
HONEYPOT: 10.0.0.100:22@admin:admin (Score: 12)
```

### 6.5 Dashboard Statistics

| Stat | Meaning |
|------|---------|
| **Progress** | Tasks completed / Total tasks |
| **Speed** | Checks per second |
| **Successful** | Valid credentials found |
| **Failed** | Connection failures or wrong passwords |
| **Honeypots** | Detected honeypot servers |
| **Success Rate** | Percentage of real servers cracked |
| **Honeypot Rate** | Percentage of honeypots detected |

---

## 7. Pause and Resume

### 7.1 Pausing a Scan

Press **Ctrl+C** during a scan:

```
⏸️  Pausing scan... Please wait...
✅ State saved to paused.json
📂 Resume with: ./sshcracker --resume
```

### 7.2 Resuming a Scan

```bash
./sshcracker --resume
```

Or with a custom state file:
```bash
./sshcracker --resume-file myscan.json
```

### 7.3 What's Saved?

The pause state includes:
- ✅ Current task position
- ✅ All statistics (goods, errors, honeypots)
- ✅ Successfully cracked IPs (to avoid duplicates)
- ✅ Original configuration
- ✅ Start time (for accurate timing)

### 7.4 Auto-Save Feature

SSHCracker automatically saves state every 5 minutes to `autosave.json`.

This protects against:
- Power failures
- System crashes
- Accidental terminal closure

### 7.5 State Files

| File | Purpose |
|------|---------|
| `paused.json` | Created when you press Ctrl+C |
| `autosave.json` | Created every 5 minutes automatically |

Both files are deleted when scan completes successfully.

---

## 8. CLI Flags

### Available Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--help` | `-h` | Show help message |
| `--resume` | `-r` | Resume from `paused.json` |
| `--resume-file` | | Resume from custom file |

### Examples

```bash
# Show help
./sshcracker --help
./sshcracker -h

# Resume from default paused.json
./sshcracker --resume
./sshcracker -r

# Resume from custom file
./sshcracker --resume-file backup.json

# Interactive mode (default)
./sshcracker
```

---

## 9. Honeypot Detection

### 9.1 What is a Honeypot?

A honeypot is a fake server designed to:
- Capture attacker credentials
- Log attack patterns
- Waste attacker time
- Collect malware samples

### 9.2 Detection Algorithms

SSHCracker uses 11 algorithms to detect honeypots:

| # | Algorithm | How It Works |
|---|-----------|--------------|
| 1 | **Pattern Recognition** | Searches for honeypot keywords in output |
| 2 | **Response Time** | Flags suspiciously fast responses |
| 3 | **Command Timing** | Measures variance in command execution time |
| 4 | **SSH Banner** | Checks for known honeypot SSH versions |
| 5 | **File System** | Looks for fake/empty directories |
| 6 | **Process List** | Searches for honeypot processes |
| 7 | **Network Config** | Checks for missing network files |
| 8 | **Behavioral** | Tests file creation, command execution |
| 9 | **Anomalies** | Checks hostname, uptime, history |
| 10 | **Advanced** | Checks CPU, kernel, package managers |
| 11 | **Performance** | Tests I/O speed, network connections |

### 9.3 Honeypot Score

Each algorithm adds points to a "honeypot score":

| Score | Meaning |
|-------|---------|
| 0-4 | Likely real server |
| 5-6 | Possibly honeypot |
| 7+ | Likely honeypot |

### 9.4 Known Honeypot Signatures

SSHCracker detects these honeypot software:

- Cowrie
- Kippo
- HonSSH
- Artillery
- Honeyd
- Dionaea
- Elastichoney
- Bifrozt
- Kojoney
- And more...

---

## 10. Performance Tuning

### 10.1 Worker Count

| Workers | Best For | Memory Usage |
|---------|----------|--------------|
| 10 | Stealth scanning | ~100 MB |
| 50 | Normal scanning | ~250 MB |
| 100 | Fast scanning | ~500 MB |
| 200 | Maximum speed | ~1 GB |

### 10.2 Timeout Settings

| Timeout | Best For | Speed |
|---------|----------|-------|
| 3s | Fast networks | Fastest |
| 5s | Normal networks | Fast |
| 10s | Slow networks | Medium |
| 15s | Very slow networks | Slow |

### 10.3 System Limits

Increase file descriptor limit for more connections:

```bash
# Temporary (current session)
ulimit -n 65536

# Permanent (add to /etc/security/limits.conf)
* soft nofile 65536
* hard nofile 65536
```

### 10.4 Performance Tips

1. **Start small**: Begin with 50 workers and increase if stable
2. **Monitor resources**: Watch CPU and memory usage
3. **Adjust timeout**: Lower for fast networks, higher for slow
4. **Use SSD**: Faster disk helps with logging
5. **Stable network**: Avoid WiFi for large scans

---

## 11. Troubleshooting

### 11.1 Common Errors

**"Permission denied"**
```bash
chmod +x sshcracker
```

**"Too many open files"**
```bash
ulimit -n 65536
```

**"Module errors"**
```bash
go mod tidy
```

**"File not found"**
- Check file path is correct
- Use absolute paths if needed: `/home/user/targets.txt`

### 11.2 Resume Not Working

```bash
# Check if paused.json exists
ls -la paused.json

# View the content
cat paused.json

# If corrupted, try autosave
./sshcracker --resume-file autosave.json
```

### 11.3 Slow Performance

1. Reduce timeout value
2. Reduce worker count
3. Check network speed
4. Close other applications
5. Use wired connection

### 11.4 High Memory Usage

1. Reduce worker count
2. Split target list into smaller files
3. Use system with more RAM

---

## 12. FAQ

### Q: Is SSHCracker legal?

A: SSHCracker is a security tool. Using it on systems you own or have permission to test is legal. Using it on unauthorized systems is illegal.

### Q: How fast is SSHCracker?

A: With 100 workers and 10s timeout, expect ~100-500 checks per second depending on network conditions.

### Q: Can I use custom ports?

A: Yes! Specify port in target file: `192.168.1.1:2222`

### Q: How do I know if I found a honeypot?

A: Check `honeypots.txt` or look for high honeypot scores in `detailed-results.txt`.

### Q: What if my scan is interrupted?

A: Your progress is auto-saved every 5 minutes. Use `--resume` to continue.

### Q: Can I run multiple instances?

A: Yes, but use different output files and target lists to avoid conflicts.

### Q: Does it support key-based auth?

A: Currently only password authentication is supported.

### Q: How do I reduce false positives in honeypot detection?

A: The v3.0 dynamic threshold system automatically adjusts. Very few false positives occur with default settings.

---

## 13. Legal Notice

### Authorized Use Only

This tool is intended for:
- ✅ Security professionals testing authorized systems
- ✅ Penetration testers with written permission
- ✅ System administrators auditing their own infrastructure
- ✅ Security researchers in controlled environments

### Prohibited Use

- ❌ Unauthorized access to computer systems
- ❌ Testing systems without explicit permission
- ❌ Any illegal activities

### Disclaimer

The developers are not responsible for any misuse of this tool. Users are solely responsible for ensuring they have proper authorization before using SSHCracker on any system.

---

## 📞 Support

- **GitHub Issues**: [Report bugs](https://github.com/Matrix-Community-ORG/SSHCracker/issues)
- **Telegram**: [@MatrixORG](https://t.me/MatrixORG)
- **Developer**: [@sudolite](https://github.com/sudolite)

---

<div align="center">

**Made with ❤️ by SudoLite & Matrix Community**

</div>
