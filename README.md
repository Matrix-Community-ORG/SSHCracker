# 🚀 SSHCracker v3.0 Beta - Advanced SSH Brute Force Tool

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=for-the-badge)](https://github.com/)
[![Release](https://img.shields.io/github/v/release/Matrix-Community-ORG/SSHCracker?style=for-the-badge)](https://github.com/Matrix-Community-ORG/SSHCracker/releases)
[![Version](https://img.shields.io/badge/Version-3.0--beta-blue?style=for-the-badge)](https://github.com/Matrix-Community-ORG/SSHCracker)

A powerful, high-performance SSH brute force tool written in Go with **advanced honeypot detection**, professional input system, **pause/resume capability**, and comprehensive system reconnaissance.

> 📚 **New to SSHCracker?** Check out our [Complete Wiki Guide](WIKI.md) for step-by-step instructions!

---

## 👨‍💻 Developer

**SudoLite**
- 🐙 GitHub: [@sudolite](https://github.com/sudolite)
- 🐦 Twitter: [@sudolite](https://twitter.com/sudolite)

---

## 🌟 Key Features

### 🔥 Core Capabilities
- **⚡ Enhanced Multi-Layer Workers** - Revolutionary concurrent processing architecture
- **🚀 High Performance** - Up to 1000+ concurrent connections
- **🍯 Advanced Honeypot Detection** - 11 intelligent detection algorithms
- **📊 Real-Time Dashboard** - Live progress tracking with beautiful UI
- **⏸️ Pause/Resume** - Press Ctrl+C to pause, resume anytime
- **💾 Auto-Save** - Automatic progress saving every 5 minutes
- **🔍 Deep System Reconnaissance** - Comprehensive server information gathering
- **📁 Beautiful Output Formats** - Enhanced logging with emojis

### 🛡️ Security & Performance
- **🚀 Cross-Platform Support** - Linux, Windows, macOS
- **⚙️ Intelligent Worker Management** - Optimized concurrent processing
- **🔒 Thread-Safe Operations** - Atomic operations for high-concurrency
- **🎛️ Professional Input System** - Validation, defaults, and colors

---

## 🆕 What's New in v3.0 Beta

### ⏸️ Pause/Resume System (NEW!)
- Press **Ctrl+C** to gracefully pause the scan
- State automatically saved to `paused.json`
- Resume anytime with `./sshcracker --resume`
- **Auto-save every 5 minutes** for crash protection
- All progress, stats, and successful IPs preserved

### 🎯 Professional Input System (NEW!)
- **Interactive prompts** with validation
- **Default values** - Just press Enter for common settings
- **Colored feedback** - Green ✓ for valid, Red ✗ for invalid
- **File existence checking** - Prevents typos and errors
- **Scan summary** with confirmation before starting

### 🍯 Enhanced Honeypot Detection (IMPROVED!)
- **11 detection algorithms** (was 9)
- **Command Timing Analysis** - Detects uniform response patterns
- **SSH Banner Fingerprinting** - Identifies known honeypot signatures
- **Dynamic Threshold** - Smart scoring based on test results
- **30+ honeypot signatures** - Extended detection database
- **Reduced false positives** - Better accuracy

### 🖥️ CLI Flags (NEW!)
```bash
./sshcracker --help           # Show help
./sshcracker --resume         # Resume from paused.json
./sshcracker --resume-file X  # Resume from custom file
```

---

## 🚀 Quick Start

### Option 1: Download Pre-built Binary (Recommended)
```bash
# Visit releases page and download for your platform:
# https://github.com/Matrix-Community-ORG/SSHCracker/releases/latest

# Make executable (Linux/macOS):
chmod +x sshcracker

# Run:
./sshcracker
```

### Option 2: Build from Source
```bash
# Clone repository
git clone https://github.com/Matrix-Community-ORG/SSHCracker.git
cd SSHCracker

# Download dependencies
go mod tidy

# Build
go build -o sshcracker ssh.go

# Run
./sshcracker
```

---

## 📋 Usage Guide

### Interactive Mode (Default)
```bash
./sshcracker
```

The tool will guide you through:
1. **Username list** - Path to file with usernames
2. **Password list** - Path to file with passwords
3. **IP list** - Path to file with targets (ip:port format)
4. **Timeout** - Connection timeout in seconds (default: 10)
5. **Workers** - Number of concurrent workers (default: 100)

### Resume Mode
```bash
# Resume from paused.json
./sshcracker --resume

# Resume from custom file
./sshcracker --resume-file myscan.json
```

### File Format Examples

**Usernames (`users.txt`)**:
```
root
admin
user
ubuntu
```

**Passwords (`passwords.txt`)**:
```
123456
password
admin
root
```

**Targets (`targets.txt`)**:
```
192.168.1.1:22
10.0.0.1:22
example.com:2222
```

---

## 🍯 Advanced Honeypot Detection System v3.0

Our enhanced honeypot detection uses **11 sophisticated algorithms**:

| Algorithm | Detection Method | Score Impact |
|-----------|------------------|--------------|
| **Pattern Recognition** | Known honeypot signatures (30+) | +3 per match |
| **Response Time Analysis** | Unusual timing patterns | +2 |
| **Command Timing Analysis** | Low variance in response times | +2 |
| **SSH Banner Analysis** | Known honeypot SSH versions | +3 |
| **File System Analysis** | Fake/empty directories | +1 per indicator |
| **Process Analysis** | Honeypot processes running | +2 per match |
| **Network Configuration** | Missing/fake network config | +1 per indicator |
| **Behavioral Tests** | File creation, command execution | +1-2 |
| **Anomaly Detection** | Suspicious hostname, uptime | +1 |
| **Advanced Tests** | CPU info, kernel, services | +1 per indicator |
| **Performance Tests** | I/O speed, network connections | +1-2 |

### Dynamic Threshold
- Threshold automatically adjusts based on successful tests
- Minimum: 5 | Maximum: 8 | Default: ~6
- Prevents false positives when some tests fail

---

## 📊 Output Files

| File | Description |
|------|-------------|
| `su-goods.txt` | Successful credentials (ip:port@user:pass) |
| `detailed-results.txt` | Full details with system info |
| `honeypots.txt` | Detected honeypots with scores |
| `paused.json` | Scan state for resume |
| `autosave.json` | Auto-saved state (every 5 min) |

---

## ⚙️ Performance Modes

### 🚀 Ultra-High Speed Mode
```
Timeout: 3 seconds
Workers: 100
Best for: Fast networks, many targets
```

### 🏃 Balanced Mode (Recommended)
```
Timeout: 10 seconds (default)
Workers: 100 (default)
Best for: Most scenarios
```

### 🥷 Stealth Mode
```
Timeout: 15 seconds
Workers: 10
Best for: Avoiding detection
```

---

## 🔧 Installation Requirements

### Prerequisites
- **Go**: Version 1.21 or higher
- **Git**: For cloning (if building from source)

### Dependencies
```
golang.org/x/crypto     - SSH client library
github.com/manifoldco/promptui  - Interactive input
github.com/spf13/pflag  - CLI flags
```

### Supported Platforms
- ✅ Linux (x64, ARM64)
- ✅ Windows (x64)
- ✅ macOS (Intel, Apple Silicon)

---

## 🛠️ Troubleshooting

### Common Issues
```bash
# Permission denied
chmod +x sshcracker

# Module errors
go mod tidy

# Too many open files
ulimit -n 65536
```

### Resume Issues
```bash
# Check if paused.json exists
ls -la paused.json

# View saved state
cat paused.json | jq .
```

---

## 📱 Community & Support

### 🌐 Join Our Communities
- **English Community**: [@MatrixORG](https://t.me/MatrixORG)
- **Persian Community**: [@MatrixFa](https://t.me/MatrixFa)
- **Chat Group**: [@DD0SChat](https://t.me/DD0SChat)

### 💬 Get Help
1. Check [Issues](https://github.com/Matrix-Community-ORG/SSHCracker/issues)
2. Read the [Wiki](WIKI.md)
3. Join our Telegram communities

---

## ⚠️ Legal & Ethical Use

**🚨 Important Notice**: This tool is designed for:
- ✅ Authorized penetration testing
- ✅ Educational purposes
- ✅ Security research
- ✅ Your own systems

**❌ DO NOT USE FOR**:
- Unauthorized access attempts
- Illegal activities
- Systems you don't own without permission

**Users are fully responsible for compliance with applicable laws.**

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. **Fork** the repository
2. **Create** your feature branch: `git checkout -b feature/AmazingFeature`
3. **Commit** your changes: `git commit -m 'Add AmazingFeature'`
4. **Push** to branch: `git push origin feature/AmazingFeature`
5. **Open** a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) for details.

---

## 🏆 Acknowledgments

- **SudoLite** - Lead Developer
- **Matrix Community** - Maintenance and support
- **Go Community** - Excellent SSH libraries
- **Security Researchers** - Honeypot detection algorithms

---

<div align="center">

**⭐ Star this project if you find it useful! ⭐**

Made with ❤️ by [SudoLite](https://github.com/sudolite) & [Matrix Community](https://github.com/Matrix-Community-ORG)

</div>
