# 🛡️ Bad IPs - Distributed IP Blocking System

[![Version](https://img.shields.io/badge/version-2.0.28-blue.svg)](https://github.com/permittivity2/bad-ips/releases)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-orange.svg)](https://projects.thedude.vip/bad-ips/)

**A distributed IP blocking system with centralized database for real-time threat sharing across your infrastructure.**

---

## 🚀 Quick Start

Install Bad IPs on Ubuntu/Debian with a single command:

```bash
bash <(curl -fsSL https://projects.thedude.vip/bad-ips/install.sh)
```

The installer will:
- ✅ Add the Silver Linings, LLC apt repository
- ✅ Install Bad IPs and all dependencies
- ✅ Configure your PostgreSQL database
- ✅ Set up detectors for your services
- ✅ Start monitoring automatically

---

## 📖 Full Documentation

**For complete documentation, configuration guides, and examples, visit:**

### 🌐 [https://projects.thedude.vip/bad-ips/](https://projects.thedude.vip/bad-ips/)

The documentation includes:
- 📚 Configuration reference
- 🔧 Detector setup guides
- 🗄️ Database configuration
- 🎯 Pattern matching examples
- 🚀 Advanced deployment scenarios
- 🐛 Troubleshooting guides

---

## 📋 Overview

Bad IPs monitors your system logs for malicious activity and automatically blocks offending IP addresses using nftables. With a **centralized PostgreSQL database**, threats detected on one server are immediately shared across your entire infrastructure.

### The NATO Effect

> *"An attack on one is an attack on all."*

When any server blocks an IP, that IP is automatically shared with **all servers** connected to your database. An attacker trying to brute force SSH on your mail server will be instantly blocked on your web servers, DNS servers, and everything else.

---

## ✨ Key Features

- 🔍 **Real-time log monitoring** via systemd journal and file tailing
- 🚫 **Automatic IP blocking** using nftables with configurable timeouts
- 🗄️ **Centralized PostgreSQL database** for threat intelligence sharing
- ⚡ **Multi-threaded async architecture** with queue-based pipeline
- 🎯 **Configurable detectors** for SSH, mail, web, DNS, and custom services
- 🛡️ **Never-block CIDR filtering** to protect trusted networks
- 🔄 **Automatic expiration** and cleanup of stale blocks
- 📊 **Fast local blocking** with <1ms response time
- 🔧 **Live configuration reload** via systemctl reload

---

## 🤝 Contributing

This is proprietary software by Silver Linings, LLC. For support, feature requests, or bug reports, please contact the maintainer or file an issue.

---

## 📄 License

Proprietary - Silver Linings, LLC

---

## 🔗 Links

- **Documentation**: https://projects.thedude.vip/bad-ips/
- **Installation**: `bash <(curl -fsSL https://projects.thedude.vip/bad-ips/install.sh)`
- **APT Repository**: https://projects.thedude.vip/apt/
- **Support**: File an issue on GitHub

---

Made with ☕ by Silver Linings, LLC
