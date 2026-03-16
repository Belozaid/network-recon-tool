# network-recon-tool

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A powerful, multi-threaded port scanner for network reconnaissance and security auditing. This tool provides real results with accurate port status detection (open/closed/filtered).

## ✨ Features

- 🚀 **Multi-threaded scanning** - Fast parallel port scanning
- 🎯 **Accurate detection** - Distinguishes between open, closed, and filtered ports
- 🔌 **Service identification** - Automatically detects services running on open ports
- 🌐 **DNS resolution** - Resolves domain names to IP addresses
- 📊 **Detailed reporting** - Saves scan results with timestamps
- ⚡ **Flexible input** - Supports port ranges (1-1000) and lists (22,80,443)
- ⏱️ **Configurable timeout** - Adjustable connection timeout

## 📋 Requirements

- Python 3.6 or higher
- No external dependencies required! (uses only standard library)

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/Belozaid/network-recon-tool.git

# Navigate to the directory
cd network-recon-tool

# Make the script executable (Linux/Mac)
chmod +x port_scanner.py
