# Diagrams from Pull Request #5

## Sequence Diagram for prompt_target_user with Sanitized Input and Abort Paths

```mermaid
sequenceDiagram
    actor User
    participant InstallScript

    User->>InstallScript: Run install.sh
    loop Prompt for target user until valid
        InstallScript->>User: Prompt Which user directory should tools be installed in?
        User-->>InstallScript: Enter target_user
        InstallScript->>InstallScript: Check target_user for slash
        alt Username contains slash
            InstallScript->>User: Print Error: Username cannot contain '/' characters.
            InstallScript->>InstallScript: continue loop
        else Username does not contain slash
            InstallScript->>InstallScript: Check if /home/target_user exists
            alt User home exists
                InstallScript->>User: Print Using user directory
                InstallScript->>InstallScript: Set TARGET_USER
                InstallScript->>InstallScript: break loop
            else User home missing
                InstallScript->>User: Ask Create directory?
                User-->>InstallScript: Yes/No
                alt User chooses Yes
                    InstallScript->>InstallScript: Attempt mkdir /home/target_user
                    alt mkdir success
                        InstallScript->>User: Print Created user directory
                        InstallScript->>InstallScript: Set TARGET_USER
                        InstallScript->>InstallScript: break loop
                    else mkdir failure
                        InstallScript->>User: Print Failed to create user directory. Aborting.
                        InstallScript->>InstallScript: exit 1
                    end
                else User chooses No
                    InstallScript->>User: Print Cannot proceed without a target directory. Aborting.
                    InstallScript->>InstallScript: exit 1
                end
            end
        end
    end
```

## Sequence Diagram for Secure Oh My Zsh Installation

```mermaid
sequenceDiagram
    actor User
    participant InstallScript
    participant Apt
    participant Curl
    participant SuTargetUser as su_TARGET_USER

    User->>InstallScript: Answer Yes to Install Zsh and Oh My Zsh?
    InstallScript->>Apt: apt install -y zsh
    Apt-->>InstallScript: Zsh installation result
    InstallScript->>InstallScript: check_error Zsh installation
    InstallScript->>InstallScript: Create mktemp file path as oh_my_zsh_install_script
    InstallScript->>Curl: curl -fsSL ohmyzsh install.sh -o oh_my_zsh_install_script
    alt Download success
        Curl-->>InstallScript: Script saved to temp file
        InstallScript->>SuTargetUser: su - TARGET_USER -c "sh temp_script --unattended"
        SuTargetUser-->>InstallScript: Oh My Zsh install result
        alt Install failure
            InstallScript->>InstallScript: record_failure Oh My Zsh installation
        end
    else Download failure
        Curl-->>InstallScript: Nonzero exit code
        InstallScript->>InstallScript: record_failure Oh My Zsh download
    end
    InstallScript->>InstallScript: rm -f oh_my_zsh_install_script
    InstallScript->>SuTargetUser: Clone zsh-autosuggestions and zsh-syntax-highlighting
    SuTargetUser-->>InstallScript: Git clone results
    InstallScript->>SuTargetUser: sed -i to set plugins line in .zshrc
    SuTargetUser-->>InstallScript: sed result
    InstallScript->>InstallScript: chsh -s /bin/zsh TARGET_USER
    InstallScript->>InstallScript: check_error Zsh configuration
```

## Flow Diagram for Updated install.sh Execution Phases

```mermaid
flowchart TD
    A_Start[Start install.sh] --> B_PromptUser[Prompt and validate TARGET_USER]
    B_PromptUser -->|Valid user dir or created| C_CorePackages[Install core system tools]

    C_CorePackages --> D_Recon[Prompt and install reconnaissance tools]
    D_Recon --> E_WebExploit[Prompt and install web exploitation tools]
    E_WebExploit --> F_RevEng[Prompt and install reverse engineering tools]
    F_RevEng --> G_Forensics[Prompt and install forensics tools]
    G_Forensics --> H_PasswordCracking[Prompt and install password cracking tools]
    H_PasswordCracking --> I_ExploitDev[Prompt and install exploit development tools]

    I_ExploitDev --> J_CreateCTFDir[Create /home/TARGET_USER/CTF]
    J_CreateCTFDir --> K_Venv[Create Python venv in CTF/venv]
    K_Venv --> L_PythonDeps[Install Python packages in venv]

    L_PythonDeps --> M_ToolsDir[Create /home/TARGET_USER/tools]
    M_ToolsDir --> N_SecLists[Optional SecLists download into tools]

    N_SecLists --> O_CTFSubdirs[Create CTF subdirectories]
    O_CTFSubdirs --> P_NotesGit[Initialize Git in CTF/notes if no repo]

    P_NotesGit --> Q_BashAliases[Configure bash aliases in .bashrc]

    Q_BashAliases --> R_SysConfig[Apply system config tweaks]
    R_SysConfig --> R1_Watch[Increase inotify watch limits]
    R1_Watch --> R2_Firewall[Install and configure ufw rules]
    R2_Firewall --> R3_DisableSvcs[Disable bluetooth and cups]

    R3_DisableSvcs --> S_Editors[Install editors and optional VS Code]

    S_Editors --> T_TestEnvs[Optional test environments installation]

    T_TestEnvs --> U_Zsh[Optional Zsh and Oh My Zsh secure install]

    U_Zsh --> V_Cleanup[Final cleanup for TARGET_USER cache and history]

    V_Cleanup --> W_ProxyChains[Optional ProxyChains configuration]

    W_ProxyChains --> X_NerdFonts[Optional Nerd Fonts installation]

    X_NerdFonts --> Y_Verify[Run tool verification and log results]

    Y_Verify --> Z_End[Show failures summary and finish]
```

## Summary by Sourcery

Harden and streamline the Kali install script with safer user handling, expanded tool category installation, and more reliable environment setup and cleanup.

### New Features:
- Add reconnaissance, forensics, and password-cracking tool groups as optional installation steps.
- Create CTF and tools directories early in the process and set up a Python virtual environment within the CTF workspace.
- Add configuration for firewall, file watch limits, editors (including optional VS Code), and ProxyChains as part of the setup.
- Provide an optional Oh My Zsh installation using a temporary downloaded script and idempotent plugin configuration.

### Bug Fixes:
- Validate the target username to prevent invalid paths and handle failures to create the user directory by aborting instead of continuing.
- Ensure notes Git repository initialization runs only once and properly checks for errors.
- Guard SecLists verification to avoid errors when SecLists was not installed.

### Enhancements:
- Inline and simplify several previously function-wrapped steps (e.g., tool installation groups, config tweaks, cleanup) for a more linear and maintainable install flow.
- Improve cleanup to target the selected target user and verify completion.
- Replace direct remote shell execution for Oh My Zsh with a safer download-then-execute flow and avoid duplicate plugin entries in .zshrc.

---
*Source: Pull Request #5 - "modified: install.sh"*
