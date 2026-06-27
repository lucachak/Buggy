#!/usr/bin/env bash
# ============================================================
# Buggy - Modular WebApp Exploiter
# One-command installer
# github.com/lucachak/Buggy
# ============================================================

set -euo pipefail

# ── Colors ────────────────────────────────────
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
BOLD='\033[1m'
RESET='\033[0m'

banner() {
    echo -e "${CYAN}${BOLD}"
    echo "  ██████╗   ██╗   ██╗   ██████╗    ██████╗   ██╗   ██╗"
    echo "  ██╔══██╗  ██║   ██║  ██╔════╝   ██╔════╝   ╚██╗ ██╔╝"
    echo "  ██████╔╝  ██║   ██║  ██║  ███╗  ██║  ███╗   ╚████╔╝"
    echo "  ██╔══██╗  ██║   ██║  ██║   ██║  ██║   ██║    ╚██╔╝"
    echo "  ██████╔╝  ╚██████╔╝  ╚██████╔╝  ╚██████╔╝     ██║"
    echo "  ╚═════╝    ╚═════╝    ╚═════╝    ╚═════╝      ╚═╝"
    echo -e "${RESET}"
    echo -e "  ${BOLD}Buggy Installer${RESET}  |  github.com/lucachak/Buggy"
    echo ""
}

info()    { echo -e "${CYAN}[i]${RESET} $1"; }
success() { echo -e "${GREEN}[✓]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[✗]${RESET} $1"; }

# ── Detect OS ─────────────────────────────────
detect_os() {
    case "$(uname -s)" in
        Linux*)     OS="linux";;
        Darwin*)    OS="macos";;
        MINGW*|MSYS*|CYGWIN*) OS="windows";;
        *)          OS="unknown";;
    esac
    info "Detected OS: ${BOLD}$OS${RESET}"
}

# ── Detect package manager ────────────────────
detect_pkg_manager() {
    if command -v apt &>/dev/null; then
        PKG_MANAGER="apt"
        INSTALL_CMD="sudo apt-get install -y"
        UPDATE_CMD="sudo apt-get update"
    elif command -v pacman &>/dev/null; then
        if command -v yay &>/dev/null; then
            PKG_MANAGER="yay"
            INSTALL_CMD="yay -S --noconfirm"
            UPDATE_CMD=""
        elif command -v paru &>/dev/null; then
            PKG_MANAGER="paru"
            INSTALL_CMD="paru -S --noconfirm"
            UPDATE_CMD=""
        else
            PKG_MANAGER="pacman"
            INSTALL_CMD="sudo pacman -S --noconfirm"
            UPDATE_CMD=""
        fi
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="sudo dnf install -y"
        UPDATE_CMD=""
    elif command -v brew &>/dev/null; then
        PKG_MANAGER="brew"
        INSTALL_CMD="brew install"
        UPDATE_CMD="brew update"
    else
        error "No supported package manager found."
        error "Please install dependencies manually:"
        echo "  - python 3.10+"
        echo "  - go 1.21+"
        echo "  - subfinder, dnsx, amass, assetfinder"
        echo "  - curl, jq, sed, sort, dig, grep"
        exit 1
    fi
    info "Package manager: ${BOLD}$PKG_MANAGER${RESET}"
}

# ── Install system dependencies ───────────────
install_system_deps() {
    echo ""
    info "Installing system dependencies..."

    if [ "$PKG_MANAGER" = "apt" ]; then
        $UPDATE_CMD
    elif [ "$PKG_MANAGER" = "brew" ]; then
        $UPDATE_CMD
    fi

    # Common tools (available in most repos)
    local common_tools=("curl" "jq" "sed" "grep" "bind-tools" "dnsutils")
    
    for tool in curl jq sed grep dig sort; do
        if ! command -v "$tool" &>/dev/null; then
            warn "Installing $tool..."
            case "$PKG_MANAGER" in
                apt)    sudo apt-get install -y "$tool" 2>/dev/null || true;;
                pacman|yay|paru) $INSTALL_CMD "$tool" 2>/dev/null || true;;
                dnf)    $INSTALL_CMD "$tool" 2>/dev/null || true;;
                brew)   $INSTALL_CMD "$tool" 2>/dev/null || true;;
            esac
        fi
    done

    # Go tools (subfinder, dnsx, amass, assetfinder)
    if command -v go &>/dev/null; then
        info "Installing Go-based security tools..."
        
        for tool in subfinder dnsx amass assetfinder; do
            if ! command -v "$tool" &>/dev/null; then
                info "  Installing $tool..."
                go install "github.com/projectdiscovery/${tool}/cmd/${tool}@latest" 2>/dev/null || \
                go install "github.com/OWASP/Amass/v3/...@latest" 2>/dev/null || \
                warn "  Could not install $tool via go. Try manual install."
            else
                success "  $tool already installed"
            fi
        done

        # Ensure GOPATH/bin is in PATH
        if [ -d "$HOME/go/bin" ]; then
            export PATH="$HOME/go/bin:$PATH"
        fi
    else
        warn "Go is not installed. Skipping Go-based tools."
        warn "Install Go from https://go.dev/dl/ and re-run this script."
    fi

    success "System dependencies installed."
}

# ── Check Python ──────────────────────────────
check_python() {
    info "Checking Python..."
    if command -v python3 &>/dev/null; then
        PYTHON="python3"
    elif command -v python &>/dev/null; then
        PYTHON="python"
    else
        error "Python 3 not found. Please install Python 3.10+"
        exit 1
    fi
    
    local version=$($PYTHON --version 2>&1 | grep -oP '\d+\.\d+')
    success "Python $version found."
}

# ── Install Python dependencies ───────────────
install_python_deps() {
    info "Installing Python dependencies..."
    
    if [ -f "requirements.txt" ]; then
        $PYTHON -m pip install -r requirements.txt --quiet
        success "Python dependencies installed."
    else
        warn "No requirements.txt found. Skipping."
    fi
}

# ── Build Dirpy Go ────────────────────────────
build_dirpy() {
    echo ""
    info "Building Dirpy v2 (Go)..."

    local dirpy_dirs=(
        "modules/Reconnaissance/Dirpy"
        "modules/Reconnaissance/DirGO"
    )

    local built=false
    for dir in "${dirpy_dirs[@]}"; do
        if [ -f "$dir/go.mod" ]; then
            info "  Found Go module in: $dir"
            cd "$dir"
            
            if command -v go &>/dev/null; then
                go build -ldflags="-s -w" -o DirGo ./cmd/dirpy/ 2>/dev/null && {
                    success "  DirGo binary built: $dir/DirGo"
                    built=true
                } || {
                    warn "  Failed to build in $dir"
                }
            else
                warn "  Go not available. Skipping Dirpy build."
            fi
            
            cd - > /dev/null
        fi
    done

    if [ "$built" = true ]; then
        success "Dirpy v2 Go binary ready."
    else
        warn "Dirpy Go binary not built. Buggy will fall back to Python dir busting."
        warn "Install Go and run: cd modules/Reconnaissance/Dirpy && make build"
    fi
}

# ── Create virtual environment ────────────────
create_venv() {
    if [ "$1" = "--venv" ]; then
        info "Creating Python virtual environment..."
        $PYTHON -m venv .venv
        source .venv/bin/activate
        success "Virtual environment created. Activate with: source .venv/bin/activate"
    fi
}

# ── Make Buggy executable ─────────────────────
make_executable() {
    if [ -f "Buggy.py" ]; then
        chmod +x Buggy.py
        success "Buggy.py is executable."
    fi
}

# ── Create alias/launcher ─────────────────────
create_launcher() {
    local buggy_path="$(pwd)/Buggy.py"
    
    # Create a wrapper script
    cat > buggy <<EOF
#!/usr/bin/env bash
cd "$(pwd)"
$PYTHON "$buggy_path" "\$@"
EOF
    chmod +x buggy
    
    info "Launcher created: $(pwd)/buggy"
    info "You can run: ./buggy -t target.com -m recon"
    info "Or add to PATH: sudo ln -s $(pwd)/buggy /usr/local/bin/buggy"
}

# ── Summary ───────────────────────────────────
print_summary() {
    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}${BOLD}║                  Installation Complete!                     ║${RESET}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "  ${BOLD}Quick start:${RESET}"
    echo -e "    ${CYAN}./buggy -t testphp.vulnweb.com -m recon${RESET}"
    echo ""
    echo -e "  ${BOLD}Local test:${RESET}"
    echo -e "    ${CYAN}./buggy -t http://localhost:8000 -m recon${RESET}"
    echo ""
    echo -e "  ${BOLD}Recursive scan:${RESET}"
    echo -e "    ${CYAN}./buggy -t http://localhost:8000 -m recon --recursive${RESET}"
    echo ""
    echo -e "  ${BOLD}Dirpy standalone:${RESET}"
    echo -e "    ${CYAN}./modules/Reconnaissance/Dirpy/DirGo -u http://localhost:8000${RESET}"
    echo ""
    echo -e "  ${BOLD}Help:${RESET}"
    echo -e "    ${CYAN}./buggy --help${RESET}"
    echo ""
}

# ── Main ──────────────────────────────────────
main() {
    banner
    
    local use_venv=false
    if [[ "${1:-}" == "--venv" ]]; then
        use_venv=true
    fi

    detect_os
    detect_pkg_manager
    install_system_deps
    check_python
    
    if [ "$use_venv" = true ]; then
        create_venv --venv
    fi
    
    install_python_deps
    build_dirpy
    make_executable
    create_launcher
    print_summary
}

main "$@"